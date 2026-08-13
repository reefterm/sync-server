package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/reefterm/sync-server/internal/auth"
	"github.com/reefterm/sync-server/internal/model"
	"github.com/reefterm/sync-server/internal/store"
)

/**
 * Recovery from a fully logged-out state: no session anywhere, passphrase
 * forgotten, only the one-time recovery code from registration still in
 * hand. Three steps, deliberately split so no single one of them is enough
 * on its own:
 *
 *   start     prove control of the registered email. The server can verify
 *             this itself (it sent the link), which is exactly the thing it
 *             cannot do for the recovery code -- that is why this step
 *             exists at all.
 *   keys      hand back the wrapped recovery envelope, now that email
 *             control is proven. Safe to expose to anyone holding a valid
 *             token: it is ciphertext, and 120 bits of recovery-code
 *             entropy behind it makes it as safe here as it is sitting in
 *             the sync/keys response an authenticated session already gets.
 *   complete  the client has unsealed the envelope locally by now (or it
 *             hasn't, and gives up here) and submits a new login password
 *             plus freshly re-sealed envelopes. The server still cannot
 *             verify the recovery code was correct -- it never sees it --
 *             so this is the point where "proved email control" is the
 *             whole of what authorizes the reset. Every existing session is
 *             revoked here, since that is the appropriate response to a
 *             password reset whether or not the reset was legitimate.
 */

const (
	recoveryTokenBytes  = 32
	minRecoveryEmailLen = 3 // just enough to reject "" and catch obvious mistakes
)

type recoverStartRequest struct {
	Email string `json:"email"`
}

func (s *Server) handleRecoverStart(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.SMTP.Configured() {
		writeError(w, http.StatusServiceUnavailable, "email-based recovery is not configured on this server")
		return
	}

	var req recoverStartRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}

	email := strings.TrimSpace(strings.ToLower(req.Email))
	if len(email) < minRecoveryEmailLen || !strings.Contains(email, "@") {
		writeError(w, http.StatusBadRequest, "a valid email is required")
		return
	}

	// Same response whether or not the account exists: telling them apart
	// hands an attacker a working way to enumerate registered emails.
	const generic = "If that email has an account, recovery instructions have been sent to it."

	ctx := r.Context()
	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"message": generic})
		return
	}

	token, err := randomToken()
	if err != nil {
		s.log.Error("generate recovery token", "error", err)
		writeError(w, http.StatusInternalServerError, "could not start recovery")
		return
	}

	now := time.Now()
	rt := model.RecoveryToken{
		TokenHash: auth.HashToken(token),
		UserID:    user.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.cfg.RecoveryTokenTTL),
	}

	if err := s.store.CreateRecoveryToken(ctx, rt); err != nil {
		s.log.Error("create recovery token", "error", err)
		writeError(w, http.StatusInternalServerError, "could not start recovery")
		return
	}

	subject := "Recover access to your Reef Terminal sync account"
	body := fmt.Sprintf(
		"Someone (hopefully you) asked to recover access to your Reef Terminal sync account.\n\n"+
			"Recovery code:\n\n    %s\n\n"+
			"Paste this into the app along with your account recovery code to continue.\n\n"+
			"This code expires in %s. If you didn't request this, you can ignore this email --"+
			" your account is unaffected.",
		token, s.cfg.RecoveryTokenTTL.Round(time.Minute),
	)

	if err := s.mailer.Send(email, subject, body); err != nil {
		// Logged, not returned: the caller learns nothing about whether
		// sending succeeded, which is part of not distinguishing a real
		// account from one that doesn't exist.
		s.log.Error("send recovery email", "error", err)
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": generic})
}

type recoverKeysRequest struct {
	Token string `json:"token"`
}

type recoverKeysResponse struct {
	WrappedKeyRecovery json.RawMessage `json:"wrapped_key_recovery"`
}

func (s *Server) handleRecoverKeys(w http.ResponseWriter, r *http.Request) {
	var req recoverKeysRequest
	if err := decodeJSON(r, &req); err != nil || req.Token == "" {
		writeError(w, http.StatusBadRequest, "a recovery token is required")
		return
	}

	ctx := r.Context()

	rt, err := s.store.GetRecoveryToken(ctx, auth.HashToken(req.Token))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "that recovery link is invalid or has expired")
		return
	}
	if err != nil {
		s.log.Error("get recovery token", "error", err)
		writeError(w, http.StatusInternalServerError, "could not process recovery")
		return
	}

	keys, err := s.store.GetWrappedKeys(ctx, rt.UserID)
	if err != nil {
		s.log.Error("get wrapped keys for recovery", "error", err)
		writeError(w, http.StatusInternalServerError, "could not process recovery")
		return
	}

	var resp recoverKeysResponse
	for _, k := range keys {
		if k.Variant == model.WrappedKeyRecovery {
			resp.WrappedKeyRecovery = json.RawMessage(k.Envelope)
		}
	}

	if len(resp.WrappedKeyRecovery) == 0 {
		writeError(w, http.StatusNotFound, "no recovery key is set up for this account")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

type recoverCompleteRequest struct {
	Token                string          `json:"token"`
	NewLoginPassword     string          `json:"new_login_password"`
	WrappedKeyPassphrase json.RawMessage `json:"wrapped_key_passphrase"`
	WrappedKeyRecovery   json.RawMessage `json:"wrapped_key_recovery"`
}

func (s *Server) handleRecoverComplete(w http.ResponseWriter, r *http.Request) {
	var req recoverCompleteRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if len(req.NewLoginPassword) < minPasswordLength {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if len(req.WrappedKeyPassphrase) == 0 || len(req.WrappedKeyRecovery) == 0 {
		writeError(w, http.StatusBadRequest, "both re-sealed key envelopes are required")
		return
	}

	ctx := r.Context()
	tokenHash := auth.HashToken(req.Token)

	rt, err := s.store.GetRecoveryToken(ctx, tokenHash)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "that recovery link is invalid or has expired")
		return
	}
	if err != nil {
		s.log.Error("get recovery token", "error", err)
		writeError(w, http.StatusInternalServerError, "could not complete recovery")
		return
	}

	newHash, err := auth.HashPassword(req.NewLoginPassword)
	if err != nil {
		s.log.Error("hash new password", "error", err)
		writeError(w, http.StatusInternalServerError, "could not complete recovery")
		return
	}

	if err := s.store.UpdateLoginPasswordHash(ctx, rt.UserID, newHash); err != nil {
		s.log.Error("update password hash for recovery", "error", err)
		writeError(w, http.StatusInternalServerError, "could not complete recovery")
		return
	}

	now := time.Now()
	for variant, envelope := range map[model.WrappedKeyVariant]json.RawMessage{
		model.WrappedKeyPassphrase: req.WrappedKeyPassphrase,
		model.WrappedKeyRecovery:   req.WrappedKeyRecovery,
	} {
		wk := model.WrappedKey{UserID: rt.UserID, Variant: variant, Envelope: string(envelope), UpdatedAt: now}
		if err := s.store.PutWrappedKey(ctx, wk); err != nil {
			s.log.Error("update wrapped key after recovery", "variant", variant, "error", err)
			writeError(w, http.StatusInternalServerError,
				"password reset, but saving your new keys failed -- try recovery again")
			return
		}
	}

	if err := s.store.MarkRecoveryTokenUsed(ctx, tokenHash); err != nil {
		s.log.Error("mark recovery token used", "error", err)
	}

	// A password reset -- legitimate or not -- should not leave whatever
	// session an attacker may already hold still valid.
	if err := s.store.DeleteSessionsByUserID(ctx, rt.UserID); err != nil {
		s.log.Error("revoke sessions after recovery", "error", err)
	}

	token, expiresAt, err := s.issueSession(ctx, rt.UserID, "")
	if err != nil {
		s.log.Error("issue session after recovery", "error", err)
		writeError(w, http.StatusInternalServerError, "recovery completed, but sign-in failed -- try logging in")
		return
	}

	writeJSON(w, http.StatusOK, sessionResponse{UserID: rt.UserID, SessionToken: token, ExpiresAt: expiresAt})
}

func randomToken() (string, error) {
	buf := make([]byte, recoveryTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
