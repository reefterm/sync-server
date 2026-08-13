package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/reefterm/sync-server/internal/auth"
	"github.com/reefterm/sync-server/internal/model"
	"github.com/reefterm/sync-server/internal/store"
)

const minPasswordLength = 8

type registerRequest struct {
	Email                string          `json:"email"`
	LoginPassword        string          `json:"login_password"`
	WrappedKeyPassphrase json.RawMessage `json:"wrapped_key_passphrase"`
	WrappedKeyRecovery   json.RawMessage `json:"wrapped_key_recovery"`
	DeviceName           string          `json:"device_name"`
}

type sessionResponse struct {
	UserID       string    `json:"user_id"`
	SessionToken string    `json:"session_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// handleRegister creates the account and, in the same request, stores both
// wrapped-key envelopes the client already sealed before sending them here.
// Neither envelope is inspected: they arrive as raw JSON and are stored as
// the exact bytes they came in as. This server never sees the passphrase,
// the recovery code, or the key they wrap.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AllowRegistration {
		writeError(w, http.StatusForbidden, "registration is closed on this server")
		return
	}

	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusBadRequest, "a valid email is required")
		return
	}
	if len(req.LoginPassword) < minPasswordLength {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if len(req.WrappedKeyPassphrase) == 0 || len(req.WrappedKeyRecovery) == 0 {
		writeError(w, http.StatusBadRequest, "both wrapped key envelopes are required")
		return
	}

	hash, err := auth.HashPassword(req.LoginPassword)
	if err != nil {
		s.log.Error("hash password", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create account")
		return
	}

	userID, err := randomID()
	if err != nil {
		s.log.Error("generate user id", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create account")
		return
	}

	ctx := r.Context()
	now := time.Now()

	user := model.User{ID: userID, Email: req.Email, LoginPasswordHash: hash, CreatedAt: now}
	if err := s.store.CreateUser(ctx, user); err != nil {
		if errors.Is(err, store.ErrExists) {
			writeError(w, http.StatusConflict, "an account with this email already exists")
			return
		}
		s.log.Error("create user", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create account")
		return
	}

	for variant, envelope := range map[model.WrappedKeyVariant]json.RawMessage{
		model.WrappedKeyPassphrase: req.WrappedKeyPassphrase,
		model.WrappedKeyRecovery:   req.WrappedKeyRecovery,
	} {
		wk := model.WrappedKey{UserID: userID, Variant: variant, Envelope: string(envelope), UpdatedAt: now}
		if err := s.store.PutWrappedKey(ctx, wk); err != nil {
			s.log.Error("store wrapped key", "variant", variant, "error", err)
			writeError(w, http.StatusInternalServerError, "could not create account")
			return
		}
	}

	token, expiresAt, err := s.issueSession(ctx, userID, req.DeviceName)
	if err != nil {
		s.log.Error("issue session", "error", err)
		writeError(w, http.StatusInternalServerError, "account created, but sign-in failed -- try logging in")
		return
	}

	writeJSON(w, http.StatusCreated, sessionResponse{UserID: userID, SessionToken: token, ExpiresAt: expiresAt})
}

type loginRequest struct {
	Email         string `json:"email"`
	LoginPassword string `json:"login_password"`
	DeviceName    string `json:"device_name"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))

	user, err := s.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		// Same message whether the email doesn't exist or the password is
		// wrong: telling them apart hands an attacker a working way to
		// enumerate registered emails.
		writeError(w, http.StatusUnauthorized, "incorrect email or password")
		return
	}

	ok, err := auth.VerifyPassword(req.LoginPassword, user.LoginPasswordHash)
	if err != nil || !ok {
		writeError(w, http.StatusUnauthorized, "incorrect email or password")
		return
	}

	token, expiresAt, err := s.issueSession(r.Context(), user.ID, req.DeviceName)
	if err != nil {
		s.log.Error("issue session", "error", err)
		writeError(w, http.StatusInternalServerError, "could not sign in")
		return
	}

	writeJSON(w, http.StatusOK, sessionResponse{UserID: user.ID, SessionToken: token, ExpiresAt: expiresAt})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if err := s.store.DeleteSession(r.Context(), auth.HashToken(token)); err != nil {
		s.log.Error("delete session", "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

type accountResponse struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	user, err := s.store.GetUserByID(r.Context(), userID(r))
	if err != nil {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}
	writeJSON(w, http.StatusOK, accountResponse{UserID: user.ID, Email: user.Email, CreatedAt: user.CreatedAt})
}

func (s *Server) issueSession(ctx context.Context, uid, deviceName string) (token string, expiresAt time.Time, err error) {
	token, err = auth.NewToken()
	if err != nil {
		return "", time.Time{}, err
	}

	expiresAt = newExpiry(s.cfg)

	sess := model.Session{
		TokenHash:  auth.HashToken(token),
		UserID:     uid,
		DeviceName: deviceName,
		CreatedAt:  time.Now(),
		ExpiresAt:  expiresAt,
	}

	if err := s.store.CreateSession(ctx, sess); err != nil {
		return "", time.Time{}, err
	}

	return token, expiresAt, nil
}

// randomID returns a URL-safe random identifier. Not a UUID: there is no
// need for RFC 4122's structure when nothing parses these beyond comparing
// them for equality, and 24 random bytes is more entropy than a UUID's 122
// bits already.
func randomID() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
