// Package api is the HTTP surface: routing, auth middleware, and the
// request/response shapes the client speaks. Every handler here is thin on
// purpose -- the actual logic lives in package auth (tokens, passwords) and
// package store (persistence), and this package's job is only to translate
// HTTP into calls on those and back.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/reefterm/sync-server/internal/auth"
	"github.com/reefterm/sync-server/internal/config"
	"github.com/reefterm/sync-server/internal/store"
)

// Version is the server's own version string, reported at GET
// /api/v1/version. Set via -ldflags at build time; "dev" otherwise.
var Version = "dev"

type Server struct {
	store store.Store
	cfg   config.Config
	log   *slog.Logger
	mux   *http.ServeMux
}

func New(st store.Store, cfg config.Config, log *slog.Logger) *Server {
	s := &Server{store: st, cfg: cfg, log: log, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/version", s.handleVersion)

	s.mux.HandleFunc("POST /api/v1/register", s.handleRegister)
	s.mux.HandleFunc("POST /api/v1/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/v1/logout", s.withAuth(s.handleLogout))
	s.mux.HandleFunc("GET /api/v1/account", s.withAuth(s.handleAccount))
	s.mux.HandleFunc("PUT /api/v1/account/password", s.withAuth(s.handleChangePassword))

	s.mux.HandleFunc("GET /api/v1/sync/keys", s.withAuth(s.handleGetSyncKeys))
	s.mux.HandleFunc("PUT /api/v1/sync/keys/passphrase", s.withAuth(s.handlePutSyncKeyPassphrase))
	s.mux.HandleFunc("PUT /api/v1/sync/keys/recovery", s.withAuth(s.handlePutSyncKeyRecovery))

	s.mux.HandleFunc("GET /api/v1/sync/snapshot/meta", s.withAuth(s.handleSnapshotMeta))
	s.mux.HandleFunc("GET /api/v1/sync/snapshot", s.withAuth(s.handleSnapshotGet))
	s.mux.HandleFunc("POST /api/v1/sync/snapshot", s.withAuth(s.handleSnapshotPut))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": Version})
}

/* ------------------------------------------------------------------ *
 * Auth middleware
 *
 * Opaque bearer token, looked up by its hash. Revocation needs
 * server-side state regardless of token format, so JWT's usual
 * stateless advantage does not apply here -- see the design notes in
 * README.md.
 * ------------------------------------------------------------------ */

type contextKey int

const userIDKey contextKey = 0

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}

		sess, err := s.store.GetSession(r.Context(), auth.HashToken(token))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "session expired or invalid")
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, sess.UserID)
		next(w, r.WithContext(ctx))
	}
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || h[:len(prefix)] != prefix {
		return ""
	}
	return h[len(prefix):]
}

func userID(r *http.Request) string {
	v, _ := r.Context().Value(userIDKey).(string)
	return v
}

/* ------------------------------------------------------------------ *
 * JSON helpers
 * ------------------------------------------------------------------ */

type errorEnvelope struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	var env errorEnvelope
	env.Error.Message = message
	writeJSON(w, status, env)
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func newExpiry(cfg config.Config) time.Time {
	return time.Now().Add(cfg.SessionTTL)
}
