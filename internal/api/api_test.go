package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/reefterm/sync-server/internal/config"
	"github.com/reefterm/sync-server/internal/store/sqlite"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()

	st, err := sqlite.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := config.Config{
		DBPath:            ":memory:",
		AllowRegistration: true,
		SessionTTL:        time.Hour,
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(st, cfg, log)
}

func doJSON(t *testing.T, srv *Server, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(b)
	}

	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func mustRegister(t *testing.T, srv *Server, email string) sessionResponse {
	t.Helper()

	rec := doJSON(t, srv, "POST", "/api/v1/register", registerRequest{
		Email:                email,
		LoginPassword:        "a reasonably long password",
		WrappedKeyPassphrase: json.RawMessage(`{"format":"reefterm-snapshot","payload":"passphrase-envelope"}`),
		WrappedKeyRecovery:   json.RawMessage(`{"format":"reefterm-snapshot","payload":"recovery-envelope"}`),
		DeviceName:           "test-device",
	}, "")

	if rec.Code != http.StatusCreated {
		t.Fatalf("register: got status %d, body %s", rec.Code, rec.Body.String())
	}

	var resp sessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	return resp
}

func TestHealthAndVersion(t *testing.T) {
	srv := newTestServer(t)

	rec := doJSON(t, srv, "GET", "/api/v1/health", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("health: got status %d", rec.Code)
	}

	rec = doJSON(t, srv, "GET", "/api/v1/version", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("version: got status %d", rec.Code)
	}
}

func TestRegisterLoginAccount(t *testing.T) {
	srv := newTestServer(t)

	reg := mustRegister(t, srv, "alice@example.com")
	if reg.UserID == "" || reg.SessionToken == "" {
		t.Fatalf("register returned an incomplete session: %+v", reg)
	}

	rec := doJSON(t, srv, "GET", "/api/v1/account", nil, reg.SessionToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("account: got status %d, body %s", rec.Code, rec.Body.String())
	}
	var acct accountResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &acct); err != nil {
		t.Fatalf("decode account response: %v", err)
	}
	if acct.Email != "alice@example.com" {
		t.Errorf("got email %q, want alice@example.com", acct.Email)
	}

	loginRec := doJSON(t, srv, "POST", "/api/v1/login", loginRequest{
		Email: "alice@example.com", LoginPassword: "a reasonably long password", DeviceName: "second-device",
	}, "")
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login: got status %d, body %s", loginRec.Code, loginRec.Body.String())
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	srv := newTestServer(t)
	mustRegister(t, srv, "bob@example.com")

	rec := doJSON(t, srv, "POST", "/api/v1/login", loginRequest{
		Email: "bob@example.com", LoginPassword: "totally the wrong password",
	}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401 for a wrong password", rec.Code)
	}
}

func TestRegisterRejectsDuplicateEmail(t *testing.T) {
	srv := newTestServer(t)
	mustRegister(t, srv, "dup@example.com")

	rec := doJSON(t, srv, "POST", "/api/v1/register", registerRequest{
		Email:                "dup@example.com",
		LoginPassword:        "a different password",
		WrappedKeyPassphrase: json.RawMessage(`{"a":1}`),
		WrappedKeyRecovery:   json.RawMessage(`{"a":2}`),
	}, "")

	if rec.Code != http.StatusConflict {
		t.Fatalf("got status %d, want 409 for a duplicate email", rec.Code)
	}
}

func TestRegisterRefusedWhenClosed(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.AllowRegistration = false

	rec := doJSON(t, srv, "POST", "/api/v1/register", registerRequest{
		Email:                "late@example.com",
		LoginPassword:        "a reasonably long password",
		WrappedKeyPassphrase: json.RawMessage(`{"a":1}`),
		WrappedKeyRecovery:   json.RawMessage(`{"a":2}`),
	}, "")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want 403 when registration is closed", rec.Code)
	}
}

func TestAuthenticatedRoutesRejectMissingOrBadToken(t *testing.T) {
	srv := newTestServer(t)

	routes := []string{"/api/v1/account", "/api/v1/sync/keys", "/api/v1/sync/snapshot/meta", "/api/v1/sync/snapshot"}

	for _, route := range routes {
		rec := doJSON(t, srv, "GET", route, nil, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with no token: got status %d, want 401", route, rec.Code)
		}

		rec = doJSON(t, srv, "GET", route, nil, "not-a-real-token")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with a bogus token: got status %d, want 401", route, rec.Code)
		}
	}
}

func TestLogoutInvalidatesTheSession(t *testing.T) {
	srv := newTestServer(t)
	reg := mustRegister(t, srv, "logout@example.com")

	rec := doJSON(t, srv, "POST", "/api/v1/logout", nil, reg.SessionToken)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout: got status %d", rec.Code)
	}

	rec = doJSON(t, srv, "GET", "/api/v1/account", nil, reg.SessionToken)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401 for a token used after logout", rec.Code)
	}
}

func TestChangePasswordUpdatesLoginAndEnvelopeTogether(t *testing.T) {
	srv := newTestServer(t)
	reg := mustRegister(t, srv, "change@example.com")

	rec := doJSON(t, srv, "PUT", "/api/v1/account/password", changePasswordRequest{
		CurrentLoginPassword: "a reasonably long password",
		NewLoginPassword:     "a brand new password here",
		WrappedKeyPassphrase: json.RawMessage(`{"payload":"resealed-under-new-password"}`),
	}, reg.SessionToken)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("change password: got status %d, body %s", rec.Code, rec.Body.String())
	}

	// The old password no longer logs in.
	oldLogin := doJSON(t, srv, "POST", "/api/v1/login", loginRequest{
		Email: "change@example.com", LoginPassword: "a reasonably long password",
	}, "")
	if oldLogin.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401 logging in with the old password after a change", oldLogin.Code)
	}

	// The new password does.
	newLogin := doJSON(t, srv, "POST", "/api/v1/login", loginRequest{
		Email: "change@example.com", LoginPassword: "a brand new password here",
	}, "")
	if newLogin.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 logging in with the new password", newLogin.Code)
	}

	var loginResp sessionResponse
	if err := json.Unmarshal(newLogin.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}

	// The envelope was re-sealed too, and the old session's token still
	// reads the update: sync/keys is not scoped to which login produced it.
	keysRec := doJSON(t, srv, "GET", "/api/v1/sync/keys", nil, loginResp.SessionToken)
	var keys syncKeysResponse
	if err := json.Unmarshal(keysRec.Body.Bytes(), &keys); err != nil {
		t.Fatalf("decode sync keys: %v", err)
	}
	if string(keys.WrappedKeyPassphrase) != `{"payload":"resealed-under-new-password"}` {
		t.Errorf("passphrase envelope was not updated: %s", keys.WrappedKeyPassphrase)
	}
}

func TestChangePasswordRejectsWrongCurrentPassword(t *testing.T) {
	srv := newTestServer(t)
	reg := mustRegister(t, srv, "wrongcur@example.com")

	rec := doJSON(t, srv, "PUT", "/api/v1/account/password", changePasswordRequest{
		CurrentLoginPassword: "not the actual current password",
		NewLoginPassword:     "a brand new password here",
		WrappedKeyPassphrase: json.RawMessage(`{"a":1}`),
	}, reg.SessionToken)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401 for a wrong current password", rec.Code)
	}

	// And the login password must be genuinely unchanged.
	login := doJSON(t, srv, "POST", "/api/v1/login", loginRequest{
		Email: "wrongcur@example.com", LoginPassword: "a reasonably long password",
	}, "")
	if login.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 -- the original password must still work", login.Code)
	}
}

func TestSyncKeysRoundTripAndAreOpaque(t *testing.T) {
	srv := newTestServer(t)
	reg := mustRegister(t, srv, "keys@example.com")

	rec := doJSON(t, srv, "GET", "/api/v1/sync/keys", nil, reg.SessionToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("get sync keys: got status %d, body %s", rec.Code, rec.Body.String())
	}

	var resp syncKeysResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(resp.WrappedKeyPassphrase) != `{"format":"reefterm-snapshot","payload":"passphrase-envelope"}` {
		t.Errorf("passphrase envelope came back altered: %s", resp.WrappedKeyPassphrase)
	}
	if string(resp.WrappedKeyRecovery) != `{"format":"reefterm-snapshot","payload":"recovery-envelope"}` {
		t.Errorf("recovery envelope came back altered: %s", resp.WrappedKeyRecovery)
	}
}

func TestRotatingRecoveryEnvelopeLeavesPassphraseEnvelopeAlone(t *testing.T) {
	srv := newTestServer(t)
	reg := mustRegister(t, srv, "rotate@example.com")

	rec := doJSON(t, srv, "PUT", "/api/v1/sync/keys/recovery", putWrappedKeyRequest{
		Envelope: json.RawMessage(`{"payload":"new-recovery-envelope"}`),
	}, reg.SessionToken)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("put recovery key: got status %d, body %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, srv, "GET", "/api/v1/sync/keys", nil, reg.SessionToken)
	var resp syncKeysResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if string(resp.WrappedKeyRecovery) != `{"payload":"new-recovery-envelope"}` {
		t.Errorf("recovery envelope did not update: %s", resp.WrappedKeyRecovery)
	}
	if string(resp.WrappedKeyPassphrase) != `{"format":"reefterm-snapshot","payload":"passphrase-envelope"}` {
		t.Errorf("passphrase envelope changed when only recovery was rotated: %s", resp.WrappedKeyPassphrase)
	}
}

func TestSnapshotMetaBeforeAnyPush(t *testing.T) {
	srv := newTestServer(t)
	reg := mustRegister(t, srv, "fresh@example.com")

	rec := doJSON(t, srv, "GET", "/api/v1/sync/snapshot/meta", nil, reg.SessionToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d", rec.Code)
	}

	var meta snapshotMetaResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if meta.Exists {
		t.Error("a fresh account must report no snapshot yet")
	}
}

func TestSnapshotPushPullAndConflict(t *testing.T) {
	srv := newTestServer(t)
	reg := mustRegister(t, srv, "snap@example.com")

	push := doJSON(t, srv, "POST", "/api/v1/sync/snapshot", putSnapshotRequest{
		Payload:      json.RawMessage(`{"cipher":"first-version"}`),
		BaseRevision: 0,
		DeviceName:   "laptop",
		Stats:        json.RawMessage(`{"hosts":3}`),
	}, reg.SessionToken)
	if push.Code != http.StatusOK {
		t.Fatalf("push: got status %d, body %s", push.Code, push.Body.String())
	}

	var pushResp putSnapshotResponse
	if err := json.Unmarshal(push.Body.Bytes(), &pushResp); err != nil {
		t.Fatalf("decode push response: %v", err)
	}
	if pushResp.Revision != 1 {
		t.Fatalf("got revision %d after first push, want 1", pushResp.Revision)
	}

	pull := doJSON(t, srv, "GET", "/api/v1/sync/snapshot", nil, reg.SessionToken)
	if pull.Code != http.StatusOK {
		t.Fatalf("pull: got status %d", pull.Code)
	}
	var pullResp snapshotResponse
	if err := json.Unmarshal(pull.Body.Bytes(), &pullResp); err != nil {
		t.Fatalf("decode pull response: %v", err)
	}
	if string(pullResp.Payload) != `{"cipher":"first-version"}` {
		t.Errorf("got payload %s, want the pushed ciphertext unchanged", pullResp.Payload)
	}
	if pullResp.Revision != 1 {
		t.Errorf("got revision %d, want 1", pullResp.Revision)
	}

	// A second device pushes against the now-stale base revision 0.
	conflict := doJSON(t, srv, "POST", "/api/v1/sync/snapshot", putSnapshotRequest{
		Payload:      json.RawMessage(`{"cipher":"conflicting-version"}`),
		BaseRevision: 0,
		DeviceName:   "phone",
	}, reg.SessionToken)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("got status %d, want 409 for a stale base revision", conflict.Code)
	}

	var conflictResp conflictResponse
	if err := json.Unmarshal(conflict.Body.Bytes(), &conflictResp); err != nil {
		t.Fatalf("decode conflict response: %v", err)
	}
	if conflictResp.Error.Revision != 1 {
		t.Errorf("conflict response reported revision %d, want the actual current revision 1", conflictResp.Error.Revision)
	}
}

func TestSnapshotStatsAreStoredButPayloadStaysOpaque(t *testing.T) {
	// This is really a documentation test: it exists to make plain that the
	// server never validates, parses or otherwise looks inside `payload`
	// beyond treating it as a JSON value to store and return -- if this
	// test ever needs the payload to be "real" ciphertext to pass, that's
	// a sign something started parsing it.
	srv := newTestServer(t)
	reg := mustRegister(t, srv, "opaque@example.com")

	rec := doJSON(t, srv, "POST", "/api/v1/sync/snapshot", putSnapshotRequest{
		Payload:      json.RawMessage(`"not even a real envelope, just a string"`),
		BaseRevision: 0,
	}, reg.SessionToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 -- the server must not validate payload structure", rec.Code)
	}
}
