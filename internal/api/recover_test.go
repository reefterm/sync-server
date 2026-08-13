package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestRecoverStartUnavailableWithoutSMTP(t *testing.T) {
	srv := newTestServer(t) // SMTP not configured
	mustRegister(t, srv, "nosmtp@example.com")

	rec := doJSON(t, srv, "POST", "/api/v1/recover/start", recoverStartRequest{Email: "nosmtp@example.com"}, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want 503 when no SMTP server is configured", rec.Code)
	}
}

func TestRecoverStartIsGenericWhetherOrNotTheEmailExists(t *testing.T) {
	srv, fake := newTestServerWithMail(t, true)
	mustRegister(t, srv, "exists@example.com")

	existing := doJSON(t, srv, "POST", "/api/v1/recover/start", recoverStartRequest{Email: "exists@example.com"}, "")
	missing := doJSON(t, srv, "POST", "/api/v1/recover/start", recoverStartRequest{Email: "nobody@example.com"}, "")

	if existing.Code != http.StatusOK || missing.Code != http.StatusOK {
		t.Fatalf("got statuses %d and %d, want 200 for both regardless of whether the account exists",
			existing.Code, missing.Code)
	}
	if existing.Body.String() != missing.Body.String() {
		t.Fatalf("responses differ (%q vs %q) -- this leaks which emails are registered",
			existing.Body.String(), missing.Body.String())
	}

	// Only the real account actually gets mail.
	if len(fake.sent) != 1 {
		t.Fatalf("got %d emails sent, want exactly 1 (only for the account that exists)", len(fake.sent))
	}
	if fake.sent[0].to != "exists@example.com" {
		t.Errorf("email went to %q, want exists@example.com", fake.sent[0].to)
	}
}

// extractToken pulls the recovery token out of the fake mailer's captured
// body, using the same format handleRecoverStart writes it in.
func extractToken(t *testing.T, body string) string {
	t.Helper()
	const marker = "Recovery code:\n\n    "
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("could not find the recovery token in the email body: %q", body)
	}
	rest := body[i+len(marker):]
	return strings.TrimSpace(strings.SplitN(rest, "\n", 2)[0])
}

func TestRecoverKeysReturnsTheRecoveryEnvelope(t *testing.T) {
	srv, fake := newTestServerWithMail(t, true)
	reg := mustRegister(t, srv, "keys@example.com")
	_ = reg

	doJSON(t, srv, "POST", "/api/v1/recover/start", recoverStartRequest{Email: "keys@example.com"}, "")
	token := extractToken(t, fake.last().body)

	rec := doJSON(t, srv, "POST", "/api/v1/recover/keys", recoverKeysRequest{Token: token}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, body %s", rec.Code, rec.Body.String())
	}

	var resp recoverKeysResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(resp.WrappedKeyRecovery) != `{"format":"reefterm-snapshot","payload":"recovery-envelope"}` {
		t.Errorf("got a different recovery envelope than what was registered: %s", resp.WrappedKeyRecovery)
	}
}

func TestRecoverKeysRejectsAnInvalidToken(t *testing.T) {
	srv, _ := newTestServerWithMail(t, true)

	rec := doJSON(t, srv, "POST", "/api/v1/recover/keys", recoverKeysRequest{Token: "not-a-real-token"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401 for an invalid token", rec.Code)
	}
}

func TestRecoverCompleteResetsPasswordAndRevokesOldSessions(t *testing.T) {
	srv, fake := newTestServerWithMail(t, true)
	reg := mustRegister(t, srv, "complete@example.com")

	// The old session, still technically valid, should stop working once
	// recovery completes.
	oldToken := reg.SessionToken

	doJSON(t, srv, "POST", "/api/v1/recover/start", recoverStartRequest{Email: "complete@example.com"}, "")
	token := extractToken(t, fake.last().body)

	rec := doJSON(t, srv, "POST", "/api/v1/recover/complete", recoverCompleteRequest{
		Token:                token,
		NewLoginPassword:     "a brand new recovered password",
		WrappedKeyPassphrase: json.RawMessage(`{"payload":"resealed-after-recovery"}`),
		WrappedKeyRecovery:   json.RawMessage(`{"payload":"rotated-after-recovery"}`),
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, body %s", rec.Code, rec.Body.String())
	}

	var resp sessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.SessionToken == "" {
		t.Fatal("recovery should issue a fresh session token")
	}

	// The old session is gone.
	stale := doJSON(t, srv, "GET", "/api/v1/account", nil, oldToken)
	if stale.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401 for a session that predates recovery", stale.Code)
	}

	// The new session works.
	fresh := doJSON(t, srv, "GET", "/api/v1/account", nil, resp.SessionToken)
	if fresh.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 for the session recovery just issued", fresh.Code)
	}

	// The old password no longer logs in; the new one does.
	oldLogin := doJSON(t, srv, "POST", "/api/v1/login", loginRequest{
		Email: "complete@example.com", LoginPassword: "a reasonably long password",
	}, "")
	if oldLogin.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401 logging in with the pre-recovery password", oldLogin.Code)
	}

	newLogin := doJSON(t, srv, "POST", "/api/v1/login", loginRequest{
		Email: "complete@example.com", LoginPassword: "a brand new recovered password",
	}, "")
	if newLogin.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 logging in with the recovered password", newLogin.Code)
	}
}

func TestRecoverCompleteRejectsReusingTheSameToken(t *testing.T) {
	srv, fake := newTestServerWithMail(t, true)
	mustRegister(t, srv, "reuse@example.com")

	doJSON(t, srv, "POST", "/api/v1/recover/start", recoverStartRequest{Email: "reuse@example.com"}, "")
	token := extractToken(t, fake.last().body)

	first := doJSON(t, srv, "POST", "/api/v1/recover/complete", recoverCompleteRequest{
		Token: token, NewLoginPassword: "first new password here",
		WrappedKeyPassphrase: json.RawMessage(`{"a":1}`), WrappedKeyRecovery: json.RawMessage(`{"a":2}`),
	}, "")
	if first.Code != http.StatusOK {
		t.Fatalf("first completion: got status %d, body %s", first.Code, first.Body.String())
	}

	second := doJSON(t, srv, "POST", "/api/v1/recover/complete", recoverCompleteRequest{
		Token: token, NewLoginPassword: "second new password here",
		WrappedKeyPassphrase: json.RawMessage(`{"a":3}`), WrappedKeyRecovery: json.RawMessage(`{"a":4}`),
	}, "")
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401 reusing an already-spent recovery token", second.Code)
	}
}

func TestRecoverStartInvalidatesAnEarlierUnusedToken(t *testing.T) {
	srv, fake := newTestServerWithMail(t, true)
	mustRegister(t, srv, "superseded@example.com")

	doJSON(t, srv, "POST", "/api/v1/recover/start", recoverStartRequest{Email: "superseded@example.com"}, "")
	firstToken := extractToken(t, fake.last().body)

	doJSON(t, srv, "POST", "/api/v1/recover/start", recoverStartRequest{Email: "superseded@example.com"}, "")
	secondToken := extractToken(t, fake.last().body)

	if firstToken == secondToken {
		t.Fatal("two separate recovery requests produced the same token")
	}

	old := doJSON(t, srv, "POST", "/api/v1/recover/keys", recoverKeysRequest{Token: firstToken}, "")
	if old.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401 -- an earlier token should be invalidated by a newer request", old.Code)
	}

	fresh := doJSON(t, srv, "POST", "/api/v1/recover/keys", recoverKeysRequest{Token: secondToken}, "")
	if fresh.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 for the latest token", fresh.Code)
	}
}
