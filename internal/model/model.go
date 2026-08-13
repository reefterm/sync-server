// Package model holds the types this server persists and passes between its
// layers. Nothing here has a JSON tag opinion beyond what's needed by
// package api -- API wire shapes are defined there, not here, so a change to
// what the HTTP layer accepts doesn't ripple into storage.
package model

import "time"

// User is an account. LoginPasswordHash is an argon2id hash, never the
// plaintext. The two wrapped-key envelopes and the snapshot are stored
// separately, keyed by UserID, so a user with no snapshot yet or no
// recovery envelope yet isn't a null field on this struct to forget to
// check.
type User struct {
	ID                string
	Email             string
	LoginPasswordHash string
	CreatedAt         time.Time
}

// WrappedKeyVariant distinguishes the two independent unlock paths to the
// same Sync Master Key. Both wrap the same key; neither can derive the
// other.
type WrappedKeyVariant string

const (
	WrappedKeyPassphrase WrappedKeyVariant = "passphrase"
	WrappedKeyRecovery   WrappedKeyVariant = "recovery"
)

// WrappedKey is an opaque envelope this server stores and serves back
// verbatim. Envelope is the JSON-encoded seal() output from the client's
// backup.js -- this server never parses it, never derives a key from it,
// and has no way to open it. That's the point: the server holds ciphertext
// it cannot read.
type WrappedKey struct {
	UserID    string
	Variant   WrappedKeyVariant
	Envelope  string
	UpdatedAt time.Time
}

// Session is a logged-in device. TokenHash, never the raw token, is what's
// stored -- a database leak then doesn't leak a usable session. The token
// itself exists only in the response to login/register and in the client's
// own memory.
type Session struct {
	TokenHash  string
	UserID     string
	DeviceName string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// RecoveryToken proves control of the account's registered email, as a
// prerequisite to email-based recovery. TokenHash, never the raw token, is
// what's stored, for the same reason a Session's is: a database leak must
// not hand out a usable token.
//
// UsedAt is nil until the token is spent completing a recovery. It stays in
// the table (not deleted) so a reused token is a "this token isn't valid"
// error rather than a "no such token", which is what makes double-submit
// and replay attempts fail the same way as a token that was never valid.
type RecoveryToken struct {
	TokenHash string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// Snapshot is one user's synced setup: an encrypted blob plus the bookkeeping
// that makes concurrent devices safe. Revision is compared against a
// client's base_revision for optimistic-concurrency writes -- see
// package api's snapshot handlers.
type Snapshot struct {
	UserID     string
	Revision   int64
	Payload    string
	Stats      string
	DeviceName string
	UpdatedAt  time.Time
}
