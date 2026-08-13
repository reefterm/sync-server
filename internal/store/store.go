// Package store defines the persistence interface the API layer depends on,
// so swapping SQLite for Postgres later is an implementation of this
// interface, not a rewrite of the API.
package store

import (
	"context"
	"errors"

	"github.com/reefterm/sync-server/internal/model"
)

// ErrNotFound is returned by any lookup that found nothing. Callers check
// errors.Is(err, ErrNotFound) rather than a sentinel per method, so adding a
// new lookup never means inventing a new not-found error to remember.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned by PutSnapshot when the caller's BaseRevision no
// longer matches what's stored. It carries no payload of its own; the
// caller re-reads GetSnapshot to learn the winning revision, the same round
// trip a network client would make anyway.
var ErrConflict = errors.New("revision conflict")

// ErrExists is returned by CreateUser when the email is already registered.
var ErrExists = errors.New("already exists")

// Store is everything the API layer needs from persistence. Every method
// takes a context so a slow query can be cancelled with the request that
// asked for it, and every method is safe to call concurrently.
type Store interface {
	CreateUser(ctx context.Context, u model.User) error
	GetUserByEmail(ctx context.Context, email string) (model.User, error)
	GetUserByID(ctx context.Context, id string) (model.User, error)
	UpdateLoginPasswordHash(ctx context.Context, userID, hash string) error

	CreateSession(ctx context.Context, s model.Session) error
	// GetSession looks up a session by the hash of its token, and returns
	// ErrNotFound for a session that never existed and for one that's
	// expired -- an expired session is not a different case a caller needs
	// to branch on, it's just gone.
	GetSession(ctx context.Context, tokenHash string) (model.Session, error)
	DeleteSession(ctx context.Context, tokenHash string) error
	// DeleteSessionsByUserID revokes every session for a user in one call --
	// used when email-based recovery completes, since a password/passphrase
	// reset should not leave whatever session an attacker may already hold
	// still valid.
	DeleteSessionsByUserID(ctx context.Context, userID string) error

	// CreateRecoveryToken also invalidates any of the user's previous unused
	// tokens, so at most one is ever live -- the last email sent is the one
	// that works, and requesting a new one can't be used to keep an old,
	// possibly-leaked token valid indefinitely.
	CreateRecoveryToken(ctx context.Context, t model.RecoveryToken) error
	// GetRecoveryToken returns ErrNotFound for a token that never existed,
	// has expired, or has already been used -- all three are "this token
	// doesn't grant anything", not three cases a caller must tell apart.
	GetRecoveryToken(ctx context.Context, tokenHash string) (model.RecoveryToken, error)
	MarkRecoveryTokenUsed(ctx context.Context, tokenHash string) error

	PutWrappedKey(ctx context.Context, wk model.WrappedKey) error
	GetWrappedKeys(ctx context.Context, userID string) ([]model.WrappedKey, error)

	// GetSnapshot returns ErrNotFound for a user who has never pushed one --
	// the ordinary state for a fresh account, not a fault.
	GetSnapshot(ctx context.Context, userID string) (model.Snapshot, error)
	// PutSnapshot writes only if baseRevision matches the stored revision
	// (0 meaning "nothing stored yet"), and returns ErrConflict otherwise.
	// The check-and-write has to be one atomic operation at the
	// implementation's level, or two devices racing could both "win".
	PutSnapshot(ctx context.Context, s model.Snapshot, baseRevision int64) error

	Close() error
}
