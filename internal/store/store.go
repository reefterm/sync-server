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

	CreateSession(ctx context.Context, s model.Session) error
	// GetSession looks up a session by the hash of its token, and returns
	// ErrNotFound for a session that never existed and for one that's
	// expired -- an expired session is not a different case a caller needs
	// to branch on, it's just gone.
	GetSession(ctx context.Context, tokenHash string) (model.Session, error)
	DeleteSession(ctx context.Context, tokenHash string) error

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
