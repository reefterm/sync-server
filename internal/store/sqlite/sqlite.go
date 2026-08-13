// Package sqlite is the default Store implementation: one file, no server to
// stand up separately, which is the whole point for something meant to be
// this easy to self-host.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/reefterm/sync-server/internal/model"
	"github.com/reefterm/sync-server/internal/store"
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    login_password_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    device_name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

CREATE TABLE IF NOT EXISTS wrapped_keys (
    user_id TEXT NOT NULL REFERENCES users(id),
    variant TEXT NOT NULL,
    envelope TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    PRIMARY KEY (user_id, variant)
);

CREATE TABLE IF NOT EXISTS snapshots (
    user_id TEXT PRIMARY KEY REFERENCES users(id),
    revision INTEGER NOT NULL DEFAULT 0,
    payload TEXT NOT NULL DEFAULT '',
    stats TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL
);
`

// Store is a Store (see package store) backed by a single SQLite file.
type Store struct {
	db *sql.DB
}

// Open creates or opens the database file at path and applies the schema.
// CREATE TABLE IF NOT EXISTS makes this safe to call on every startup rather
// than needing a separate migration step for a schema this small.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	// SQLite allows one writer at a time regardless of how many connections
	// ask; capping the pool at one avoids SQLITE_BUSY errors that WAL mode
	// and the busy_timeout pragma above would otherwise just paper over with
	// latency.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) CreateUser(ctx context.Context, u model.User) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, login_password_hash, created_at) VALUES (?, ?, ?, ?)`,
		u.ID, u.Email, u.LoginPasswordHash, u.CreatedAt.UTC(),
	)
	if err != nil && isUniqueViolation(err) {
		return store.ErrExists
	}
	return err
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (model.User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx,
		`SELECT id, email, login_password_hash, created_at FROM users WHERE email = ?`, email))
}

func (s *Store) GetUserByID(ctx context.Context, id string) (model.User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx,
		`SELECT id, email, login_password_hash, created_at FROM users WHERE id = ?`, id))
}

func (s *Store) UpdateLoginPasswordHash(ctx context.Context, userID, hash string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE users SET login_password_hash = ? WHERE id = ?`, hash, userID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) scanUser(row *sql.Row) (model.User, error) {
	var u model.User
	if err := row.Scan(&u.ID, &u.Email, &u.LoginPasswordHash, &u.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.User{}, store.ErrNotFound
		}
		return model.User{}, err
	}
	u.CreatedAt = u.CreatedAt.UTC()
	return u, nil
}

func (s *Store) CreateSession(ctx context.Context, sess model.Session) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, device_name, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		sess.TokenHash, sess.UserID, sess.DeviceName, sess.CreatedAt.UTC(), sess.ExpiresAt.UTC(),
	)
	return err
}

func (s *Store) GetSession(ctx context.Context, tokenHash string) (model.Session, error) {
	var sess model.Session
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash, user_id, device_name, created_at, expires_at
		 FROM sessions WHERE token_hash = ?`, tokenHash,
	).Scan(&sess.TokenHash, &sess.UserID, &sess.DeviceName, &sess.CreatedAt, &sess.ExpiresAt)

	if errors.Is(err, sql.ErrNoRows) {
		return model.Session{}, store.ErrNotFound
	}
	if err != nil {
		return model.Session{}, err
	}

	sess.CreatedAt = sess.CreatedAt.UTC()
	sess.ExpiresAt = sess.ExpiresAt.UTC()

	// Expired reads the same as absent: a caller checking "is this session
	// good" should not have to separately ask "and is it still fresh".
	if sess.ExpiresAt.Before(time.Now()) {
		return model.Session{}, store.ErrNotFound
	}

	return sess, nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *Store) PutWrappedKey(ctx context.Context, wk model.WrappedKey) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO wrapped_keys (user_id, variant, envelope, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (user_id, variant) DO UPDATE SET envelope = excluded.envelope, updated_at = excluded.updated_at
	`, wk.UserID, string(wk.Variant), wk.Envelope, wk.UpdatedAt.UTC())
	return err
}

func (s *Store) GetWrappedKeys(ctx context.Context, userID string) ([]model.WrappedKey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT user_id, variant, envelope, updated_at FROM wrapped_keys WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []model.WrappedKey
	for rows.Next() {
		var wk model.WrappedKey
		var variant string
		if err := rows.Scan(&wk.UserID, &variant, &wk.Envelope, &wk.UpdatedAt); err != nil {
			return nil, err
		}
		wk.Variant = model.WrappedKeyVariant(variant)
		wk.UpdatedAt = wk.UpdatedAt.UTC()
		out = append(out, wk)
	}
	return out, rows.Err()
}

func (s *Store) GetSnapshot(ctx context.Context, userID string) (model.Snapshot, error) {
	var snap model.Snapshot
	err := s.db.QueryRowContext(ctx, `
		SELECT user_id, revision, payload, stats, device_name, updated_at
		FROM snapshots WHERE user_id = ?
	`, userID).Scan(&snap.UserID, &snap.Revision, &snap.Payload, &snap.Stats, &snap.DeviceName, &snap.UpdatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return model.Snapshot{}, store.ErrNotFound
	}
	if err != nil {
		return model.Snapshot{}, err
	}

	snap.UpdatedAt = snap.UpdatedAt.UTC()
	return snap, nil
}

// PutSnapshot is the one place this store needs a real transaction: reading
// the current revision and writing the next one has to be atomic, or two
// devices racing to push could both read revision 4, both believe they are
// writing revision 5, and one write would silently vanish.
func (s *Store) PutSnapshot(ctx context.Context, snap model.Snapshot, baseRevision int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	var current int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM snapshots WHERE user_id = ?`, snap.UserID).Scan(&current)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		current = 0
	case err != nil:
		return err
	}

	if current != baseRevision {
		return store.ErrConflict
	}

	snap.Revision = current + 1

	_, err = tx.ExecContext(ctx, `
		INSERT INTO snapshots (user_id, revision, payload, stats, device_name, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (user_id) DO UPDATE SET
			revision = excluded.revision,
			payload = excluded.payload,
			stats = excluded.stats,
			device_name = excluded.device_name,
			updated_at = excluded.updated_at
	`, snap.UserID, snap.Revision, snap.Payload, snap.Stats, snap.DeviceName, snap.UpdatedAt.UTC())
	if err != nil {
		return err
	}

	return tx.Commit()
}

// isUniqueViolation is deliberately loose (a substring check) rather than
// typed against a driver-specific error, because modernc.org/sqlite's error
// type for this is not part of its stable API. A false negative here just
// means a UNIQUE violation surfaces as a generic error instead of
// store.ErrExists, which the caller's own validation catches anyway.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
