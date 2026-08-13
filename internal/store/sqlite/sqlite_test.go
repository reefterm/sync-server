package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/reefterm/sync-server/internal/model"
	"github.com/reefterm/sync-server/internal/store"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// seedUser creates a user so that FK-constrained rows (sessions, wrapped
// keys, snapshots) have something valid to reference. Tests below that only
// care about those child tables use this rather than re-deriving user setup
// each time.
func seedUser(t *testing.T, st *Store, id string) {
	t.Helper()
	err := st.CreateUser(context.Background(), model.User{
		ID: id, Email: id + "@example.com", LoginPasswordHash: "hash", CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("seedUser(%q): %v", id, err)
	}
}

func TestCreateAndGetUser(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()

	u := model.User{ID: "u1", Email: "a@example.com", LoginPasswordHash: "hash", CreatedAt: time.Now()}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	byEmail, err := st.GetUserByEmail(ctx, "a@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if byEmail.ID != "u1" {
		t.Errorf("got id %q, want u1", byEmail.ID)
	}

	byID, err := st.GetUserByID(ctx, "u1")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if byID.Email != "a@example.com" {
		t.Errorf("got email %q, want a@example.com", byID.Email)
	}
}

func TestCreateUserRejectsDuplicateEmail(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()

	u := model.User{ID: "u1", Email: "dup@example.com", LoginPasswordHash: "hash", CreatedAt: time.Now()}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	u2 := model.User{ID: "u2", Email: "dup@example.com", LoginPasswordHash: "hash2", CreatedAt: time.Now()}
	err := st.CreateUser(ctx, u2)
	if !errors.Is(err, store.ErrExists) {
		t.Fatalf("got err %v, want store.ErrExists", err)
	}
}

func TestGetUserNotFound(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()

	if _, err := st.GetUserByEmail(ctx, "nobody@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got err %v, want store.ErrNotFound", err)
	}
	if _, err := st.GetUserByID(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got err %v, want store.ErrNotFound", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	seedUser(t, st, "u1")

	sess := model.Session{
		TokenHash:  "hash-of-token",
		UserID:     "u1",
		DeviceName: "laptop",
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	if err := st.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := st.GetSession(ctx, "hash-of-token")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.UserID != "u1" || got.DeviceName != "laptop" {
		t.Errorf("got %+v, want userID=u1 deviceName=laptop", got)
	}

	if err := st.DeleteSession(ctx, "hash-of-token"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := st.GetSession(ctx, "hash-of-token"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got err %v after delete, want store.ErrNotFound", err)
	}
}

func TestExpiredSessionReadsAsNotFound(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	seedUser(t, st, "u1")

	sess := model.Session{
		TokenHash: "expired-token",
		UserID:    "u1",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour), // already expired
	}
	if err := st.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if _, err := st.GetSession(ctx, "expired-token"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an expired session must read as not found, got %v", err)
	}
}

func TestWrappedKeysRoundTripAndUpsert(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	seedUser(t, st, "u1")

	wk := model.WrappedKey{UserID: "u1", Variant: model.WrappedKeyPassphrase, Envelope: `{"v":1}`, UpdatedAt: time.Now()}
	if err := st.PutWrappedKey(ctx, wk); err != nil {
		t.Fatalf("PutWrappedKey: %v", err)
	}

	keys, err := st.GetWrappedKeys(ctx, "u1")
	if err != nil {
		t.Fatalf("GetWrappedKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].Envelope != `{"v":1}` {
		t.Fatalf("got %+v, want one key with envelope {\"v\":1}", keys)
	}

	// Upsert: writing the same variant again replaces it rather than adding
	// a second row, which is exactly what a passphrase change needs.
	wk.Envelope = `{"v":2}`
	if err := st.PutWrappedKey(ctx, wk); err != nil {
		t.Fatalf("PutWrappedKey (update): %v", err)
	}

	keys, err = st.GetWrappedKeys(ctx, "u1")
	if err != nil {
		t.Fatalf("GetWrappedKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].Envelope != `{"v":2}` {
		t.Fatalf("got %+v, want one key with envelope {\"v\":2} after upsert", keys)
	}
}

func TestSnapshotFirstPushRequiresBaseRevisionZero(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	seedUser(t, st, "u1")

	snap := model.Snapshot{UserID: "u1", Payload: `{"hosts":[]}`, Stats: `{}`, DeviceName: "laptop", UpdatedAt: time.Now()}

	if err := st.PutSnapshot(ctx, snap, 5); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a first push with a nonzero base revision must conflict, got %v", err)
	}

	if err := st.PutSnapshot(ctx, snap, 0); err != nil {
		t.Fatalf("a first push with base revision 0 must succeed: %v", err)
	}

	got, err := st.GetSnapshot(ctx, "u1")
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	if got.Revision != 1 {
		t.Errorf("got revision %d, want 1 after the first push", got.Revision)
	}
}

func TestSnapshotConflictOnStaleBaseRevision(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	seedUser(t, st, "u1")

	snap := model.Snapshot{UserID: "u1", Payload: `{"hosts":[]}`, UpdatedAt: time.Now()}
	if err := st.PutSnapshot(ctx, snap, 0); err != nil {
		t.Fatalf("first push: %v", err)
	}

	// Device A pushes again correctly, moving the revision to 2.
	if err := st.PutSnapshot(ctx, snap, 1); err != nil {
		t.Fatalf("second push: %v", err)
	}

	// Device B, still holding revision 1, tries to push and must conflict.
	err := st.PutSnapshot(ctx, snap, 1)
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a stale base revision must conflict, got %v", err)
	}

	// The conflict must not have corrupted the stored revision.
	got, err := st.GetSnapshot(ctx, "u1")
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	if got.Revision != 2 {
		t.Errorf("got revision %d after a rejected conflicting push, want 2 (unchanged)", got.Revision)
	}
}

func TestGetSnapshotNotFoundForFreshUser(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()

	if _, err := st.GetSnapshot(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got err %v, want store.ErrNotFound for a user who never pushed a snapshot", err)
	}
}
