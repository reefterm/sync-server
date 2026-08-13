package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/reefterm/sync-server/internal/model"
	"github.com/reefterm/sync-server/internal/store"
)

/* ------------------------------------------------------------------ *
 * Wrapped keys
 *
 * Both envelopes wrap the same Sync Master Key, sealed independently: one
 * under a KEK derived from the user's passphrase, one under a KEK derived
 * from their recovery code. This server stores and returns them verbatim
 * and has no way to open either.
 * ------------------------------------------------------------------ */

type syncKeysResponse struct {
	WrappedKeyPassphrase json.RawMessage `json:"wrapped_key_passphrase,omitempty"`
	WrappedKeyRecovery   json.RawMessage `json:"wrapped_key_recovery,omitempty"`
}

func (s *Server) handleGetSyncKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.GetWrappedKeys(r.Context(), userID(r))
	if err != nil {
		s.log.Error("get wrapped keys", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read your account key")
		return
	}

	var resp syncKeysResponse
	for _, k := range keys {
		switch k.Variant {
		case model.WrappedKeyPassphrase:
			resp.WrappedKeyPassphrase = json.RawMessage(k.Envelope)
		case model.WrappedKeyRecovery:
			resp.WrappedKeyRecovery = json.RawMessage(k.Envelope)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

type putWrappedKeyRequest struct {
	Envelope json.RawMessage `json:"envelope"`
}

// handlePutSyncKeyPassphrase re-wraps the Sync Master Key under a new
// passphrase, e.g. after the user changes it. The recovery envelope is a
// separate row and is untouched -- the two unlock paths are independent by
// design, so changing one never invalidates the other.
func (s *Server) handlePutSyncKeyPassphrase(w http.ResponseWriter, r *http.Request) {
	s.putWrappedKey(w, r, model.WrappedKeyPassphrase)
}

// handlePutSyncKeyRecovery replaces the recovery envelope, used both to set
// it up and to rotate it after a redemption.
func (s *Server) handlePutSyncKeyRecovery(w http.ResponseWriter, r *http.Request) {
	s.putWrappedKey(w, r, model.WrappedKeyRecovery)
}

func (s *Server) putWrappedKey(w http.ResponseWriter, r *http.Request, variant model.WrappedKeyVariant) {
	var req putWrappedKeyRequest
	if err := decodeJSON(r, &req); err != nil || len(req.Envelope) == 0 {
		writeError(w, http.StatusBadRequest, "a wrapped key envelope is required")
		return
	}

	wk := model.WrappedKey{
		UserID:    userID(r),
		Variant:   variant,
		Envelope:  string(req.Envelope),
		UpdatedAt: time.Now(),
	}

	if err := s.store.PutWrappedKey(r.Context(), wk); err != nil {
		s.log.Error("put wrapped key", "variant", variant, "error", err)
		writeError(w, http.StatusInternalServerError, "could not save your account key")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

/* ------------------------------------------------------------------ *
 * Snapshot
 * ------------------------------------------------------------------ */

type snapshotMetaResponse struct {
	Exists    bool       `json:"exists"`
	Revision  int64      `json:"revision"`
	SizeBytes int        `json:"size_bytes"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

func (s *Server) handleSnapshotMeta(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.GetSnapshot(r.Context(), userID(r))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, snapshotMetaResponse{Exists: false})
		return
	}
	if err != nil {
		s.log.Error("get snapshot meta", "error", err)
		writeError(w, http.StatusInternalServerError, "could not check your saved setup")
		return
	}

	updatedAt := snap.UpdatedAt
	writeJSON(w, http.StatusOK, snapshotMetaResponse{
		Exists:    true,
		Revision:  snap.Revision,
		SizeBytes: len(snap.Payload),
		UpdatedAt: &updatedAt,
	})
}

type snapshotResponse struct {
	Payload  json.RawMessage `json:"payload"`
	Revision int64           `json:"revision"`
}

func (s *Server) handleSnapshotGet(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.GetSnapshot(r.Context(), userID(r))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "nothing saved yet")
		return
	}
	if err != nil {
		s.log.Error("get snapshot", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load your saved setup")
		return
	}

	writeJSON(w, http.StatusOK, snapshotResponse{
		Payload:  json.RawMessage(snap.Payload),
		Revision: snap.Revision,
	})
}

type putSnapshotRequest struct {
	Payload      json.RawMessage `json:"payload"`
	BaseRevision int64           `json:"base_revision"`
	DeviceName   string          `json:"device_name"`
	// Stats is plaintext counts alongside the encrypted payload -- host
	// count, key count and so on -- so an operator can confirm the feature
	// is working without ever decrypting a snapshot to find out. It
	// deliberately carries nothing that describes a user's actual
	// infrastructure.
	Stats json.RawMessage `json:"stats"`
}

type putSnapshotResponse struct {
	Revision int64 `json:"revision"`
}

type conflictResponse struct {
	Error struct {
		Message  string `json:"message"`
		Revision int64  `json:"revision"`
	} `json:"error"`
}

// handleSnapshotPut writes only if BaseRevision matches what's currently
// stored, and answers 409 with the winning revision otherwise. The client's
// job on a 409 is to pull, merge and retry once -- this handler's job is
// only to make the check-and-write atomic, which it delegates entirely to
// store.PutSnapshot.
func (s *Server) handleSnapshotPut(w http.ResponseWriter, r *http.Request) {
	var req putSnapshotRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if len(req.Payload) == 0 {
		writeError(w, http.StatusBadRequest, "a payload is required")
		return
	}

	snap := model.Snapshot{
		UserID:     userID(r),
		Payload:    string(req.Payload),
		Stats:      string(req.Stats),
		DeviceName: req.DeviceName,
		UpdatedAt:  time.Now(),
	}

	err := s.store.PutSnapshot(r.Context(), snap, req.BaseRevision)
	if errors.Is(err, store.ErrConflict) {
		current, getErr := s.store.GetSnapshot(r.Context(), userID(r))
		var resp conflictResponse
		resp.Error.Message = "another device saved first"
		if getErr == nil {
			resp.Error.Revision = current.Revision
		}
		writeJSON(w, http.StatusConflict, resp)
		return
	}
	if err != nil {
		s.log.Error("put snapshot", "error", err)
		writeError(w, http.StatusInternalServerError, "could not save your setup")
		return
	}

	writeJSON(w, http.StatusOK, putSnapshotResponse{Revision: req.BaseRevision + 1})
}
