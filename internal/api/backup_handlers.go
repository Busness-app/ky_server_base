package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"

	"github.com/Busness-app/ky_server_base/internal/backup"
)

// errRecoveryKeyMismatch answers a swapped recovery.pub: the pin in the database and the key
// on disk disagree, so refuse rather than seal a capsule nobody's custodians can open.
const errRecoveryKeyMismatch = "Recovery key file does not match the pinned key ID; refusing to seal"

// collectFiles is what both the drill and the export seal: the same payload the deposit path
// will send, decoded from BuildLocalPayload's transport form.
func (s *Server) collectFiles() (*backup.PushBackupPayload, []backup.BackupFile, error) {
	payload, err := backup.BuildLocalPayload(s.config, "1.0.0")
	if err != nil {
		return nil, nil, err
	}
	files := make([]backup.BackupFile, 0, len(payload.Files))
	for _, f := range payload.Files {
		data, err := base64.StdEncoding.DecodeString(f.DataBase64)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, backup.BackupFile{Path: f.Path, Data: data, Mode: f.Mode})
	}
	return payload, files, nil
}

func (s *Server) handleBackupDrill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	payload, files, err := s.collectFiles()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to collect backup files")
		return
	}
	pinned, err := backup.LoadRecoveryKey(r.Context(), s.config.Database.DataDir, s.store.Settings())
	if errors.Is(err, backup.ErrRecoveryKeyMismatch) {
		s.writeError(w, http.StatusConflict, errRecoveryKeyMismatch)
		return
	}
	if err != nil && !errors.Is(err, backup.ErrNotPaired) {
		s.writeError(w, http.StatusInternalServerError, "Failed to load recovery key")
		return
	}
	result, err := backup.RunRestoreDrill(r.Context(), s.config.Server.AppName, "1.0.0", files, payload.Dependencies, payload.VerificationRecipe, pinned)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to execute restore drill")
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

// handleExportCapsule hands the operator the sealed capsule itself. Only the custodians'
// shares open it, so the download is safe to store anywhere; kyrecovery is where it belongs.
func (s *Server) handleExportCapsule(w http.ResponseWriter, r *http.Request) {
	payload, files, err := s.collectFiles()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to collect backup files")
		return
	}
	key, err := backup.LoadRecoveryKey(r.Context(), s.config.Database.DataDir, s.store.Settings())
	if errors.Is(err, backup.ErrNotPaired) {
		s.writeError(w, http.StatusPreconditionFailed, "Not paired with KyRecovery; no recovery key to seal to")
		return
	}
	if errors.Is(err, backup.ErrRecoveryKeyMismatch) {
		s.writeError(w, http.StatusConflict, errRecoveryKeyMismatch)
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load recovery key")
		return
	}
	raw, m, err := backup.Seal(s.config.Server.AppName, "1.0.0", files, payload.Dependencies, payload.VerificationRecipe, key)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to seal capsule")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.kycap"`, backup.FilenameSafe(m.CapsuleID)))
	w.Header().Set("X-Recovery-Key-ID", m.RecoveryKeyID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

type RemotePairRequest struct {
	RecoveryURL string `json:"recovery_url"`
	PairingCode string `json:"pairing_code"`
}

func (s *Server) handlePairRemoteRecovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req RemotePairRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	result, err := s.recovery.ClaimPairing(r.Context(), req.RecoveryURL, req.PairingCode, s.config.Server.AppName)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Recovery pairing failed")
		return
	}

	if err := backup.StoreRecoveryKey(r.Context(), s.config.Database.DataDir, s.store.Settings(), result.Key); err != nil {
		if errors.Is(err, fs.ErrExist) {
			s.writeError(w, http.StatusConflict, "Already paired to a different recovery key")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to save recovery key")
		return
	}
	if err := s.store.Settings().SetSetting(r.Context(), "kyrecovery_url", req.RecoveryURL); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to save recovery pairing")
		return
	}
	if err := s.store.Settings().SetSetting(r.Context(), "kyrecovery_token", result.APIToken); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to save recovery pairing")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"paired":          true,
		"recovery_url":    req.RecoveryURL,
		"recovery_key_id": result.Key.Public.ID(),
		"threshold":       result.Key.Threshold,
		"total_shares":    result.Key.TotalShares,
	})
}
