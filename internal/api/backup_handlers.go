package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/Yoshiofthewire/ky_server_base/internal/backup"
)

func (s *Server) handleBackupDrill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 1. Build local payload
	payload, err := backup.BuildLocalPayload(s.config, "1.0.0")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to collect backup files")
		return
	}

	var files []backup.BackupFile
	for _, f := range payload.Files {
		data, err := base64.StdEncoding.DecodeString(f.DataBase64)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "Invalid backup file encoding")
			return
		}
		files = append(files, backup.BackupFile{
			Path: f.Path,
			Data: data,
			Mode: f.Mode,
		})
	}

	// 2. Encapsulate
	capsule, key, err := backup.CreateCapsule(s.config.Server.AppName, "1.0.0", files, payload.Dependencies, payload.VerificationRecipe, 2, 3)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to create backup capsule")
		return
	}

	// 3. Execute restore drill
	drillResult, err := backup.RunRestoreDrill(r.Context(), capsule, key)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to execute restore drill")
		return
	}

	s.writeJSON(w, http.StatusOK, drillResult)
}

func (s *Server) handleExportRecoveryKit(w http.ResponseWriter, r *http.Request) {
	payload, err := backup.BuildLocalPayload(s.config, "1.0.0")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to collect backup files")
		return
	}
	var files []backup.BackupFile
	for _, f := range payload.Files {
		data, err := base64.StdEncoding.DecodeString(f.DataBase64)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "Invalid backup file encoding")
			return
		}
		files = append(files, backup.BackupFile{
			Path: f.Path,
			Data: data,
			Mode: f.Mode,
		})
	}

	capsule, _, err := backup.CreateCapsule(s.config.Server.AppName, "1.0.0", files, payload.Dependencies, payload.VerificationRecipe, 2, 3)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to generate capsule for kit")
		return
	}

	html := backup.GenerateRecoveryKitHTML(capsule, s.config.Server.AppName, s.config.Server.AppURL)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
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

	token, err := s.recovery.ClaimPairing(r.Context(), req.RecoveryURL, req.PairingCode, s.config.Server.AppName)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Recovery pairing failed")
		return
	}

	if err := s.store.Settings().SetSetting(r.Context(), "kyrecovery_url", req.RecoveryURL); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to save recovery pairing")
		return
	}
	if err := s.store.Settings().SetSetting(r.Context(), "kyrecovery_token", token); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to save recovery pairing")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"paired":       true,
		"recovery_url": req.RecoveryURL,
	})
}
