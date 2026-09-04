package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky_server_base/internal/backup"
	"github.com/Busness-app/ky_server_base/internal/store"
)

// appVersion is what the capsule manifest records for this build.
const appVersion = "1.0.0"

// errRecoveryKeyMismatch answers a swapped recovery.pub: the pin in the database and the key
// on disk disagree, so refuse rather than seal a capsule nobody's custodians can open.
const errRecoveryKeyMismatch = "Recovery key file does not match the pinned key ID; refusing to seal"

func (s *Server) handleBackupDrill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	payload, err := backup.CollectSealable(s.config, appVersion)
	if errors.Is(err, backup.ErrNoDatabaseSnapshot) {
		// An honest failed drill, not a 500: the operator needs to read why no backup exists.
		s.writeJSON(w, http.StatusOK, &backup.DrillResult{Passed: false, ErrorMessage: err.Error(),
			Checks: []backup.CheckItem{{Name: "Database", Passed: false, Message: err.Error()}}})
		return
	}
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
	result, err := backup.RunRestoreDrill(r.Context(), payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, pinned)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to execute restore drill")
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

// handleExportCapsule hands the operator the sealed capsule itself. Only the custodians'
// shares open it, so the download is safe to store anywhere; kyrecovery is where it belongs.
func (s *Server) handleExportCapsule(w http.ResponseWriter, r *http.Request) {
	payload, err := backup.CollectSealable(s.config, appVersion)
	if errors.Is(err, backup.ErrNoDatabaseSnapshot) {
		s.writeError(w, http.StatusPreconditionFailed, err.Error())
		return
	}
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
	raw, m, err := backup.Seal(payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, key)
	if err != nil {
		// Logged because writeError only reaches the browser: without this an export that has
		// outgrown the capsule limits is a bare 500 with nothing anywhere naming the cause.
		// capsule's errors carry member paths and sizes, never key material or content.
		log.Printf("[BACKUP] export capsule: seal failed: %v", err)
		if errors.Is(err, capsule.ErrCapsuleTooLarge) {
			s.writeError(w, http.StatusRequestEntityTooLarge, backup.TooLargeMessage)
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to seal capsule")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.kycap"`, backup.FilenameSafe(m.CapsuleID)))
	w.Header().Set("X-Recovery-Key-ID", m.RecoveryKeyID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// depositWriteBudget is how long the admin's connection may stay open for the receipt: the
// upload budget plus room for sealing. The listener's WriteTimeout is sized for JSON replies.
const depositWriteBudget = 16 * time.Minute

// handleDepositBackup seals a capsule and deposits it with KyRecovery now, outside the
// schedule. The receipt it returns is what a restore is later checked against.
//
// The deposit runs on a context that outlives the request: once bytes are on their way, a
// browser closing the tab must not leave KyRecovery holding a capsule this instance has no
// receipt for.
func (s *Server) handleDepositBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(depositWriteBudget))
	// The acting admin is resolved while the request is still live; the audit row is written
	// on the same detached context as the deposit, so a dropped connection cannot decide
	// whether the row exists.
	actor := s.actorID(r)
	ctx := context.WithoutCancel(r.Context())
	rcpt, m, err := backup.DepositBackup(ctx, s.config, s.store.Settings(), s.recovery, appVersion)
	if errors.Is(err, backup.ErrReceiptUnrecorded) {
		// The store has the capsule; only this side's record is missing. Say that, and audit it
		// as a deposit, so nobody re-sends a capsule that already exists.
		s.auditBackup(ctx, actor, r, "backup.deposited", rcpt.CapsuleID, "digest="+rcpt.Digest+" receipt_unrecorded")
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Capsule %s was deposited but the receipt could not be recorded locally", rcpt.CapsuleID))
		return
	}
	if err != nil {
		s.auditBackup(ctx, actor, r, "backup.deposit_failed", m.CapsuleID, err.Error())
		switch {
		case errors.Is(err, backup.ErrNotPaired):
			s.writeError(w, http.StatusPreconditionFailed, "Not paired with KyRecovery")
		case errors.Is(err, backup.ErrNoDatabaseSnapshot):
			s.writeError(w, http.StatusPreconditionFailed, err.Error())
		case errors.Is(err, backup.ErrDepositInProgress):
			s.writeError(w, http.StatusConflict, "A deposit is already in progress")
		case errors.Is(err, backup.ErrRecoveryKeyMismatch):
			s.writeError(w, http.StatusConflict, errRecoveryKeyMismatch)
		case errors.Is(err, capsule.ErrCapsuleTooLarge):
			s.writeError(w, http.StatusRequestEntityTooLarge, backup.TooLargeMessage)
		case errors.Is(err, backup.ErrRemote):
			// The cause is audited; the browser gets only that the store did not take it.
			log.Printf("[BACKUP] deposit failed: %s", backup.AuditSafe(err.Error()))
			s.writeError(w, http.StatusBadGateway, "KyRecovery did not accept the deposit")
		default:
			log.Printf("[BACKUP] deposit: seal failed: %s", backup.AuditSafe(err.Error()))
			s.writeError(w, http.StatusInternalServerError, "Failed to seal capsule")
		}
		return
	}
	s.auditBackup(ctx, actor, r, "backup.deposited", rcpt.CapsuleID, "digest="+rcpt.Digest)
	s.writeJSON(w, http.StatusOK, rcpt)
}

// auditBackup records a backup event against the acting admin. Details never carry the
// token or capsule bytes, and both text fields are bounded and printable before they are
// stored: a resource may be an operator-typed URL and details may quote a remote body.
func (s *Server) auditBackup(ctx context.Context, userID string, r *http.Request, action, resource, details string) {
	resource, details = backup.AuditSafe(resource), backup.AuditSafe(details)
	if err := s.store.Audit().LogAudit(ctx, &store.AuditRecord{
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		Details:   details,
		IPAddress: s.requestIP(r),
	}); err != nil {
		log.Printf("[BACKUP] audit %s for %s not recorded: %v", action, resource, err)
	}
}

// actorID is the session user behind an admin request, resolved while the request is live.
func (s *Server) actorID(r *http.Request) string {
	user, _, err := s.sessions.AuthenticateRequest(r)
	if err != nil {
		return ""
	}
	return user.ID
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

	// The service name sent here is what kyrecovery pins for the token and what every
	// capsule's manifest is checked against, so it is the same AppName the collectors seal under.
	result, err := s.recovery.ClaimPairing(r.Context(), req.RecoveryURL, req.PairingCode, s.config.Server.AppName, s.config.Server.AppName)
	if err != nil {
		s.auditBackup(r.Context(), s.actorID(r), r, "backup.pair_failed", req.RecoveryURL, err.Error())
		s.writeError(w, http.StatusBadRequest, "Recovery pairing failed")
		return
	}

	if err := backup.StoreRecoveryKey(r.Context(), s.config.Database.DataDir, s.store.Settings(), result.Key); err != nil {
		if errors.Is(err, fs.ErrExist) {
			s.auditBackup(r.Context(), s.actorID(r), r, "backup.pair_failed", req.RecoveryURL, "already paired to a different recovery key")
			s.writeError(w, http.StatusConflict, "Already paired to a different recovery key")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to save recovery key")
		return
	}
	if err := backup.StorePairing(r.Context(), s.store.Settings(), req.RecoveryURL, result.APIToken); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to save recovery pairing")
		return
	}
	s.auditBackup(r.Context(), s.actorID(r), r, "backup.paired", req.RecoveryURL, "recovery_key_id="+result.Key.Public.ID())

	s.writeJSON(w, http.StatusOK, map[string]any{
		"paired":          true,
		"recovery_url":    req.RecoveryURL,
		"recovery_key_id": result.Key.Public.ID(),
		"threshold":       result.Key.Threshold,
		"total_shares":    result.Key.TotalShares,
	})
}
