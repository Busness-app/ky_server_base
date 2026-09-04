package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky_server_base/internal/config"
	"github.com/Busness-app/ky_server_base/internal/crypto"
	"github.com/Busness-app/ky_server_base/internal/store"
)

// Settings keys. The token lives under its own key so a value written by an older build,
// which stored it in the clear, is never mistaken for ciphertext.
const (
	settingRecoveryURL   = "kyrecovery_url"
	settingRecoveryToken = "kyrecovery_token_enc"
	settingLastDeposit   = "kyrecovery_last_deposit"

	// recoveryTokenLabel domain-separates this ciphertext from every other value encrypted
	// under the deployment key, so a row copied here from elsewhere will not decrypt.
	recoveryTokenLabel = "ky_server_base:setting:kyrecovery_token"
)

// ErrKeyPinMissing means the instance has a pairing record but the recovery public key it
// seals to cannot be resolved: recovery.pub is gone or disagrees with the pin. Unlike
// ErrNotPaired it is a failure to report, not a quiet skip, because scheduled backups have
// stopped on an instance the operator believes is covered.
var ErrKeyPinMissing = errors.New("backup: paired with KyRecovery but the recovery public key is missing or does not match the pin")

// ErrReceiptUnrecorded means KyRecovery holds the capsule but this instance failed to write
// the receipt. The deposit happened; the caller must say so rather than report a refusal.
var ErrReceiptUnrecorded = errors.New("backup: deposit succeeded but the receipt was not recorded")

// ErrDepositInProgress answers a second deposit started while one is still uploading.
var ErrDepositInProgress = errors.New("backup: a deposit is already in progress")

// depositMu makes deposits single-flight across the scheduler, the admin route and the CLI
// within one process: two at once would upload the same data twice and race on the receipt.
var depositMu sync.Mutex

// Depositor is the deposit half of the KyRecovery client, narrowed so callers can stand in
// a fake without reaching the network.
type Depositor interface {
	Deposit(ctx context.Context, serverURL, apiToken string, container []byte) (Receipt, error)
}

// Pairing is everything a deposit needs: where to send it, the bearer token, and the key
// the container is sealed to.
type Pairing struct {
	URL   string
	Token string
	Key   RecoveryKey
}

// StorePairing records the server URL and bearer token after StoreRecoveryKey has pinned the
// key. The token is the standing credential to the service holding every historical backup,
// so it is sealed under a key derived for this setting alone: a single database disclosure
// must not hand it over.
func StorePairing(ctx context.Context, settings store.SettingsStore, encryptionKey []byte, serverURL, token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("backup: refusing to store an empty KyRecovery token")
	}
	sealed, err := crypto.EncryptAESGCM([]byte(token), crypto.DeriveKey(encryptionKey, recoveryTokenLabel))
	if err != nil {
		return fmt.Errorf("backup: failed to encrypt the KyRecovery token: %w", err)
	}
	if err := settings.SetSetting(ctx, settingRecoveryURL, serverURL); err != nil {
		return err
	}
	return settings.SetSetting(ctx, settingRecoveryToken, sealed)
}

// HasPairing reports whether a URL and a sealed token are stored, without decrypting.
func HasPairing(ctx context.Context, settings store.SettingsStore) bool {
	u, err := settings.GetSetting(ctx, settingRecoveryURL)
	if err != nil || u == "" {
		return false
	}
	t, err := settings.GetSetting(ctx, settingRecoveryToken)
	return err == nil && t != ""
}

// LoadPairing returns ErrNotPaired unless the key, URL and token are all present, and
// ErrKeyPinMissing when a pairing record exists but the key it would seal to cannot be
// resolved.
func LoadPairing(ctx context.Context, dataDir string, settings store.SettingsStore, encryptionKey []byte) (Pairing, error) {
	key, err := LoadRecoveryKey(ctx, dataDir, settings)
	if (errors.Is(err, ErrNotPaired) || errors.Is(err, ErrRecoveryKeyMismatch)) && HasPairing(ctx, settings) {
		return Pairing{}, fmt.Errorf("%w: %v", ErrKeyPinMissing, err)
	}
	if err != nil {
		return Pairing{}, err
	}
	p := Pairing{Key: key}
	if p.URL, err = settings.GetSetting(ctx, settingRecoveryURL); err != nil {
		return Pairing{}, notPaired(err)
	}
	sealed, err := settings.GetSetting(ctx, settingRecoveryToken)
	if err != nil {
		return Pairing{}, notPaired(err)
	}
	if p.URL == "" || sealed == "" {
		return Pairing{}, ErrNotPaired
	}
	plain, err := crypto.DecryptAESGCM(sealed, crypto.DeriveKey(encryptionKey, recoveryTokenLabel))
	if err != nil {
		return Pairing{}, fmt.Errorf("backup: the stored KyRecovery token will not decrypt under this deployment's encryption key: %w", err)
	}
	p.Token = string(plain)
	return p, nil
}

func notPaired(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotPaired
	}
	return err
}

// DepositBackup seals the instance's backup to the pinned key, deposits it, and records the
// receipt. The receipt is what a restore is checked against, so it is written only after
// kyrecovery has confirmed the digest of the bytes sent.
func DepositBackup(ctx context.Context, cfg *config.Config, settings store.SettingsStore, client Depositor, appVersion string) (Receipt, capsule.Manifest, error) {
	if !depositMu.TryLock() {
		return Receipt{}, capsule.Manifest{}, ErrDepositInProgress
	}
	defer depositMu.Unlock()
	pairing, err := LoadPairing(ctx, cfg.Database.DataDir, settings, cfg.Security.EncryptionKey)
	if err != nil {
		return Receipt{}, capsule.Manifest{}, err
	}
	payload, err := CollectSealable(cfg, appVersion)
	if err != nil {
		return Receipt{}, capsule.Manifest{}, err
	}
	raw, m, err := Seal(payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, pairing.Key)
	if err != nil {
		return Receipt{}, capsule.Manifest{}, err
	}
	rcpt, err := client.Deposit(ctx, pairing.URL, pairing.Token, raw)
	if err != nil {
		return Receipt{}, m, err
	}
	if rcpt.CapsuleID != m.CapsuleID {
		return Receipt{}, m, fmt.Errorf("%w: deposit receipt names capsule %s, sent %s", ErrRemote, rcpt.CapsuleID, m.CapsuleID)
	}
	b, _ := json.Marshal(rcpt)
	if err := settings.SetSetting(ctx, settingLastDeposit, string(b)); err != nil {
		return rcpt, m, fmt.Errorf("%w: %s: %w", ErrReceiptUnrecorded, rcpt.CapsuleID, err)
	}
	return rcpt, m, nil
}

// Outcome classifies a DepositBackup result for the audit log, so every caller records the
// same event for the same result. A capsule KyRecovery holds is "deposited" even when this
// side failed to write the receipt; the cause rides in the details.
func Outcome(rcpt Receipt, m capsule.Manifest, err error) (action, resource, details string) {
	switch {
	case err == nil:
		return "backup.deposited", rcpt.CapsuleID, "digest=" + rcpt.Digest
	case errors.Is(err, ErrReceiptUnrecorded):
		return "backup.deposited", rcpt.CapsuleID, AuditSafe("digest=" + rcpt.Digest + " receipt_unrecorded: " + err.Error())
	default:
		return "backup.deposit_failed", m.CapsuleID, AuditSafe(err.Error())
	}
}

// LastDeposit is the most recent receipt, or ok=false when nothing has been deposited.
func LastDeposit(ctx context.Context, settings store.SettingsStore) (Receipt, bool, error) {
	v, err := settings.GetSetting(ctx, settingLastDeposit)
	if errors.Is(err, store.ErrNotFound) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, err
	}
	var r Receipt
	if err := json.Unmarshal([]byte(v), &r); err != nil {
		return Receipt{}, false, err
	}
	return r, true, nil
}
