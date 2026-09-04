package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky_server_base/internal/config"
	"github.com/Busness-app/ky_server_base/internal/store"
)

const (
	settingRecoveryURL   = "kyrecovery_url"
	settingRecoveryToken = "kyrecovery_token"
	settingLastDeposit   = "kyrecovery_last_deposit"
)

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
// key, so a pairing with a key but no token reads as not paired rather than half paired.
func StorePairing(ctx context.Context, settings store.SettingsStore, serverURL, token string) error {
	if err := settings.SetSetting(ctx, settingRecoveryURL, serverURL); err != nil {
		return err
	}
	return settings.SetSetting(ctx, settingRecoveryToken, token)
}

// LoadPairing returns ErrNotPaired unless the key, URL and token are all present.
func LoadPairing(ctx context.Context, dataDir string, settings store.SettingsStore) (Pairing, error) {
	key, err := LoadRecoveryKey(ctx, dataDir, settings)
	if err != nil {
		return Pairing{}, err
	}
	p := Pairing{Key: key}
	if p.URL, err = settings.GetSetting(ctx, settingRecoveryURL); err != nil {
		return Pairing{}, notPaired(err)
	}
	if p.Token, err = settings.GetSetting(ctx, settingRecoveryToken); err != nil {
		return Pairing{}, notPaired(err)
	}
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
	pairing, err := LoadPairing(ctx, cfg.Database.DataDir, settings)
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
