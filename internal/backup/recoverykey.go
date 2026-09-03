package backup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"

	"github.com/Busness-app/ky-primitives/keyfile"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/ky_server_base/internal/store"
)

var (
	ErrNotPaired           = errors.New("backup: no recovery public key; pair with KyRecovery first")
	ErrRecoveryKeyMismatch = errors.New("backup: stored recovery public key does not match the pinned key ID")
)

const (
	settingRecoveryKeyID  = "kyrecovery_key_id"
	settingThreshold      = "kyrecovery_threshold"
	settingTotalShares    = "kyrecovery_total_shares"
	recoveryPublicKeyFile = "recovery.pub"
)

// RecoveryKey is what a product holds after pairing: the suite recovery public key and the
// custodian topology kyrecovery reported for it. There is no private half here, ever.
type RecoveryKey struct {
	Public      recoverykey.PublicKey
	Threshold   int
	TotalShares int
}

// RecoveryKeyPath is where the raw 1216-byte public key lives.
func RecoveryKeyPath(dataDir string) string {
	return filepath.Join(dataDir, recoveryPublicKeyFile)
}

// StoreRecoveryKey persists k. keyfile.Store refuses to replace an existing file, so a
// second pairing to a different key fails with fs.ErrExist; the same key again is a no-op.
func StoreRecoveryKey(ctx context.Context, dataDir string, settings store.SettingsStore, k RecoveryKey) error {
	if k.Public.IsZero() {
		return errors.New("backup: refusing to store a zero recovery public key")
	}
	if k.Threshold < 2 || k.TotalShares < k.Threshold || k.TotalShares > 255 {
		return fmt.Errorf("backup: %d-of-%d is not a custodian topology", k.Threshold, k.TotalShares)
	}
	path := RecoveryKeyPath(dataDir)
	err := keyfile.Store(path, k.Public.Bytes(), keyfile.Raw)
	if errors.Is(err, fs.ErrExist) {
		existing, lerr := keyfile.LoadEncoded(path, recoverykey.PublicKeyBytes, keyfile.Raw)
		if lerr != nil {
			return lerr
		}
		if pk, perr := recoverykey.ParsePublicKey(existing); perr != nil || pk.ID() != k.Public.ID() {
			return fmt.Errorf("%w: already paired to recovery key %s; remove %s to re-pair", err, pinnedID(existing), path)
		}
		// Same key: fall through and refresh the settings.
	} else if err != nil {
		return err
	}
	if err := settings.SetSetting(ctx, settingRecoveryKeyID, k.Public.ID()); err != nil {
		return err
	}
	if err := settings.SetSetting(ctx, settingThreshold, strconv.Itoa(k.Threshold)); err != nil {
		return err
	}
	return settings.SetSetting(ctx, settingTotalShares, strconv.Itoa(k.TotalShares))
}

func pinnedID(raw []byte) string {
	pk, err := recoverykey.ParsePublicKey(raw)
	if err != nil {
		return "(unparseable)"
	}
	return pk.ID()
}

// LoadRecoveryKey reads the public key file and checks it against the pinned key ID in the
// settings table, so a swapped file is detected before anything is sealed to it.
func LoadRecoveryKey(ctx context.Context, dataDir string, settings store.SettingsStore) (RecoveryKey, error) {
	raw, err := keyfile.LoadEncoded(RecoveryKeyPath(dataDir), recoverykey.PublicKeyBytes, keyfile.Raw)
	if errors.Is(err, fs.ErrNotExist) {
		return RecoveryKey{}, ErrNotPaired
	}
	if err != nil {
		return RecoveryKey{}, err
	}
	pk, err := recoverykey.ParsePublicKey(raw)
	if err != nil {
		return RecoveryKey{}, err
	}
	id, err := settings.GetSetting(ctx, settingRecoveryKeyID)
	if errors.Is(err, store.ErrNotFound) {
		return RecoveryKey{}, ErrNotPaired
	}
	if err != nil {
		return RecoveryKey{}, err
	}
	if id != pk.ID() {
		return RecoveryKey{}, ErrRecoveryKeyMismatch
	}
	k := RecoveryKey{Public: pk}
	if k.Threshold, err = intSetting(ctx, settings, settingThreshold); err != nil {
		return RecoveryKey{}, err
	}
	if k.TotalShares, err = intSetting(ctx, settings, settingTotalShares); err != nil {
		return RecoveryKey{}, err
	}
	return k, nil
}

func intSetting(ctx context.Context, settings store.SettingsStore, key string) (int, error) {
	v, err := settings.GetSetting(ctx, key)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return strconv.Atoi(v)
}
