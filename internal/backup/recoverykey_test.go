package backup_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/Busness-app/ky-primitives/keyfile"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/ky_server_base/internal/backup"
	"github.com/Busness-app/ky_server_base/internal/store"
	"github.com/Busness-app/ky_server_base/internal/testdb"
)

func openSettings(t *testing.T) store.SettingsStore {
	t.Helper()
	st, err := store.Open(context.Background(), testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st.Settings()
}

func TestRecoveryKeyRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	settings := openSettings(t)

	priv, _ := recoverykey.Generate()
	want := backup.RecoveryKey{Public: priv.Public(), Threshold: 3, TotalShares: 5}
	if err := backup.StoreRecoveryKey(ctx, dir, settings, want); err != nil {
		t.Fatal(err)
	}
	got, err := backup.LoadRecoveryKey(ctx, dir, settings)
	if err != nil {
		t.Fatal(err)
	}
	if got.Public.ID() != want.Public.ID() || got.Threshold != 3 || got.TotalShares != 5 {
		t.Fatalf("got %+v", got)
	}
}

func TestLoadRecoveryKeyUnpaired(t *testing.T) {
	_, err := backup.LoadRecoveryKey(context.Background(), t.TempDir(), openSettings(t))
	if !errors.Is(err, backup.ErrNotPaired) {
		t.Fatalf("got %v, want ErrNotPaired", err)
	}
}

func TestStoreRecoveryKeyRefusesADifferentKey(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	settings := openSettings(t)
	a, _ := recoverykey.Generate()
	b, _ := recoverykey.Generate()
	if err := backup.StoreRecoveryKey(ctx, dir, settings, backup.RecoveryKey{Public: a.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	err := backup.StoreRecoveryKey(ctx, dir, settings, backup.RecoveryKey{Public: b.Public(), Threshold: 2, TotalShares: 3})
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second key: got %v, want fs.ErrExist", err)
	}
	// Storing the same key again is idempotent.
	if err := backup.StoreRecoveryKey(ctx, dir, settings, backup.RecoveryKey{Public: a.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatalf("same key again: %v", err)
	}
	got, _ := backup.LoadRecoveryKey(ctx, dir, settings)
	if got.Public.ID() != a.Public().ID() {
		t.Fatal("pinned key changed")
	}
}

func TestLoadRecoveryKeyDetectsSwappedFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	settings := openSettings(t)
	a, _ := recoverykey.Generate()
	b, _ := recoverykey.Generate()
	if err := backup.StoreRecoveryKey(ctx, dir, settings, backup.RecoveryKey{Public: a.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	// Someone with filesystem access swaps the public key file.
	if err := os.Remove(backup.RecoveryKeyPath(dir)); err != nil {
		t.Fatal(err)
	}
	if err := keyfile.Store(backup.RecoveryKeyPath(dir), b.Public().Bytes(), keyfile.Raw); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.LoadRecoveryKey(ctx, dir, settings); !errors.Is(err, backup.ErrRecoveryKeyMismatch) {
		t.Fatalf("got %v, want ErrRecoveryKeyMismatch", err)
	}
}
