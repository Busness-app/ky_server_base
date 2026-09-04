package backup_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
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

// A swapped file must not become the pinned key just because a peer hands back the same swap.
func TestStoreRecoveryKeyRefusesARePairToASwappedFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	settings := openSettings(t)
	a, _ := recoverykey.Generate()
	b, _ := recoverykey.Generate()
	if err := backup.StoreRecoveryKey(ctx, dir, settings, backup.RecoveryKey{Public: a.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	// Attacker has the data directory but not the database.
	if err := os.Remove(backup.RecoveryKeyPath(dir)); err != nil {
		t.Fatal(err)
	}
	if err := keyfile.Store(backup.RecoveryKeyPath(dir), b.Public().Bytes(), keyfile.Raw); err != nil {
		t.Fatal(err)
	}
	// ...and now serves a claim for the same key B they planted.
	err := backup.StoreRecoveryKey(ctx, dir, settings, backup.RecoveryKey{Public: b.Public(), Threshold: 2, TotalShares: 3})
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("re-pair to the planted key: got %v, want fs.ErrExist", err)
	}
	pinned, err := settings.GetSetting(ctx, "kyrecovery_key_id")
	if err != nil {
		t.Fatal(err)
	}
	if pinned != a.Public().ID() {
		t.Fatalf("pin moved to %s, want %s", pinned, a.Public().ID())
	}
}

// Deleting recovery.pub is easier than swapping it, and a restored instance starts that way:
// the pin is in the database, the file is not on disk. A re-pair to a different key must still
// be refused, because the pin is what decides.
func TestStoreRecoveryKeyRefusesADifferentKeyWithNoFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	settings := openSettings(t)
	a, _ := recoverykey.Generate()
	b, _ := recoverykey.Generate()
	if err := backup.StoreRecoveryKey(ctx, dir, settings, backup.RecoveryKey{Public: a.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(backup.RecoveryKeyPath(dir)); err != nil {
		t.Fatal(err)
	}
	err := backup.StoreRecoveryKey(ctx, dir, settings, backup.RecoveryKey{Public: b.Public(), Threshold: 2, TotalShares: 3})
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("re-pair with no key file: got %v, want fs.ErrExist", err)
	}
	pinned, err := settings.GetSetting(ctx, "kyrecovery_key_id")
	if err != nil {
		t.Fatal(err)
	}
	if pinned != a.Public().ID() {
		t.Fatalf("pin moved to %s, want %s", pinned, a.Public().ID())
	}
	if _, err := os.Stat(backup.RecoveryKeyPath(dir)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused re-pair wrote a key file: %v", err)
	}
}

// The same key with the file missing is the self-healing path a restore needs: it comes back.
func TestStoreRecoveryKeyRecreatesAMissingFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	settings := openSettings(t)
	a, _ := recoverykey.Generate()
	k := backup.RecoveryKey{Public: a.Public(), Threshold: 2, TotalShares: 3}
	if err := backup.StoreRecoveryKey(ctx, dir, settings, k); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(backup.RecoveryKeyPath(dir)); err != nil {
		t.Fatal(err)
	}
	if err := backup.StoreRecoveryKey(ctx, dir, settings, k); err != nil {
		t.Fatalf("same key with no file: %v", err)
	}
	got, err := backup.LoadRecoveryKey(ctx, dir, settings)
	if err != nil {
		t.Fatalf("load after self-heal: %v", err)
	}
	if got.Public.ID() != a.Public().ID() {
		t.Fatalf("recreated file holds %s, want %s", got.Public.ID(), a.Public().ID())
	}
}

// A pairing that died between writing the key ID and the topology is not a pairing.
func TestLoadRecoveryKeyPartialPinIsUnpaired(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	settings := openSettings(t)
	a, _ := recoverykey.Generate()
	if err := keyfile.Store(backup.RecoveryKeyPath(dir), a.Public().Bytes(), keyfile.Raw); err != nil {
		t.Fatal(err)
	}
	if err := settings.SetSetting(ctx, "kyrecovery_key_id", a.Public().ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.LoadRecoveryKey(ctx, dir, settings); !errors.Is(err, backup.ErrNotPaired) {
		t.Fatalf("got %v, want ErrNotPaired", err)
	}
}

type claimTransport struct{ body string }

func (c claimTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Header:     http.Header{},
	}, nil
}

// A claim without a usable custodian topology is not a completed pairing, so the client
// refuses it rather than handing the handler a result that only fails when it is stored.
func TestClaimPairingRequiresATopology(t *testing.T) {
	priv, _ := recoverykey.Generate()
	pub := base64.StdEncoding.EncodeToString(priv.Public().Bytes())

	body := func(threshold, total int) string {
		return fmt.Sprintf(`{"api_token":"tok","recovery_public_key":%q,"threshold":%d,"total_shares":%d}`, pub, threshold, total)
	}

	client := backup.NewClientWithTransportForTest(claimTransport{body: body(2, 3)})
	got, err := client.ClaimPairing(context.Background(), "https://recovery.busnes.app", "123456", "svc", "app")
	if err != nil {
		t.Fatalf("valid claim: %v", err)
	}
	if got.Key.Threshold != 2 || got.Key.TotalShares != 3 || got.Key.Public.ID() != priv.Public().ID() {
		t.Fatalf("valid claim: got %+v", got)
	}

	for _, tc := range []struct{ threshold, total int }{{0, 0}, {0, 3}, {1, 3}, {4, 3}} {
		client := backup.NewClientWithTransportForTest(claimTransport{body: body(tc.threshold, tc.total)})
		if _, err := client.ClaimPairing(context.Background(), "https://recovery.busnes.app", "123456", "svc", "app"); err == nil {
			t.Errorf("%d-of-%d: claim accepted, want an error", tc.threshold, tc.total)
		}
	}
}
