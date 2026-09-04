package backup_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/ky_server_base/internal/backup"
	"github.com/Busness-app/ky_server_base/internal/config"
	"github.com/Busness-app/ky_server_base/internal/store"
)

// fakeStore is kyrecovery's side of a deposit: it records what arrived and answers with the
// receipt the real server would, so the private half can open what was sent.
type fakeStore struct {
	url, token string
	container  []byte
	err        error
	calls      int
}

func (f *fakeStore) Deposit(_ context.Context, serverURL, apiToken string, container []byte) (backup.Receipt, error) {
	f.calls++
	f.url, f.token, f.container = serverURL, apiToken, container
	if f.err != nil {
		return backup.Receipt{}, f.err
	}
	m, err := capsule.ReadUnverifiedManifest(container)
	if err != nil {
		return backup.Receipt{}, err
	}
	sum := sha256.Sum256(container)
	return backup.Receipt{CapsuleID: m.CapsuleID, Digest: hex.EncodeToString(sum[:]), SizeBytes: int64(len(container)), DepositedAt: time.Now().UTC()}, nil
}

func depositConfig(t *testing.T) (*config.Config, store.Store) {
	t.Helper()
	return sqliteInstance(t)
}

func pair(t *testing.T, cfg *config.Config, st store.Store) recoverykey.PrivateKey {
	t.Helper()
	ctx := context.Background()
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.StoreRecoveryKey(ctx, cfg.Database.DataDir, st.Settings(), backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	if err := backup.StorePairing(ctx, st.Settings(), "https://recovery.busnes.app", "kyrec_live_t"); err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestDepositBackupSealsToThePinnedKeyAndRecordsTheReceipt(t *testing.T) {
	cfg, st := depositConfig(t)
	priv := pair(t, cfg, st)
	ctx := context.Background()
	fake := &fakeStore{}

	rcpt, m, err := backup.DepositBackup(ctx, cfg, st.Settings(), fake, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if fake.url != "https://recovery.busnes.app" || fake.token != "kyrec_live_t" {
		t.Errorf("sent to %s with %s", fake.url, fake.token)
	}
	if m.ServiceName != "busnes_app" || m.RecoveryKeyID != priv.Public().ID() || rcpt.CapsuleID != m.CapsuleID {
		t.Errorf("manifest %+v, receipt %+v", m, rcpt)
	}

	// What kyrecovery holds opens with the private half and carries the encryption key.
	target := t.TempDir()
	if _, files, err := capsule.Open(fake.container, priv, target); err != nil {
		t.Fatal(err)
	} else if len(files) == 0 {
		t.Fatal("empty capsule")
	}

	last, ok, err := backup.LastDeposit(ctx, st.Settings())
	if err != nil || !ok {
		t.Fatalf("last deposit: %v %v", ok, err)
	}
	if last.CapsuleID != rcpt.CapsuleID || last.Digest != rcpt.Digest {
		t.Errorf("recorded %+v, want %+v", last, rcpt)
	}
}

func TestDepositBackupRequiresAFullPairing(t *testing.T) {
	cfg, st := depositConfig(t)
	ctx := context.Background()
	fake := &fakeStore{}
	if _, _, err := backup.DepositBackup(ctx, cfg, st.Settings(), fake, "1.0.0"); !errors.Is(err, backup.ErrNotPaired) {
		t.Fatalf("unpaired: got %v, want ErrNotPaired", err)
	}
	// A key without a token is a pairing that died halfway.
	priv, _ := recoverykey.Generate()
	if err := backup.StoreRecoveryKey(ctx, cfg.Database.DataDir, st.Settings(), backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := backup.DepositBackup(ctx, cfg, st.Settings(), fake, "1.0.0"); !errors.Is(err, backup.ErrNotPaired) {
		t.Fatalf("key only: got %v, want ErrNotPaired", err)
	}
	if fake.calls != 0 {
		t.Errorf("deposit attempted %d times without a pairing", fake.calls)
	}
}

func TestAFailedDepositLeavesNoReceipt(t *testing.T) {
	cfg, st := depositConfig(t)
	pair(t, cfg, st)
	ctx := context.Background()
	fake := &fakeStore{err: errors.New("deposit rejected (503): no free slot")}
	if _, _, err := backup.DepositBackup(ctx, cfg, st.Settings(), fake, "1.0.0"); err == nil {
		t.Fatal("refusal swallowed")
	}
	if _, ok, _ := backup.LastDeposit(ctx, st.Settings()); ok {
		t.Error("a refused deposit was recorded as the last deposit")
	}
}

// blockingStore holds the deposit open until released, so a second caller can be observed.
type blockingStore struct {
	fakeStore
	started chan struct{}
	release chan struct{}
}

func (b *blockingStore) Deposit(ctx context.Context, url, token string, container []byte) (backup.Receipt, error) {
	close(b.started)
	<-b.release
	return b.fakeStore.Deposit(ctx, url, token, container)
}

func TestDepositsAreSingleFlight(t *testing.T) {
	cfg, st := depositConfig(t)
	pair(t, cfg, st)
	ctx := context.Background()
	slow := &blockingStore{started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, _, err := backup.DepositBackup(ctx, cfg, st.Settings(), slow, "1.0.0")
		done <- err
	}()
	<-slow.started
	if _, _, err := backup.DepositBackup(ctx, cfg, st.Settings(), &fakeStore{}, "1.0.0"); !errors.Is(err, backup.ErrDepositInProgress) {
		t.Fatalf("second deposit: got %v, want ErrDepositInProgress", err)
	}
	close(slow.release)
	if err := <-done; err != nil {
		t.Fatalf("first deposit: %v", err)
	}
}
