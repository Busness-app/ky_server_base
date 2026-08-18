package devices_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Yoshiofthewire/ky_server_base/internal/config"
	"github.com/Yoshiofthewire/ky_server_base/internal/devices"
	"github.com/Yoshiofthewire/ky_server_base/internal/store"
)

func TestPairingLifecycle(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	st, err := store.Open(ctx, config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    filepath.Join(tmpDir, "test.db"),
	})
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer st.Close()

	svc := devices.NewPairingService(st, "BusnesApp", "http://localhost:8080")

	// 1. Init
	initRes, err := svc.InitPairing(ctx, "usr_alice")
	if err != nil {
		t.Fatalf("InitPairing failed: %v", err)
	}
	if len(initRes.Code) != 6 || len(initRes.Secret) == 0 {
		t.Errorf("unexpected code or secret: %+v", initRes)
	}

	// 2. Poll initial status -> pending
	p, err := svc.PollPairingStatus(ctx, initRes.Secret)
	if err != nil || p.Status != "pending" {
		t.Fatalf("expected pending status, got %v (err: %v)", p, err)
	}

	// 3. Verify pairing by code
	verified, err := svc.VerifyPairing(ctx, initRes.Code, "Alice iPhone", "ios", "apns-token-12345")
	if err != nil {
		t.Fatalf("VerifyPairing failed: %v", err)
	}
	if verified.Status != "approved" || verified.DeviceName != "Alice iPhone" {
		t.Errorf("unexpected verified status: %+v", verified)
	}

	// 4. Poll again -> approved
	p2, err := svc.PollPairingStatus(ctx, initRes.Secret)
	if err != nil || p2.Status != "approved" {
		t.Fatalf("expected approved status on second poll, got %v", p2)
	}
}
