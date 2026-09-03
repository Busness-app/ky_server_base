package backup_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/ky_server_base/internal/backup"
)

func testKey(t *testing.T) (recoverykey.PrivateKey, backup.RecoveryKey) {
	t.Helper()
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return priv, backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}
}

var testFiles = []backup.BackupFile{
	{Path: "data/test.db", Data: []byte("SQLite format 3\x00mock"), Mode: 0600},
	{Path: "config/app.json", Data: []byte(`{"app_name":"BusnesApp"}`), Mode: 0600},
}

func TestSealProducesKycap3ForThePinnedKey(t *testing.T) {
	priv, key := testKey(t)
	raw, m, err := backup.Seal("busnes_app", "1.0.0", testFiles, nil, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	if m.RecoveryKeyID != key.Public.ID() || m.Threshold != 2 || m.TotalShares != 3 {
		t.Fatalf("manifest %+v", m.UnverifiedManifest)
	}
	um, err := capsule.ReadUnverifiedManifest(raw)
	if err != nil || um.CapsuleID != m.CapsuleID {
		t.Fatalf("keyless read: %v %+v", err, um)
	}
	_, files, err := capsule.Open(raw, priv, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || string(files[0].Content) != string(testFiles[0].Data) {
		t.Fatalf("files %+v", files)
	}
}

func TestSealRefusesWhenNotPaired(t *testing.T) {
	_, _, err := backup.Seal("busnes_app", "1.0.0", testFiles, nil, nil, backup.RecoveryKey{})
	if !errors.Is(err, backup.ErrNotPaired) {
		t.Fatalf("got %v, want ErrNotPaired", err)
	}
}

func TestDrillPassesAndReportsThePinnedKey(t *testing.T) {
	_, key := testKey(t)
	recipe := map[string]any{
		"required_files": []any{"data/test.db", "config/app.json"},
		"expected_env":   []any{"KY_PORT"},
		"expected_ports": []any{8080},
	}
	t.Setenv("KY_PORT", "8080")
	res, err := backup.RunRestoreDrill(context.Background(), "busnes_app", "1.0.0", testFiles, map[string]any{"ports": []int{8080}}, recipe, key)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed {
		t.Fatalf("drill failed: %+v", res)
	}
	var sawKey bool
	for _, c := range res.Checks {
		if c.Name == "Recovery Key" && c.Passed {
			sawKey = true
		}
	}
	if !sawKey {
		t.Fatalf("no passing Recovery Key check in %+v", res.Checks)
	}
}

func TestDrillFailsWhenNotPaired(t *testing.T) {
	res, err := backup.RunRestoreDrill(context.Background(), "busnes_app", "1.0.0", testFiles, nil, nil, backup.RecoveryKey{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed {
		t.Fatal("drill passed with no recovery key")
	}
}

func TestDrillFailsARequiredFileThatIsMissing(t *testing.T) {
	_, key := testKey(t)
	recipe := map[string]any{"required_files": []any{"data/absent.db"}}
	res, err := backup.RunRestoreDrill(context.Background(), "busnes_app", "1.0.0", testFiles, nil, recipe, key)
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed {
		t.Fatal("drill passed with a missing required file")
	}
}
