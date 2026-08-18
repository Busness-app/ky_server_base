package backup_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/Yoshiofthewire/ky_server_base/internal/backup"
	"github.com/Yoshiofthewire/ky_server_base/internal/crypto"
	_ "modernc.org/sqlite"
)

func TestShamirSecretSharing(t *testing.T) {
	secret := []byte("32-byte-master-encryption-key-!!")
	threshold := 3
	totalShares := 5

	// 1. Split
	shares, err := backup.SplitSecret(secret, threshold, totalShares)
	if err != nil {
		t.Fatalf("SplitSecret failed: %v", err)
	}
	if len(shares) != totalShares {
		t.Fatalf("expected %d shares, got %d", totalShares, len(shares))
	}

	// 2. Reconstruct with exact threshold (e.g. shares [0, 2, 4])
	subset := []backup.Share{shares[0], shares[2], shares[4]}
	reconstructed, err := backup.CombineShares(subset, threshold)
	if err != nil {
		t.Fatalf("CombineShares failed: %v", err)
	}

	if string(reconstructed) != string(secret) {
		t.Errorf("expected %s, got %s", string(secret), string(reconstructed))
	}

	// 3. Reconstruct with another combination (shares [1, 3, 4])
	subset2 := []backup.Share{shares[1], shares[3], shares[4]}
	reconstructed2, err := backup.CombineShares(subset2, threshold)
	if err != nil {
		t.Fatalf("CombineShares subset2 failed: %v", err)
	}
	if string(reconstructed2) != string(secret) {
		t.Errorf("subset2 expected %s, got %s", string(secret), string(reconstructed2))
	}

	// 4. Reconstruct with less than threshold should fail
	_, err = backup.CombineShares(shares[:2], threshold)
	if err != backup.ErrNotEnoughShares {
		t.Errorf("expected ErrNotEnoughShares, got %v", err)
	}
}

func TestCapsuleLifecycleAndRestoreDrill(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// 1. Create a dummy SQLite DB with data
	dbFile := filepath.Join(tmpDir, "test.db")
	db, err := sql.Open("sqlite", dbFile)
	if err != nil {
		t.Fatalf("failed to create sqlite db: %v", err)
	}
	_, _ = db.Exec("CREATE TABLE notes (id INTEGER PRIMARY KEY, content TEXT);")
	_, _ = db.Exec("INSERT INTO notes (content) VALUES ('Secret KyNote entry');")
	_ = db.Close()

	// Read sqlite bytes
	dbBytes, err := crypto.RandomHex(16), nil
	_ = dbBytes

	files := []backup.BackupFile{
		{
			Path: "data/test.db",
			Data: []byte("SQLite format 3\x00mock-header-content"),
			Mode: 0600,
		},
		{
			Path: "config/app.json",
			Data: []byte(`{"app_name":"BusnesApp","port":8080}`),
			Mode: 0600,
		},
	}

	recipe := map[string]interface{}{
		"check_sqlite_integrity": false,
		"required_files":         []interface{}{"data/test.db", "config/app.json"},
		"expected_env":           []interface{}{"KY_PORT"},
		"expected_ports":         []interface{}{8080},
	}

	deps := map[string]interface{}{
		"ports": []int{8080},
	}

	// 2. Create Capsule
	capsule, key, err := backup.CreateCapsule("busnes_app", "1.0.0", files, deps, recipe, 2, 3)
	if err != nil {
		t.Fatalf("CreateCapsule failed: %v", err)
	}

	if len(capsule.Shares) != 3 {
		t.Errorf("expected 3 shares, got %d", len(capsule.Shares))
	}

	// 3. Reconstruct key from 2 shares
	recoveredKey, err := backup.CombineShares(capsule.Shares[:2], 2)
	if err != nil {
		t.Fatalf("CombineShares failed: %v", err)
	}

	if string(recoveredKey) != string(key) {
		t.Errorf("recovered key does not match original key")
	}

	// 4. Run Restore Drill
	drillResult, err := backup.RunRestoreDrill(ctx, capsule, recoveredKey)
	if err != nil {
		t.Fatalf("RunRestoreDrill error: %v", err)
	}

	if !drillResult.Passed {
		t.Errorf("expected drill to pass, got failure: %s, checks: %+v", drillResult.ErrorMessage, drillResult.Checks)
	}

	// 5. Generate Recovery Kit HTML
	html := backup.GenerateRecoveryKitHTML(capsule, "BusnesApp", "https://recovery.internal")
	if len(html) == 0 {
		t.Errorf("expected non-empty recovery kit HTML")
	}
}
