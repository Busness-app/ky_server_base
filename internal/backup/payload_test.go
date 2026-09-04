package backup_test

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/keyfile"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/ky_server_base/internal/backup"
	"github.com/Busness-app/ky_server_base/internal/config"
)

func payloadConfig(t *testing.T) (*config.Config, []byte) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Server.AppName = "busnes_app"
	cfg.Server.Port = 8080
	cfg.Database.Driver = "postgres" // no SQLite file to read in a temp dir
	cfg.Security.EncryptionKey = key
	return cfg, key
}

// sealingPayload is what the sealing collectors assemble: the local payload plus the members
// that may only travel inside a capsule.
func sealingPayload(t *testing.T, cfg *config.Config) *backup.Payload {
	t.Helper()
	payload, err := backup.BuildLocalPayload(cfg, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.AppendSealedOnlyFiles(cfg, payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

// BuildLocalPayload alone must carry neither the encryption key nor the recovery public key:
// only the sealing collectors may add them, so nothing else can leak them by accident.
func TestLocalPayloadCarriesNoKeys(t *testing.T) {
	cfg, _ := payloadConfig(t)
	cfg.Database.DataDir = t.TempDir()
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := keyfile.Store(backup.RecoveryKeyPath(cfg.Database.DataDir), priv.Public().Bytes(), keyfile.Raw); err != nil {
		t.Fatal(err)
	}

	payload, err := backup.BuildLocalPayload(cfg, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := payload.VerificationRecipe["required_files"].([]string)
	for _, path := range []string{"data/encryption.key", "data/recovery.pub"} {
		if findFile(payload.Files, path) != nil {
			t.Errorf("the local payload carries %s", path)
		}
		if slices.Contains(req, path) {
			t.Errorf("required_files: got %v, want no %s", req, path)
		}
	}
}

// The encryption key must ride in the capsule: users.totp_secret_enc is AES-GCM under it, so
// a restore without it hands the operator a database whose MFA secrets are gone for good.
func TestPayloadCarriesTheEncryptionKey(t *testing.T) {
	cfg, key := payloadConfig(t)
	payload := sealingPayload(t, cfg)
	var found bool
	for _, f := range payload.Files {
		if f.Path != "data/encryption.key" {
			continue
		}
		found = true
		if want := hex.EncodeToString(key) + "\n"; string(f.Data) != want {
			t.Errorf("content: got %q, want the lowercase hex keyfile reads", f.Data)
		}
		if f.Mode != 0600 {
			t.Errorf("mode: got %o, want 600", f.Mode)
		}
	}
	if !found {
		t.Fatal("payload has no data/encryption.key")
	}
	req, _ := payload.VerificationRecipe["required_files"].([]string)
	if !slices.Contains(req, "data/encryption.key") {
		t.Errorf("required_files: got %v, want data/encryption.key among them", req)
	}
}

// End to end: seal the payload to a recovery key, open it with the private half, and the
// restored tree must hold a key file keyfile can read back byte for byte.
func TestSealedCapsuleRestoresTheEncryptionKey(t *testing.T) {
	cfg, key := payloadConfig(t)
	payload := sealingPayload(t, cfg)
	files := payload.Files
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := backup.Seal(cfg.Server.AppName, "1.0.0", files, payload.Dependencies, payload.VerificationRecipe,
		backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3})
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if _, _, err := capsule.Open(raw, priv, target); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(target, "data", "encryption.key")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("restored key file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("restored mode: got %o, want 600", info.Mode().Perm())
	}
	got, err := keyfile.LoadEncoded(path, 32, keyfile.Hex)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(key) {
		t.Error("restored key does not match the running instance's key")
	}
}

// A restore must come back paired, not half-paired: recovery.pub is public and the capsule is
// sealed to that very key, so it rides along whenever the instance has one.
func TestPayloadCarriesTheRecoveryPublicKeyWhenPaired(t *testing.T) {
	cfg, _ := payloadConfig(t)
	cfg.Database.DataDir = t.TempDir()

	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}

	unpaired := sealingPayload(t, cfg)
	if f := findFile(unpaired.Files, "data/recovery.pub"); f != nil {
		t.Error("unpaired instance shipped a recovery.pub")
	}
	if req, _ := unpaired.VerificationRecipe["required_files"].([]string); slices.Contains(req, "data/recovery.pub") {
		t.Errorf("unpaired required_files: got %v", req)
	}

	if err := keyfile.Store(backup.RecoveryKeyPath(cfg.Database.DataDir), priv.Public().Bytes(), keyfile.Raw); err != nil {
		t.Fatal(err)
	}
	paired := sealingPayload(t, cfg)
	f := findFile(paired.Files, "data/recovery.pub")
	if f == nil {
		t.Fatal("paired instance has no data/recovery.pub in the payload")
	}
	if string(f.Data) != string(priv.Public().Bytes()) {
		t.Error("data/recovery.pub is not the pinned public key byte for byte")
	}
	if f.Mode != 0600 {
		t.Errorf("mode: got %o, want 600", f.Mode)
	}
	if req, _ := paired.VerificationRecipe["required_files"].([]string); !slices.Contains(req, "data/recovery.pub") {
		t.Errorf("required_files: got %v, want data/recovery.pub among them", req)
	}
}

func findFile(files []backup.BackupFile, path string) *backup.BackupFile {
	for i := range files {
		if files[i].Path == path {
			return &files[i]
		}
	}
	return nil
}

func TestAppendSealedOnlyFilesRefusesAShortKey(t *testing.T) {
	cfg, _ := payloadConfig(t)
	cfg.Security.EncryptionKey = cfg.Security.EncryptionKey[:16]
	payload, err := backup.BuildLocalPayload(cfg, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.AppendSealedOnlyFiles(cfg, payload); err == nil {
		t.Fatal("a 16-byte encryption key was accepted")
	}
}

func TestFilenameSafe(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"busnes_app-2026-09-03T00.00.00Z", "busnes_app-2026-09-03T00.00.00Z"},
		{`../../etc/pa"sswd`, "..-..-etc-pa-sswd"}, // dots survive, separators do not
		{"cap\nid", "cap-id"},
	} {
		if got := backup.FilenameSafe(tc.in); got != tc.want {
			t.Errorf("FilenameSafe(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
