package crypto_test

import (
	"testing"

	"github.com/Yoshiofthewire/ky_server_base/internal/crypto"
)

func TestPasswordHashingAndVerification(t *testing.T) {
	password := "CorrectHorseBatteryStaple123!"

	hash, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	if !crypto.VerifyPassword(password, hash) {
		t.Errorf("expected password verification to succeed")
	}

	if crypto.VerifyPassword("WrongPassword123!", hash) {
		t.Errorf("expected password verification to fail on invalid password")
	}
}

func TestAESGCMEncryption(t *testing.T) {
	key := crypto.RandomHex(32)
	plaintext := []byte("Sensitive MFA Secret Payload")

	ciphertext, err := crypto.EncryptAESGCM(plaintext, key)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decrypted, err := crypto.DecryptAESGCM(ciphertext, key)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("expected %s, got %s", plaintext, decrypted)
	}

	// Wrong key should fail
	wrongKey := crypto.RandomHex(32)
	if _, err := crypto.DecryptAESGCM(ciphertext, wrongKey); err == nil {
		t.Errorf("expected decryption failure with wrong key")
	}
}

func TestHMACSHA256(t *testing.T) {
	secret := "shared-sync-webhook-secret"
	payload := []byte(`{"event":"user.updated","username":"alice"}`)

	sig := crypto.ComputeHMACSHA256(payload, secret)
	if !crypto.VerifyHMACSHA256(payload, secret, sig) {
		t.Errorf("expected HMAC verification to succeed")
	}

	if crypto.VerifyHMACSHA256(payload, "wrong-secret", sig) {
		t.Errorf("expected HMAC verification to fail with wrong secret")
	}
}

func TestPKCEGeneration(t *testing.T) {
	verifier, challenge, err := crypto.GeneratePKCE()
	if err != nil {
		t.Fatalf("failed to generate PKCE: %v", err)
	}
	if len(verifier) == 0 || len(challenge) == 0 {
		t.Errorf("expected non-empty verifier and challenge")
	}
	if verifier == challenge {
		t.Errorf("verifier and challenge should not be identical")
	}
}
