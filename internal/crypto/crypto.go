package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

var (
	ErrCiphertextTooShort = errors.New("ciphertext too short")
	ErrDecryptionFailed   = errors.New("decryption failed or invalid key")
)

// Argon2id parameters (RFC 9106 recommended defaults for interactive login)
const (
	ArgonTime    = 1
	ArgonMemory  = 64 * 1024 // 64 MB
	ArgonThreads = 4
	ArgonKeyLen  = 32
	SaltLen      = 16
)

// HashPassword hashes a plaintext password using Argon2id with a cryptographically secure random salt.
func HashPassword(password string) (string, error) {
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, ArgonMemory, ArgonTime, ArgonThreads, b64Salt, b64Hash), nil
}

// VerifyPassword verifies an Argon2id formatted password hash against a candidate plaintext password.
func VerifyPassword(password, encodedHash string) bool {
	var version int
	var memory uint32
	var time uint32
	var threads uint8
	var b64Salt, b64Hash string

	_, err := fmt.Sscanf(encodedHash, "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		&version, &memory, &time, &threads, &b64Salt, &b64Hash)
	if err != nil {
		// Fallback parse if fmt.Sscanf splits differently
		parts := splitHash(encodedHash)
		if len(parts) != 6 || parts[1] != "argon2id" {
			return false
		}
		b64Salt = parts[4]
		b64Hash = parts[5]
		memory = ArgonMemory
		time = ArgonTime
		threads = ArgonThreads
	}

	salt, err := base64.RawStdEncoding.DecodeString(b64Salt)
	if err != nil {
		return false
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(b64Hash)
	if err != nil {
		return false
	}

	candidateHash := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expectedHash)))

	return subtle.ConstantTimeCompare(candidateHash, expectedHash) == 1
}

func splitHash(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '$' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// EncryptAESGCM encrypts plaintext using AES-256-GCM with a random 12-byte IV.
// key must be either a 32-byte raw slice or a 64-char hex string.
func EncryptAESGCM(plaintext []byte, key string) (string, error) {
	k, err := parseKey(key)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// DecryptAESGCM decrypts a base64url encoded ciphertext with AES-256-GCM.
func DecryptAESGCM(encodedCiphertext, key string) ([]byte, error) {
	k, err := parseKey(key)
	if err != nil {
		return nil, err
	}

	data, err := base64.RawURLEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

func parseKey(keyStr string) ([]byte, error) {
	if len(keyStr) == 64 {
		if b, err := hex.DecodeString(keyStr); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	raw := []byte(keyStr)
	if len(raw) == 32 {
		return raw, nil
	}
	// Derive 32 bytes from arbitrary key using SHA-256
	h := sha256.Sum256([]byte(keyStr))
	return h[:], nil
}

// ComputeHMACSHA256 computes HMAC-SHA256 hex string.
func ComputeHMACSHA256(data []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyHMACSHA256 verifies HMAC-SHA256 signature in constant time.
func VerifyHMACSHA256(data []byte, secret, expectedHex string) bool {
	actualHex := ComputeHMACSHA256(data, secret)
	return subtle.ConstantTimeCompare([]byte(actualHex), []byte(expectedHex)) == 1
}

// SHA256Hex returns the hex-encoded SHA-256 digest of input.
func SHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// RandomHex generates a cryptographically secure random hex string of 2*n characters.
func RandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// RandomBase64URL generates a cryptographically secure URL-safe base64 string.
func RandomBase64URL(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// GeneratePKCE creates a PKCE code_verifier and code_challenge (S256).
func GeneratePKCE() (verifier string, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}
