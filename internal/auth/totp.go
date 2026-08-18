package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// GenerateTOTPSecret generates a random base32 encoded RFC 6238 secret key.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20) // 160-bit secret
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// GenerateTOTPURL formats the otpauth:// URI for QR code generation in authenticator apps.
func GenerateTOTPURL(issuer, accountName, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, accountName, secret, issuer)
}

// ValidateTOTP checks if candidate code matches the TOTP generated for the current time window ±1 step (30s).
func ValidateTOTP(secret, code string) bool {
	cleanCode := strings.TrimSpace(code)
	if len(cleanCode) != 6 {
		return false
	}

	secret = strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		// Try with standard padding if needed
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return false
		}
	}

	now := time.Now().Unix()
	step := int64(30)
	currentInterval := now / step

	// Check window: [current - 1, current, current + 1]
	for _, interval := range []int64{currentInterval - 1, currentInterval, currentInterval + 1} {
		if computeHOTP(key, interval) == cleanCode {
			return true
		}
	}
	return false
}

func computeHOTP(key []byte, counter int64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	code := (int(h[offset])&0x7f)<<24 |
		(int(h[offset+1])&0xff)<<16 |
		(int(h[offset+2])&0xff)<<8 |
		(int(h[offset+3]) & 0xff)

	otp := code % 1000000
	return fmt.Sprintf("%06d", otp)
}
