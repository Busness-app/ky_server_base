package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// GenerateRecoveryCodes produces a set of human-friendly recovery codes and their SHA-256 hashes.
func GenerateRecoveryCodes(count int) (plainCodes []string, hashedJSON string, err error) {
	if count <= 0 {
		count = 8
	}

	plainCodes = make([]string, count)
	var hashes []string

	for i := 0; i < count; i++ {
		code, err := randomCode()
		if err != nil {
			return nil, "", err
		}
		plainCodes[i] = code
		h := sha256.Sum256([]byte(strings.ToUpper(strings.ReplaceAll(code, "-", ""))))
		hashes = append(hashes, hex.EncodeToString(h[:]))
	}

	b, err := json.Marshal(hashes)
	if err != nil {
		return nil, "", err
	}

	return plainCodes, string(b), nil
}

// RedeemRecoveryCode verifies a code against the stored JSON array of hashes.
// If valid, returns updated JSON hash list with the redeemed code removed and ok=true.
func RedeemRecoveryCode(candidateCode, hashedJSON string) (updatedHashedJSON string, ok bool) {
	candidateNorm := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(candidateCode), "-", ""))
	h := sha256.Sum256([]byte(candidateNorm))
	candidateHash := hex.EncodeToString(h[:])

	var hashes []string
	if err := json.Unmarshal([]byte(hashedJSON), &hashes); err != nil {
		return hashedJSON, false
	}

	foundIdx := -1
	for i, h := range hashes {
		if h == candidateHash {
			foundIdx = i
			break
		}
	}

	if foundIdx == -1 {
		return hashedJSON, false
	}

	// Remove used hash
	hashes = append(hashes[:foundIdx], hashes[foundIdx+1:]...)
	newJSON, _ := json.Marshal(hashes)
	return string(newJSON), true
}

func randomCode() (string, error) {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Crockford-style avoid 0/O, 1/I
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	var sb strings.Builder
	for i, v := range b {
		if i == 4 {
			sb.WriteByte('-')
		}
		sb.WriteByte(charset[int(v)%len(charset)])
	}
	return sb.String(), nil
}
