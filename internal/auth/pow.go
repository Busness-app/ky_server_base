package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// PoWChallenge represents a client-side SHA256 puzzle matching the KySecurity standard.
type PoWChallenge struct {
	Algorithm string `json:"algorithm"`
	Salt      string `json:"salt"`
	Challenge string `json:"challenge"`
	MaxNumber int    `json:"maxnumber"`
	ExpiresAt int64  `json:"expires_at"`
}

// PoWSolution represents the client's submitted answer.
type PoWSolution struct {
	Algorithm string `json:"algorithm"`
	Salt      string `json:"salt"`
	Challenge string `json:"challenge"`
	Number    int    `json:"number"`
}

// GeneratePoWChallenge creates a puzzle of given difficulty (e.g. 5000 to 50000 max iterations).
func GeneratePoWChallenge(difficulty int) (*PoWChallenge, error) {
	if difficulty <= 0 {
		difficulty = 20000
	}

	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return nil, err
	}
	salt := hex.EncodeToString(saltBytes)

	// Pick a random winning number in range [1, difficulty]
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(difficulty)))
	if err != nil {
		return nil, err
	}
	targetNumber := int(nBig.Int64()) + 1

	targetStr := fmt.Sprintf("%s%d", salt, targetNumber)
	h := sha256.Sum256([]byte(targetStr))
	challenge := hex.EncodeToString(h[:])

	return &PoWChallenge{
		Algorithm: "SHA-256",
		Salt:      salt,
		Challenge: challenge,
		MaxNumber: difficulty,
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	}, nil
}

// VerifyPoWSolution decodes and validates the client's base64-encoded JSON solution.
func VerifyPoWSolution(solutionBase64 string) bool {
	data, err := base64.StdEncoding.DecodeString(solutionBase64)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(solutionBase64)
		if err != nil {
			return false
		}
	}

	var sol PoWSolution
	if err := json.Unmarshal(data, &sol); err != nil {
		return false
	}

	if sol.Algorithm != "SHA-256" || sol.Salt == "" || sol.Challenge == "" || sol.Number < 0 {
		return false
	}

	targetStr := fmt.Sprintf("%s%d", sol.Salt, sol.Number)
	h := sha256.Sum256([]byte(targetStr))
	actualChallenge := hex.EncodeToString(h[:])

	return actualChallenge == sol.Challenge
}
