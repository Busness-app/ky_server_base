package auth_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/Busness-app/ky_server_base/internal/auth"
)

func TestTOTPGenerationAndValidation(t *testing.T) {
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("failed to generate TOTP secret: %v", err)
	}

	uri := auth.GenerateTOTPURL("BusnesApp", "alice", secret)
	if len(uri) == 0 {
		t.Errorf("expected non-empty TOTP URL")
	}

	// Invalid code should fail
	if auth.ValidateTOTP(secret, "000000") && auth.ValidateTOTP(secret, "999999") {
		// Both couldn't possibly be valid at once
		t.Errorf("expected invalid TOTP to fail")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashedJSON, err := auth.GenerateRecoveryCodes(8)
	if err != nil {
		t.Fatalf("failed to generate recovery codes: %v", err)
	}
	if len(codes) != 8 {
		t.Fatalf("expected 8 codes, got %d", len(codes))
	}

	// Redeem first code
	codeToRedeem := codes[0]
	updatedJSON, ok := auth.RedeemRecoveryCode(codeToRedeem, hashedJSON)
	if !ok {
		t.Fatalf("failed to redeem valid code: %s", codeToRedeem)
	}

	// Redeeming same code again should fail
	_, okAgain := auth.RedeemRecoveryCode(codeToRedeem, updatedJSON)
	if okAgain {
		t.Errorf("expected redeemed code to fail second attempt")
	}
}

func TestProofOfWorkChallenge(t *testing.T) {
	const secret = "test-signing-secret"
	challenge, err := auth.GeneratePoWChallenge(1000, secret)
	if err != nil {
		t.Fatalf("failed to generate PoW challenge: %v", err)
	}

	// Solve challenge client-side
	var winningNumber int = -1
	for i := 1; i <= challenge.MaxNumber; i++ {
		sol := auth.PoWSolution{
			Algorithm: challenge.Algorithm,
			Salt:      challenge.Salt,
			Challenge: challenge.Challenge,
			Number:    i,
			MaxNumber: challenge.MaxNumber,
			ExpiresAt: challenge.ExpiresAt,
			Signature: challenge.Signature,
		}
		solBytes, _ := json.Marshal(sol)
		solB64 := base64.StdEncoding.EncodeToString(solBytes)
		if auth.VerifyPoWSolution(solB64, secret) {
			winningNumber = i
			break
		}
	}

	if winningNumber == -1 {
		t.Errorf("failed to solve PoW within max iterations")
	}
	forged := auth.PoWSolution{Algorithm: "SHA-256", Salt: "mine", Challenge: "fake", Number: 1, MaxNumber: 1, ExpiresAt: challenge.ExpiresAt, Signature: challenge.Signature}
	forgedJSON, _ := json.Marshal(forged)
	if auth.VerifyPoWSolution(base64.StdEncoding.EncodeToString(forgedJSON), secret) {
		t.Fatal("accepted forged challenge metadata")
	}
}

func TestPolicyValidation(t *testing.T) {
	if err := auth.ValidatePassword("short"); err != auth.ErrPasswordTooShort {
		t.Errorf("expected ErrPasswordTooShort, got %v", err)
	}
	if err := auth.ValidatePassword("ValidLongPassword123!"); err != nil {
		t.Errorf("expected valid password, got %v", err)
	}

	if err := auth.ValidateUsername("a"); err != auth.ErrInvalidUsername {
		t.Errorf("expected ErrInvalidUsername for short username, got %v", err)
	}
	if err := auth.ValidateUsername("alice.ops_01"); err != nil {
		t.Errorf("expected valid username, got %v", err)
	}

	if err := auth.ValidateEmail("not-an-email"); err != auth.ErrInvalidEmail {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
	if err := auth.ValidateEmail("alice@busnes.app"); err != nil {
		t.Errorf("expected valid email, got %v", err)
	}
}
