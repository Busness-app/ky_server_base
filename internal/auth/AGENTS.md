# Auth

## Purpose
Manages user authentication, password policies, Multi-Factor Authentication (RFC 6238 TOTP), recovery codes, session token lifecycle, and anti-abuse CAPTCHA (Proof-of-Work default).

## Ownership
Owns session issuance and verification, TOTP token generation/validation, recovery code redemption, and client-side PoW verification.

## Local Contracts
- Passwords require at least 12 characters (`ValidatePassword`).
- Active sessions are stored with SHA-256 hashed tokens and verified against secure HttpOnly / SameSite cookies or Bearer headers.
- Session authentication rejects inactive accounts and deletes their presented session.
- PoW solutions must carry unexpired server-signed challenge metadata.
- Password verification creates a five-minute opaque MFA transaction; MFA endpoints never accept a user ID and consume the transaction once.
- Single-use recovery codes are invalidated immediately upon redemption.

## Verification
- `go test -v ./internal/auth/...`

## Child DOX Index
None.
