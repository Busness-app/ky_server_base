# Crypto

## Purpose
Provides cryptographic primitives for password hashing (Argon2id), data-at-rest encryption (AES-256-GCM), HMAC signing, SHA-256 digests, and PKCE key pairs.

## Ownership
Owns core cryptographic implementations, key derivation, and constant-time equality checks.

## Local Contracts
- Never store or log plaintext cryptographic keys or master secrets.
- Argon2id must use standard parameters (m=64MB, t=1, p=4).
- AES-256-GCM uses fresh 12-byte random IVs per encryption operation.

## Verification
- `go test -v ./internal/crypto/...`

## Child DOX Index
None.
