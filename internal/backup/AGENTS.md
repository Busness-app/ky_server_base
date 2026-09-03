# Backup

## Purpose
Implements "Feature 0" disaster recovery: `kycap/3` container encapsulation (`.kycap`) from `github.com/Busness-app/ky-primitives/capsule`, sealed to the suite recovery public key received at pairing, automated sandboxed restore drills, and KyRecovery pairing integration.

## Ownership
Owns backup payload collection, loading and pinning the suite recovery public key (`recovery.pub`, key ID pinned in `server_settings`), sandboxed restore drill verification against a throwaway key, and exposing the sealed capsule for download. It holds no private key and no shares.

## Local Contracts
- Sandboxed restore drills must execute inside ephemeral temporary directories with POSIX `0700` permissions and be wiped upon completion.
- Capsules are sealed only to the pinned suite recovery public key; a mismatch between the stored key and the pinned key ID is refused.
- Capsule extraction accepts bounded regular files only and rejects absolute paths, traversal, links, unsafe modes, and oversized archives.
- KyRecovery connections require HTTPS and reject private, loopback, link-local, reserved, and unsafe redirect destinations.
- Restore drills decode backup file payloads before encapsulation, seal to a throwaway key generated and discarded within the same call, and report only checks they actually execute.

## Verification
- `go test -v ./internal/backup/...`

## Child DOX Index
None.
