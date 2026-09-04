# Backup

## Purpose
Implements "Feature 0" disaster recovery: `kycap/3` container encapsulation (`.kycap`) from `github.com/Busness-app/ky-primitives/capsule`, sealed to the suite recovery public key received at pairing, deposit of the sealed container to KyRecovery, automated sandboxed restore drills, and KyRecovery pairing.

## Ownership
Owns backup payload collection, the KyRecovery client (claim and deposit), loading and pinning the suite recovery public key (`recovery.pub`, key ID pinned in `server_settings`), the pairing record (`kyrecovery_url`, `kyrecovery_token`), the last deposit receipt (`kyrecovery_last_deposit`), sandboxed restore drill verification against a throwaway key, and exposing the sealed capsule for download. It holds no private key and no shares.

## Local Contracts
- `ClaimPairing` sends `service_name` explicitly and it must be the value `Seal` is given (`cfg.Server.AppName`): KyRecovery pins the claimed name and refuses every deposit whose manifest names another.
- `StoreRecoveryKey` is write-once per key; `StorePairing` runs after it, and `LoadPairing` reports `ErrNotPaired` unless key, URL and token are all present.
- `Deposit` sends the container as `application/octet-stream` with the bearer token, accepts 200 or 201, and refuses a receipt whose digest, size or capsule ID do not describe the bytes sent. The upload budget is 15 minutes, matching KyRecovery's read deadline.
- `BuildLocalPayload` snapshots SQLite with `VACUUM INTO` (the store runs in WAL mode; a plain file read misses uncheckpointed commits) and returns `ErrNoDatabaseSnapshot` for any other driver, so a capsule without a consistent database is never sealed or deposited as a backup.
- Deposits are single-flight per process (`ErrDepositInProgress`), across the scheduler, the admin route and the CLI.
- Text from outside the process (remote error bodies, operator-typed URLs) goes through `AuditSafe` before it reaches an error string or an audit record: printable only, 200 characters, so a row always fits the 255-byte Postgres audit columns.
- Errors from the wire or the store wrap `ErrRemote`; a deposit that landed but whose receipt write failed wraps `ErrReceiptUnrecorded` and still returns the receipt. `Outcome` turns any `DepositBackup` result into the audit action, resource and details, and every caller (route, scheduler, CLI) records through it.
- `DepositBackup` records the receipt only after KyRecovery confirmed the digest; a refused deposit leaves the previous receipt in place. The receipt is what a restore compares `CapsuleID` and `CreatedAt` against.
- Sandboxed restore drills must execute inside ephemeral temporary directories with POSIX `0700` permissions and be wiped upon completion.
- Capsules are sealed only to the pinned suite recovery public key; a mismatch between the stored key and the pinned key ID is refused.
- `BuildLocalPayload` carries no key material; only `AppendSealedOnlyFiles` (via `CollectSealable`) adds the encryption key and `recovery.pub`, and its output leaves the process only inside a sealed capsule.
- KyRecovery connections require HTTPS and reject private, loopback, link-local, reserved, and unsafe redirect destinations.
- Restore drills seal to a throwaway key generated and discarded within the same call, and report only checks they actually execute.

## Verification
- `go test -v ./internal/backup/...`

## Child DOX Index
None.
