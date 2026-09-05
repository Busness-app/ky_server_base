# Backup

## Purpose
Adapts the scaffold to `github.com/Busness-app/ky-primitives/recoveryclient`, which owns the
KyRecovery pairing, sealing, deposit, restore and drill contract. This package supplies only
what differs per product: a `Settings` adapter over `store.SettingsStore`, a `Sealer` under the
deployment key, the payload the scaffold seals (`Collect`), and the drill's verification
checks (`Checks`).

## Ownership
Owns the settings adapter (`settings.go`), payload collection (`payload.go`), and restore-drill
checks (`drill.go`). It holds no private key, no share, and no pairing state of its own — those
live in `recoveryclient` and in the settings rows it reads and writes through the adapter.

## Local Contracts
- `Settings` maps `store.ErrNotFound` to `recoveryclient.ErrNotFound`; every other error passes
  through unchanged.
- `NewSealer` seals the KyRecovery token under the deployment key with label
  `ky_server_base:setting:kyrecovery_token`, domain-separated so a row copied from another
  setting will not open.
- `Collect` snapshots SQLite with the lib's `SQLiteSnapshot` (`VACUUM INTO`; the store runs in
  WAL mode, so a plain file read misses uncheckpointed commits) and returns
  `ErrNoDatabaseSnapshot` for any other driver, so a capsule without a consistent database is
  never sealed. It also carries the encryption key (`data/encryption.key`, required — restores
  a database whose MFA secrets are gone otherwise) and the pinned recovery public key
  (`data/recovery.pub`, only when paired).
- `Checks` sees only the scratch directory the lib opened a drilled capsule into: it asserts
  every `required_files` member is present and non-empty, every `sqlite_paths` member passes
  `PRAGMA integrity_check`, and every `expected_env` name is set.
- `DrillRoot` is under the data directory, never the system temp dir, because the opened
  payload is the whole instance in the clear.
- `Members` names what `Collect` would seal now, for the status route and the screen; keep
  the two in step.
- Pairing, the write-once key pin, `Run` (one seal, every destination), the schedule, local
  copies and their pruning, drill mechanics, restore and the decrypt guard are the lib's;
  their contracts are in the `recoveryclient` README. `client_test.go` pins only what this
  package's wiring buys: `KY_BACKUP_ALLOW_PRIVATE_RECOVERY` admits RFC1918 and CGNAT and
  nothing else.

## Verification
- `go test -v ./internal/backup/...`

## Child DOX Index
None.
