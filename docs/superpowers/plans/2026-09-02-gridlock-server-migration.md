# gridlock-server Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `gridlock-server` its own module identity, then move it onto the suite's shared backup primitives without breaking any capsule it has already written.

**Architecture:** `gridlock-server` is a copy of the scaffold whose module was never renamed — it currently declares and imports `github.com/Yoshiofthewire/ky_server_base`. The rename must land first and alone, because it touches every file and would otherwise drown the migration diff. The primitives migration then follows the same shape as every other repo's.

**Tech Stack:** Go 1.26+, standard library plus the repo's existing dependencies.

**Spec:** [The suite shared primitives plan](2026-09-02-suite-shared-primitives.md) Task 4, corrected by [the Shamir interop findings](../../shamir-interop-findings.md) and [the capsule interop plan](2026-09-02-capsule-format-interop.md).

## Global Constraints

- **No behaviour change to any capsule that already exists on disk.**
- Gates stay green: `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`.
- Module path prefix is `github.com/Yoshiofthewire/`.
- `ky-primitives` has zero dependencies; adding it must add **no new indirect entries** to this repo's `go.mod`.

---

## Why this repo needs its own plan

The parent plan's Task 4 says: *"Same shape as Task 3, in either order. These two already share an implementation (md5 `a0d9905b`), so they migrate together or not at all."*

Two things about that are wrong.

**1. It is only true of `shamir.go`.** The capsule files differ:

```
gridlock-server/internal/backup/capsule.go   md5 e93fdf6c…   223 lines
ky_server_base/internal/backup/capsule.go    md5 9a17784d…   226 lines
```

49 changed lines between them. gridlock and the scaffold share a Shamir implementation, not a backup package.

**2. `gridlock-server` has no module identity of its own.**

```
$ head -1 gridlock-server/go.mod
module github.com/Yoshiofthewire/ky_server_base
```

Every one of its **32 Go files** imports internal packages under that prefix, and `scripts/ky-init.sh` references it too. Two repositories currently claim one module path. `go get github.com/Yoshiofthewire/ky_server_base` is ambiguous between them, and any tool resolving that path may get either repo's code.

Migrating this repo without renaming it first would add `ky-primitives` to a module that is pretending to be a different module.

---

## Task 1: Give gridlock-server its own module path

**Files:**
- Modify: `go.mod` line 1
- Modify: all 32 `.go` files importing `github.com/Yoshiofthewire/ky_server_base`
- Modify: `scripts/ky-init.sh`

This task changes no behaviour. It is a pure rename, and it should be reviewed as one — a rename with a logic change buried in it is unreviewable.

- [ ] **Step 1: Record the starting state so the rename can be checked**

```bash
cd /home/yoshi/busness.app/gridlock-server
go test -race -count=1 ./... 2>&1 | tee /tmp/gridlock-before.txt
grep -rl "github.com/Yoshiofthewire/ky_server_base" . | sort > /tmp/gridlock-refs.txt
wc -l /tmp/gridlock-refs.txt
```

Expected: 34 paths — 32 Go files, `go.mod`, `scripts/ky-init.sh`.

- [ ] **Step 2: Rewrite the module path everywhere**

```bash
cd /home/yoshi/busness.app/gridlock-server
xargs -a /tmp/gridlock-refs.txt \
  sed -i 's|github.com/Yoshiofthewire/ky_server_base|github.com/Yoshiofthewire/gridlock-server|g'
```

- [ ] **Step 3: Verify nothing was missed and nothing else changed**

```bash
grep -rn "Yoshiofthewire/ky_server_base" . ; echo "exit=$?"
```

Expected: no output, `exit=1`. A match here means a reference outside the list from Step 1 — find it before continuing.

```bash
git diff --stat
git diff | grep -E "^[-+]" | grep -v "Yoshiofthewire" | grep -vE "^(---|\+\+\+)"
```

The second command must print nothing. **Any line it prints is a change the rename should not have made** — investigate rather than accepting it.

- [ ] **Step 4: Verify the build and tests are unchanged**

```bash
go mod tidy
gofmt -l . && go vet ./... && go test -race -count=1 ./... 2>&1 | tee /tmp/gridlock-after.txt
diff <(sed 's|ky_server_base|MODULE|g' /tmp/gridlock-before.txt) \
     <(sed 's|gridlock-server|MODULE|g' /tmp/gridlock-after.txt)
```

The diff should show only timing differences. A test that passed before and fails now means the rename was not pure.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: claim gridlock-server's own module path

This repo was copied from ky_server_base and its go.mod was never
renamed, so two repositories declared one module identity and every
internal import resolved under the scaffold's path. Pure rename: no
behaviour change."
```

---

## Task 2: Adopt ky-primitives for Shamir

**Files:**
- Modify: `internal/backup/shamir.go`
- Modify: `go.mod`, `go.sum`
- Test: `internal/backup/backup_test.go` (unchanged — it is the contract)

**Depends on:** Task 1; `ky-primitives` published (parent plan Task 2).

**Interfaces consumed:**
- `shamir.Split(secret []byte, k, n int) ([]Share, error)`
- `shamir.Combine(shares []Share, k int) ([]byte, error)`
- `shamir.Share{Index int, Data []byte}`

Shamir is the safe half of this migration: [the interop findings](../../shamir-interop-findings.md) proved this repo's implementation and KySignOn's are behaviourally identical across 7,200 randomised round trips. Nothing about existing share sets changes.

- [ ] **Step 1: Copy the golden vectors in as a pre-migration guard**

```bash
mkdir -p testdata
cp /home/yoshi/busness.app/ky_server_base/testdata/shamir-vectors.json testdata/
cp /home/yoshi/busness.app/ky_server_base/internal/backup/shamir_vectors_test.go internal/backup/
sed -i 's|github.com/Yoshiofthewire/ky_server_base/internal/backup|github.com/Yoshiofthewire/gridlock-server/internal/backup|' \
  internal/backup/shamir_vectors_test.go
go test -race -count=1 -run TestShamirGoldenVectors ./internal/backup/...
```

Expected: PASS, **before** anything is replaced. This proves the vectors describe this repo's current behaviour, which is what makes them a meaningful check afterwards.

- [ ] **Step 2: Add the dependency and check its cost**

```bash
go list -m all | wc -l > /tmp/gridlock-modcount-before.txt
go get github.com/Yoshiofthewire/ky-primitives@v0.1.0
go mod tidy
go list -m all | wc -l
```

The count must rise by exactly one. If any new indirect entry appears, **stop** — `ky-primitives` violated its own zero-dependency contract and the parent plan's Task 2 is not finished.

- [ ] **Step 3: Delegate, keeping the package boundary**

Replace the body of `internal/backup/shamir.go` with delegation. `SplitSecret` and `CombineShares` keep their exported signatures so nothing outside `internal/backup` changes:

```go
package backup

import (
	"github.com/Yoshiofthewire/ky-primitives/shamir"
)

// Share is one custodian's key shard in a (k, n) threshold scheme.
type Share = shamir.Share

// SplitSecret splits a secret into n shares with a reconstruction threshold of k.
func SplitSecret(secret []byte, k, n int) ([]Share, error) {
	return shamir.Split(secret, k, n)
}

// CombineShares reconstructs the secret from any k valid shares.
func CombineShares(shares []Share, k int) ([]byte, error) {
	return shamir.Combine(shares, k)
}
```

`Share` is a type alias, not a new type: callers construct `backup.Share{Index: …, Data: …}` today, and an alias keeps that working without touching them.

The `ErrInvalidThreshold` and `ErrNotEnoughShares` sentinels move to `ky-primitives` too. If any caller in this repo compares against them, re-export them here:

```go
var (
	ErrInvalidThreshold = shamir.ErrInvalidThreshold
	ErrNotEnoughShares  = shamir.ErrNotEnoughShares
)
```

Check first, and delete these two lines if nothing uses them:

```bash
grep -rn "ErrInvalidThreshold\|ErrNotEnoughShares" --include='*.go' .
```

- [ ] **Step 4: Run the vectors and the full suite**

```bash
go test -race -count=1 ./internal/backup/...
go test -race -count=1 ./...
```

The vector test and `backup_test.go` must pass **without being edited**. A test you had to change is a behaviour change — report it rather than letting it ride.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./... && go test -race -count=1 ./...
git add go.mod go.sum internal/backup testdata
git commit -m "refactor(backup): use shared ky-primitives for Shamir"
```

---

## Task 3: Adopt ky-primitives for the capsule format

**Files:**
- Modify: `internal/backup/capsule.go`
- Test: `internal/backup/backup_test.go`, plus the capsule fixtures

**Depends on:** Task 2, and **[the capsule interop plan](2026-09-02-capsule-format-interop.md) Task 3 complete and passing.**

**This task is blocked until the shared capsule package opens all three products' capsules.** This repo writes ciphertext in `base64.RawURLEncoding`; KySignOn writes `base64.StdEncoding`; they are mutually unreadable. A shared package that picks one encoding orphans this repo's backups.

- [ ] **Step 1: Prove this repo's existing capsules open, before changing anything**

```bash
go test -race -count=1 ./internal/backup/...
ls /home/yoshi/busness.app/ky_server_base/testdata/capsules/capsule-gridlock.kycap
```

The fixture generated in the capsule plan's Task 1 is this repo's own capsule. It is the thing that must still open at the end.

- [ ] **Step 2: Delegate the capsule to the shared package**

Replace `CreateCapsule` and `ExtractCapsule` with calls into `ky-primitives/capsule`, keeping this package's exported signatures:

```go
func CreateCapsule(serviceName, appVersion string, files []BackupFile, deps, recipe map[string]interface{}, threshold, totalShares int) (*Capsule, []byte, error)
func ExtractCapsule(capsule *Capsule, key []byte, targetDir string) ([]BackupFile, error)
```

Read `internal/backup/capsule.go` before writing the delegation. The 49-line difference from the scaffold's copy is unreviewed — if any of it is behaviour this repo depends on rather than drift, it has to survive the move. Report anything you find that the shared package does not cover.

- [ ] **Step 3: Prove the pre-migration capsule still opens**

```bash
go test -race -count=1 ./internal/backup/...
```

Add a test that opens `testdata/capsules/capsule-gridlock.kycap` through the post-migration code path. **This is the single most important check in this plan.** If it fails, stop: a backup written before the migration no longer opens, and that is data loss, not a test failure.

- [ ] **Step 4: Full gate and commit**

```bash
gofmt -l . && go vet ./... && go test -race -count=1 ./...
git add go.mod go.sum internal/backup testdata
git commit -m "refactor(backup): use shared ky-primitives for the capsule format"
```

---

## Task 4: Replace the stale pairing spec with a pointer

Covered by [the pairing spec plan](2026-09-02-pairing-spec-one-home.md), which handles all nine copies in one change. Do not do it here — nine separate commits to nine repos is how the copies drifted in the first place.

---

## What this plan deliberately does not do

- **It does not touch `internal/crypto`.** The `EncryptAESGCM` signature fork is real but is a separate five-repo change with no data-loss risk.
- **It does not rename the repository or its GitHub remote.** Only the Go module path. If the remote should move too, that is a decision for a human and a separate change.
- **It does not consolidate `internal/devices` or `internal/sso`**, both of which this repo shares with the scaffold. Divergence there costs maintenance, not correctness.
