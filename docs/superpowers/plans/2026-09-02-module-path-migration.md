# Module Path Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every Go module in the suite declare the path it actually lives at, `github.com/busness-app/<name>`, before anything imports anything else.

**Architecture:** Eight Go repositories, four naming conventions, none of them matching the org the code now lives in. Each repo is renamed on its own — a pure find-and-replace over its own import prefix, verified by a diff that must contain nothing but the path change.

**Tech Stack:** Go 1.26+. No behaviour changes anywhere in this plan.

**Spec:** The suite moved to `github.com/busness-app/`. This plan is the go.mod half of that move, which did not travel with the remotes.

## Global Constraints

- **The canonical prefix is `github.com/busness-app/`, lowercase.** Go module paths are case-sensitive and an uppercase letter is escaped as `!b` in the module cache and on the proxy. The suite already carries the scar of getting this inconsistent — `kydns-server` and `kynotes-server` say `yoshiofthewire` while three others say `Yoshiofthewire`.
- **No behaviour change in any repo.** A rename commit that also changes logic is unreviewable.
- Gates stay green in every repo touched: `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`.
- Each repo is renamed and committed **separately**. They are separate repositories.

---

## Why this plan exists, and why it goes first

The repositories moved to the `busness-app` GitHub organisation. **No `go.mod` followed them.** Measured 2026-09-02:

| Repo | `go.mod` says | `origin` says |
|---|---|---|
| `ky_server_base` | `github.com/Yoshiofthewire/ky_server_base` | `Busness-app/ky_server_base` |
| `kysignon-server` | `github.com/Yoshiofthewire/kysignon-server` | `Busness-app/kysignon-server` |
| `gridlock-server` | `github.com/Yoshiofthewire/ky_server_base` | **no origin** |
| `kydns-server` | `github.com/yoshiofthewire/kydns-server` | `Busness-app/kydns-server` |
| `kynotes-server` | `github.com/yoshiofthewire/kynotes-server` | `Busness-app/kynotes-server` |
| `kybookmarks-server` | `kybookmarks-server` | `Busness-app/kybookmarks-server` |
| `kypassword-server` | `kypassword-server` | `Busness-app/kypassword-server` |
| `kyrecovery-server` | `kyrecovery-server` | `Busness-app/kyrecovery-server` |

Four conventions: the old org capitalised, the old org lowercased, a bare name with no domain, and — in `gridlock-server` — another repository's path entirely.

**This blocks the rest of the overhaul.** The parent plan's Task 2 creates `ky-primitives` as a module that five repos will import, and its path is the first thing that gets written down. Publishing it under a prefix nothing else uses, or picking one while eight repos still disagree, means renaming it again later — through every import in every consumer.

### A correction to the Shamir findings

[The Shamir interop findings](../../shamir-interop-findings.md) say the parent plan's `github.com/Busness-app/<name>` convention "is wrong" and that the real prefix is `github.com/Yoshiofthewire/`. **That correction was itself wrong.** It described `go.mod` accurately, but `go.mod` was the stale artefact — the parent plan named the destination, not the current state. The destination stands; only the case changes, to lowercase.

### A bare module path is not harmless

Three repos declare a module path with no domain (`kyrecovery-server`, `kypassword-server`, `kybookmarks-server`). Such a module still *consumes* dependencies fine, which is why this has gone unnoticed. It cannot be *imported* by anything. `kyrecovery-server` is the donor for the shared audit chain and `kypassword-server` and `kybookmarks-server` are its consumers — all three appear in [the audit chain plan](2026-09-02-audit-chain-convergence.md), and none of them can participate in a shared-module relationship until this is fixed.

---

## Task 1: Rename gridlock-server, resolving the collision

**Files:**
- Modify: `gridlock-server/go.mod`, its 32 `.go` files, `scripts/ky-init.sh`

This repo goes first because it is the only one whose current path is actively wrong rather than merely stale: it claims `github.com/Yoshiofthewire/ky_server_base`, the scaffold's path. Two repositories, one module identity.

- [ ] **Step 1: Record the starting state**

```bash
cd /home/yoshi/busness.app/gridlock-server
go test -race -count=1 ./... 2>&1 | tee /tmp/gridlock-before.txt
grep -rl "github.com/Yoshiofthewire/ky_server_base" . | sort > /tmp/gridlock-refs.txt
wc -l /tmp/gridlock-refs.txt
```

Expected: 34 paths — 32 Go files, `go.mod`, `scripts/ky-init.sh`.

- [ ] **Step 2: Rewrite the path**

```bash
xargs -a /tmp/gridlock-refs.txt \
  sed -i 's|github.com/Yoshiofthewire/ky_server_base|github.com/busness-app/gridlock-server|g'
```

- [ ] **Step 3: Verify nothing was missed and nothing else changed**

```bash
grep -rn "Yoshiofthewire" . ; echo "exit=$?"
```

Expected: no output, `exit=1`.

```bash
git diff | grep -E "^[-+]" | grep -vE "busness-app|Yoshiofthewire" | grep -vE "^(---|\+\+\+)"
```

Must print nothing. **Any line it prints is a change the rename should not have made.**

- [ ] **Step 4: Verify build and tests are unchanged**

```bash
go mod tidy
gofmt -l . && go vet ./... && go test -race -count=1 ./... 2>&1 | tee /tmp/gridlock-after.txt
diff <(sed 's|Yoshiofthewire/ky_server_base|MODULE|g' /tmp/gridlock-before.txt) \
     <(sed 's|busness-app/gridlock-server|MODULE|g' /tmp/gridlock-after.txt)
```

Only timing should differ.

- [ ] **Step 5: This repo has no `origin`**

```bash
git -C /home/yoshi/busness.app/gridlock-server remote -v
```

It prints nothing today. Every other repo in the suite has a `Busness-app` remote; this one exists only on this machine, which is part of why its module path went unnoticed for so long.

**Ask the human before adding a remote.** Creating or pushing to a repository is an outward-facing action and the name is theirs to choose. Record the answer here either way — a repo that exists on one laptop is a bus factor, not a design.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor: claim gridlock-server's own module path

This repo was copied from ky_server_base and its go.mod was never
renamed, so two repositories declared one module identity and every
internal import resolved under the scaffold's path. Pure rename: no
behaviour change."
```

---

## Task 2: Rename the two repos already on GitHub paths

**Files:**
- Modify: `ky_server_base` and `kysignon-server` — `go.mod` and every file importing the old prefix

These two only change organisation and case.

- [ ] **Step 1: Rename `kysignon-server`**

```bash
cd /home/yoshi/busness.app/kysignon-server
go test -race -count=1 ./... 2>&1 | tee /tmp/kysignon-before.txt
grep -rl "github.com/Yoshiofthewire/kysignon-server" . | sort > /tmp/kysignon-refs.txt
xargs -a /tmp/kysignon-refs.txt \
  sed -i 's|github.com/Yoshiofthewire/kysignon-server|github.com/busness-app/kysignon-server|g'
grep -rn "Yoshiofthewire" . ; echo "exit=$?"
go mod tidy && gofmt -l . && go vet ./... && go test -race -count=1 ./...
git add -A && git commit -m "refactor: move module path to github.com/busness-app"
```

Expected from the `grep`: no output, `exit=1`.

- [ ] **Step 2: Rename `ky_server_base`**

```bash
cd /home/yoshi/busness.app/ky_server_base
go test -race -count=1 ./... 2>&1 | tee /tmp/base-before.txt
grep -rl "github.com/Yoshiofthewire/ky_server_base" . | sort > /tmp/base-refs.txt
xargs -a /tmp/base-refs.txt \
  sed -i 's|github.com/Yoshiofthewire/ky_server_base|github.com/busness-app/ky_server_base|g'
grep -rn "Yoshiofthewire" . ; echo "exit=$?"
go mod tidy && gofmt -l . && go vet ./... && go test -race -count=1 ./...
git add -A && git commit -m "refactor: move module path to github.com/busness-app"
```

**`grep -rn "Yoshiofthewire"` will still match inside `docs/`** — the plans and the Shamir findings quote the old paths when describing what the state used to be. Those are history and should stay accurate. Restrict the check to code if that is noisy:

```bash
grep -rn "Yoshiofthewire" --include='*.go' --include='go.mod' --include='*.sh' .
```

- [ ] **Step 3: Confirm both**

```bash
head -1 /home/yoshi/busness.app/kysignon-server/go.mod
head -1 /home/yoshi/busness.app/ky_server_base/go.mod
```

Both must read `module github.com/busness-app/<name>`.

---

## Task 3: Rename the two lowercase-org repos

**Files:**
- Modify: `kydns-server`, `kynotes-server` — `go.mod` and every importing file

- [ ] **Step 1: Rename each**

```bash
cd /home/yoshi/busness.app
for r in kydns-server kynotes-server; do
  cd "/home/yoshi/busness.app/$r"
  go test -race -count=1 ./... > "/tmp/$r-before.txt" 2>&1
  grep -rl "github.com/yoshiofthewire/$r" . | sort > "/tmp/$r-refs.txt"
  xargs -a "/tmp/$r-refs.txt" \
    sed -i "s|github.com/yoshiofthewire/$r|github.com/busness-app/$r|g"
  go mod tidy
  gofmt -l . && go vet ./... && go test -race -count=1 ./...
  git add -A && git commit -m "refactor: move module path to github.com/busness-app"
done
```

- [ ] **Step 2: Confirm neither casing survives**

```bash
cd /home/yoshi/busness.app
grep -rn "yoshiofthewire\|Yoshiofthewire" kydns-server kynotes-server --include='*.go' --include='go.mod'
echo "exit=$?"
```

Expected: no output, `exit=1`.

---

## Task 4: Give the three bare-path repos a domain

**Files:**
- Modify: `kyrecovery-server`, `kypassword-server`, `kybookmarks-server` — `go.mod` and every importing file

These are the ones that cannot currently be imported at all, and all three are in the audit chain plan.

- [ ] **Step 1: Find how each refers to itself**

A bare module path means internal imports look like `kyrecovery-server/internal/audit` with no domain. Confirm the shape before rewriting:

```bash
cd /home/yoshi/busness.app/kyrecovery-server
grep -rho '"kyrecovery-server/[a-z/]*"' --include='*.go' . | sort -u | head
```

- [ ] **Step 2: Rename each**

```bash
for r in kyrecovery-server kypassword-server kybookmarks-server; do
  cd "/home/yoshi/busness.app/$r"
  go test -race -count=1 ./... > "/tmp/$r-before.txt" 2>&1
  # The bare name appears in import strings and in go.mod's module line. Anchor on
  # the quote and the module keyword so prose and file paths are left alone.
  grep -rl "\"$r/" --include='*.go' . | xargs -r sed -i "s|\"$r/|\"github.com/busness-app/$r/|g"
  sed -i "1s|^module $r$|module github.com/busness-app/$r|" go.mod
  go mod tidy
  gofmt -l . && go vet ./... && go test -race -count=1 ./...
  git add -A && git commit -m "refactor: give the module an importable path under github.com/busness-app

A bare module path consumes dependencies fine but cannot be imported by
anything, which blocks this repo from sharing primitives with the suite."
done
```

**Read the `sed` before running it.** Anchoring on `"<name>/` catches import strings and misses prose, but a repo that imports itself in some other shape — a `replace` directive, a build tag, a code generator's output — will not be caught. Step 3 is what proves it.

- [ ] **Step 3: Confirm each builds and declares the right path**

```bash
cd /home/yoshi/busness.app
for r in kyrecovery-server kypassword-server kybookmarks-server; do
  printf '%-22s %s\n' "$r" "$(head -1 $r/go.mod)"
  (cd "$r" && go build ./... && go test -race -count=1 ./... > /dev/null && echo "    build+tests OK")
done
```

---

## Task 5: Prove the suite is consistent

- [ ] **Step 1: Every module declares its own busness-app path**

```bash
cd /home/yoshi/busness.app
for d in */; do r=${d%/}; [ -f "$r/go.mod" ] && printf '%-22s %s\n' "$r" "$(head -1 $r/go.mod | awk '{print $2}')"; done
```

Expected, exactly:

```
gridlock-server        github.com/busness-app/gridlock-server
kybookmarks-server     github.com/busness-app/kybookmarks-server
kydns-server           github.com/busness-app/kydns-server
kynotes-server         github.com/busness-app/kynotes-server
kypassword-server      github.com/busness-app/kypassword-server
kyrecovery-server      github.com/busness-app/kyrecovery-server
ky_server_base         github.com/busness-app/ky_server_base
kysignon-server        github.com/busness-app/kysignon-server
```

- [ ] **Step 2: No old path survives in code**

```bash
grep -rn "Yoshiofthewire\|yoshiofthewire" */. --include='*.go' --include='go.mod' --include='go.sum' --include='*.sh'
echo "exit=$?"
```

Expected: no output, `exit=1`. Matches inside `docs/` are history and are fine.

- [ ] **Step 3: Every module path matches its remote**

```bash
for d in */; do r=${d%/}; [ -f "$r/go.mod" ] || continue
  m=$(head -1 "$r/go.mod" | awk '{print $2}')
  o=$(git -C "$r" remote get-url origin 2>/dev/null || echo "NO-ORIGIN")
  printf '%-22s %-45s %s\n' "$r" "$m" "$o"
done
```

The org in each `go.mod` must match the org in each `origin`. `gridlock-server` shows `NO-ORIGIN` unless Task 1 Step 5 was resolved.

---

## What this plan deliberately does not do

- **It does not rename any GitHub repository or create any remote.** Only Go module paths. `gridlock-server` having no remote is raised in Task 1 Step 5 as a question for the human, not an action.
- **It does not change behaviour anywhere.** Every commit here is a pure rename, and each has a verification step that fails if the diff contains anything else.
- **It does not touch the client repos.** `kypost-Linux`, `kypost-for-Mac`, `kyauth-android` and the rest are not Go modules and have no module path to migrate.
