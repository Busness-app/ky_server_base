# Suite Repo Plans: Index and Sequencing

The [suite shared primitives plan](2026-09-02-suite-shared-primitives.md) covers nine
repositories in one document. This index splits the work that remains into plans that
can each be executed, reviewed and reverted on their own.

`ky_server_base`'s own work — Task 6, cutting the scaffold to three direct dependencies —
stays in the parent plan. Everything here is the other repos.

## The plans

| Plan | Repos | Blocked by |
|---|---|---|
| [Module path migration](2026-09-02-module-path-migration.md) | all eight Go repos | nothing |
| [Capsule format interop](2026-09-02-capsule-format-interop.md) | shared gate | `ky-primitives` exists |
| [kysignon-server migration](2026-09-02-kysignon-server-migration.md) | `kysignon-server` | capsule gate, for its Task 3 only |
| [gridlock-server migration](2026-09-02-gridlock-server-migration.md) | `gridlock-server` | capsule gate, for its Task 3 only |
| [Audit chain convergence](2026-09-02-audit-chain-convergence.md) | `kyrecovery-server`, `kypassword-server`, `kybookmarks-server` | `ky-primitives` exists |
| [Pairing spec, one home](2026-09-02-pairing-spec-one-home.md) | all nine, plus a loose copy | nothing |

## Why the audit work is one plan and not three

Every other plan here is per-repo. The audit chain is not, because its entire purpose is
that three products end up chaining records the same way. Three separate plans would let
three executors pick three targets, which is how there came to be four implementations.
Inside it, each repo's tasks are still independently executable and revertible.

## Sequencing

**First, and blocking almost everything:** the module path migration. The suite moved to
`github.com/busness-app/` and no `go.mod` followed. `ky-primitives` cannot be tagged until
its path is settled, three repos cannot be imported at all until they have a domain, and
`gridlock-server` still claims the scaffold's identity. It is eight pure renames with no
behaviour change.

**In parallel, no dependencies:** the pairing spec plan. It is documentation only and
touches no module path.

**Then, once `ky-primitives` exists** (parent plan Task 2): the capsule gate, and the
Shamir halves of the two migration plans, which can run in parallel — they are separate
repositories with no shared state.

**Last:** the capsule halves of both migrations, gated on the shared package opening all
three products' capsules.

## What measurement changed

Three of these plans exist because the parent plan's assumptions did not survive being
checked. The corrections, with what proved each:

- **The capsule gate fails where the Shamir gate passed.** `ky_server_base` and
  `gridlock-server` write ciphertext in `base64.RawURLEncoding`; `kysignon-server` writes
  `base64.StdEncoding`. Cross-decoding fails in both directions with `illegal base64
  data`. The parent plan's instruction to port the capsule from `kysignon-server` alone
  would have left two products unable to open their own backups.
- **`gridlock-server` and `ky_server_base` do not "already share an implementation."**
  True of `shamir.go`, false of `capsule.go` — 49 lines apart, and three distinct md5s
  across the three repos.
- **`kysignon-server` has no audit hash chain**, so the parent plan's choice of donor
  "`kyrecovery-server` or `kysignon-server`" has one candidate.
- **`kypassword-server`'s audit chain is unkeyed** and can therefore be forged by anyone
  who can write the audit file. This is the only genuine security defect the split turned
  up.
- **The pairing spec drift is not purely additive**, which trips the parent plan's
  escalation gate — but the server's own code resolves it without a human decision.
- **No `go.mod` followed the move to `github.com/busness-app/`.** Four conventions are in
  use, including one repo claiming another's identity. See below.

## The module path question is now answered

The suite has moved to `github.com/busness-app/`. The remotes went; the module paths did
not:

```
go.mod says                                    origin says
github.com/Yoshiofthewire/ky_server_base       Busness-app/ky_server_base
github.com/Yoshiofthewire/ky_server_base       (no origin)          <- gridlock-server
github.com/Yoshiofthewire/kysignon-server      Busness-app/kysignon-server
github.com/yoshiofthewire/kydns-server         Busness-app/kydns-server
github.com/yoshiofthewire/kynotes-server       Busness-app/kynotes-server
kybookmarks-server                             Busness-app/kybookmarks-server
kypassword-server                              Busness-app/kypassword-server
kyrecovery-server                              Busness-app/kyrecovery-server
```

[The module path migration plan](2026-09-02-module-path-migration.md) fixes all eight.

**One thing to confirm: the case.** These plans use `github.com/busness-app/` in lowercase,
as written in the instruction to make the move. The GitHub remotes render as
`Busness-app`. GitHub does not care, but **Go module paths are case-sensitive** — an
uppercase letter is escaped as `!b` in the module cache and on the proxy, so
`github.com/busness-app/x` and `github.com/Busness-app/x` are two different modules to the
toolchain. The suite already has this exact inconsistency today, with `yoshiofthewire`
and `Yoshiofthewire` both in use.

Lowercase is the safer default and is what is written throughout. Nothing is implemented
yet, so switching is a one-line change across these plans — but it is much more expensive
after eight repos have been renamed.
