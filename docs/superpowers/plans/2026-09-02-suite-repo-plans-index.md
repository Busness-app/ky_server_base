# Suite Repo Plans: Index and Sequencing

The [suite shared primitives plan](2026-09-02-suite-shared-primitives.md) covers nine
repositories in one document. This index splits the work that remains into plans that
can each be executed, reviewed and reverted on their own.

`ky_server_base`'s own work — Task 6, cutting the scaffold to three direct dependencies —
stays in the parent plan. Everything here is the other repos.

## The plans

| Plan | Repos | Blocked by |
|---|---|---|
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

**Start now, no dependencies:** the pairing spec plan. It is documentation, it touches
every repo, and it is the only plan here that is not waiting on `ky-primitives`.

**Then, once `ky-primitives` exists** (parent plan Task 2): the capsule gate, and the
Shamir halves of the two migration plans, which can run in parallel — they are separate
repositories with no shared state.

**gridlock-server's module rename is its own prerequisite.** That repo declares
`module github.com/Yoshiofthewire/ky_server_base` and 32 of its Go files import under
that prefix. The rename must land alone, before anything else touches the repo, or every
later diff is buried in it.

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
- **The module prefix is `github.com/Yoshiofthewire/`, not `github.com/Busness-app/`**,
  and four different conventions are in use across the suite. See below.

## An unresolved question: module paths

Not planned here, because it needs a decision rather than an implementation. The suite
currently uses four conventions:

```
github.com/Yoshiofthewire/ky_server_base       ky_server_base
github.com/Yoshiofthewire/ky_server_base       gridlock-server   <- collision
github.com/Yoshiofthewire/kysignon-server      kysignon-server
github.com/yoshiofthewire/kydns-server         kydns-server      <- lowercase
github.com/yoshiofthewire/kynotes-server       kynotes-server    <- lowercase
kybookmarks-server                             kybookmarks-server <- no domain
kypassword-server                              kypassword-server  <- no domain
kyrecovery-server                              kyrecovery-server  <- no domain
```

The gridlock collision is planned, because it blocks that repo's migration. The rest is
not urgent: a bare module path still consumes external modules fine, it only prevents the
repo from being imported. But `ky-primitives` is about to be imported by several of these,
and picking its path means picking the convention. **Worth deciding before the parent
plan's Task 2 tags v0.1.0.**
