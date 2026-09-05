# ky_server_base

The scaffold every Busnes.app server is built from: Go backend, embedded React PWA, SQLite or
PostgreSQL, local and federated sign-in (KySignOn, OIDC, SAML), SCIM provisioning, and
disaster recovery through the suite's KyRecovery.

```bash
make ci        # gofmt, vet, race tests, smoke test
make run       # build and start on :8080; first start prints the bootstrap admin password
docker compose up -d
```

`AGENTS.md` is the contract for working in this repository.

## Disaster recovery

Every backup is one `.kycap` capsule: the database snapshot, the deployment's encryption key,
the settings that describe the deployment, and the pinned suite recovery public key. It is
sealed to the suite recovery key, which only the custodians' cards (k of n, split at the suite
ceremony) can reconstruct. Nothing on this server, and nothing on KyRecovery, can open one.
The mechanics are `github.com/Busness-app/ky-primitives/recoveryclient`; this repository
supplies what it seals and how it checks a drill.

The admin screen **Backup & recovery** shows four facts (recovery key, KyRecovery, local
copies, schedule) and the actions: Back up now, Download capsule, Run restore drill, the
schedule, pairing with Unpair, and pinning the key by hand.

### Two ways to get a key

- **Pair with KyRecovery.** Its dashboard issues a six-digit code; entering it here hands this
  server the suite public key and a deposit credential. The key is pinned once and never
  replaced: a later pairing that returns a different key is refused.
- **Pin the key by hand.** For a server with no KyRecovery: paste the base64 public key the
  ceremony page shows, with its k-of-n. Capsules then go only to the local directory.

### Why TLS matters here

The capsule is sealed, so a copy of it is worthless to an eavesdropper. What the wire does
carry is the suite public key at pairing (trust on first use), the deposit credential, and
each receipt. A man in the middle at pairing could substitute a key whose shares they hold,
so pairing over plain HTTP is refused outright, and a pairing across your own network should
be checked: compare the key ID on the screen with the ceremony card, or pin the key by hand
and skip the question.

### One run, every destination

Back up now, the schedule and the `deposit` command all do the same thing: seal one capsule
and deliver it to every configured destination. A pinned key with no destination is refused
with a message that says so. A local write that fails does not stop the deposit, and a
refused deposit does not remove the local copy.

### Environment

| Variable | Default | Meaning |
|---|---|---|
| `KY_BACKUP_DIR` | empty (off) | Directory for sealed local copies, `<escaped app name>.<capsule-id>.kycap` at mode 0600 (`Busnes_2eapp.cap-Busnes.app-<n>.kycap` by default: bytes outside `[A-Za-z0-9-]` in the app name are hex-escaped). Pruning removes only this application's own prefix. |
| `KY_BACKUP_KEEP` | `7` | Local copies to retain; below 1 refuses startup. |
| `KY_BACKUP_DEPOSIT_INTERVAL` | `24h` | Default schedule only. The admin screen's setting wins; `0` is off; 15 minutes to 366 days otherwise. |
| `KY_BACKUP_ALLOW_PRIVATE_RECOVERY` | `false` | Admit a KyRecovery on an RFC1918 or CGNAT address behind your own TLS proxy. Loopback, link-local and other reserved ranges stay refused; HTTPS stays required. Logged at startup and on the pairing audit row. |
| `KY_DNS` | unset | Only in `docker-compose.lan-dns.yml`: the container's resolver, for names that exist only on your LAN. |

Reach a KyRecovery that only your LAN's DNS knows:

```bash
KY_BACKUP_ALLOW_PRIVATE_RECOVERY=true KY_DNS=192.168.1.1 \
  docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml up -d --force-recreate
docker inspect ky_server_base --format '{{.HostConfig.Dns}}'   # [192.168.1.1]
```

Setting `KY_DNS` in `.env` alone does nothing; the override file must be named.

### Upgrading from plaintext local backups

Earlier builds wrote unencrypted backups into `KY_BACKUP_DIR`. The variable keeps its name and
now means sealed capsules. Retention deliberately never touches files it did not write, so old
plaintext backups stay where they are: move them out of the directory, keep them until a
restore from a capsule has been proven, then remove them securely. They are the live
directory in the clear.

### Restoring

`docs/RESTORE.md` is the runbook: opening a capsule with the custodians' cards, putting the
result in service, and what to distrust afterwards. Drill it once a quarter with real cards.
