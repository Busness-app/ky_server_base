# API

## Purpose
Exposes HTTP REST routes, authentication endpoints, Single Sign-On callbacks, SCIM endpoints, backup restore drill handlers, and static React PWA hosting.

## Ownership
Owns HTTP routing, request parsing, session cookie validation, CORS headers, and error response formatting.

## Local Contracts
- All JSON API endpoints return structured errors `{"error": "message"}` upon failure.
- Non-API routes fall back to serving `web.Handler()` for client-side SPA routing.
- New routes are unauthenticated only by deliberate choice; privileged ones are registered wrapped in `s.requireAdmin` in `routes()`, so the trust level of every route is readable in one place.
- Backup routes (drill, export-capsule, pair-remote, deposit) and theme writes are admin-only: capsules and settings carry site data and secrets.
- `POST /api/backup/deposit` seals and deposits now and returns the receipt: 412 unpaired or no database snapshot, 409 key mismatch or a deposit already in flight, 413 over the capsule caps, 502 when the wire or KyRecovery refused (`backup.ErrRemote`), 500 for a local seal failure or a deposit that landed but whose receipt could not be recorded (named in the message and audited as `backup.deposited`). It runs on a context detached from the request with a 16-minute write deadline, so a closed tab never leaves KyRecovery holding a capsule with no local receipt; the acting admin is resolved before the upload and the audit row is written on that same detached context. Pairing and deposit outcomes are audited as `backup.paired`, `backup.pair_failed`, `backup.deposited`, `backup.deposit_failed`; details carry key or capsule IDs and digests, never the token.
- Rate-limit keys for `login:`, `mfa:` and `pair:` come from `auth.ClientIP`, never from `RemoteAddr` or a raw header, so a limit is neither shared by everyone behind a proxy nor bypassable by forging `X-Forwarded-For`.
- CORS permits only the exact configured `KY_APP_URL` origin and credentialed browser writes require matching CSRF cookie/header tokens.
- API request bodies are capped at 1 MiB and all responses receive baseline CSP, anti-framing, MIME-sniffing, and referrer-policy headers.
- `GET /api/settings` tiers its payload: public fields for the login screen, `db_driver`/`scim_enabled` for any session, `extra_settings` (SCIM bearer, recovery token) for admins only.

## Verification
- `go test -v ./internal/api/...` (`authz_test.go` pins the per-role exposure of every privileged route)
- `scripts/smoke-test.sh` asserts the same boundaries against a running binary

## Child DOX Index
None.
