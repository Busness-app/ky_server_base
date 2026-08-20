# API

## Purpose
Exposes HTTP REST routes, authentication endpoints, Single Sign-On callbacks, SCIM endpoints, backup restore drill handlers, and static React PWA hosting.

## Ownership
Owns HTTP routing, request parsing, session cookie validation, CORS headers, and error response formatting.

## Local Contracts
- All JSON API endpoints return structured errors `{"error": "message"}` upon failure.
- Non-API routes fall back to serving `web.Handler()` for client-side SPA routing.
- New routes are unauthenticated only by deliberate choice; privileged ones are registered wrapped in `s.requireAdmin` in `routes()`, so the trust level of every route is readable in one place.
- Backup routes (drill, export-kit, pair-remote) and theme writes are admin-only: capsules and settings carry site data and secrets.
- CORS still answers with a wildcard origin; see the `FIXME(security)` in `ServeHTTP` before exposing this server to untrusted origins.
- `GET /api/settings` tiers its payload: public fields for the login screen, `db_driver`/`scim_enabled` for any session, `extra_settings` (SCIM bearer, recovery token) for admins only.

## Verification
- `go test -v ./internal/api/...` (`authz_test.go` pins the per-role exposure of every privileged route)
- `scripts/smoke-test.sh` asserts the same boundaries against a running binary

## Child DOX Index
None.
