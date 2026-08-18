# API

## Purpose
Exposes HTTP REST routes, authentication endpoints, Single Sign-On callbacks, SCIM endpoints, backup restore drill handlers, and static React PWA hosting.

## Ownership
Owns HTTP routing, request parsing, session cookie validation, CORS headers, and error response formatting.

## Local Contracts
- All JSON API endpoints return structured errors `{"error": "message"}` upon failure.
- Non-API routes fall back to serving `web.Handler()` for client-side SPA routing.

## Verification
- `go test -v ./internal/api/...`

## Child DOX Index
None.
