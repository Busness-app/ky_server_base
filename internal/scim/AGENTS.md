# SCIM

## Purpose
Implements RFC 7643 and RFC 7644 SCIM 2.0 protocol for enterprise inbound user and group provisioning from Okta, Azure AD / Microsoft Entra ID, OneLogin, and KySignOn.

## Ownership
Owns `/scim/v2/Users`, `/scim/v2/Groups`, `/scim/v2/ServiceProviderConfig`, `/scim/v2/Schemas`, and `/scim/v2/ResourceTypes` endpoints and SCIM Bearer token authentication.

## Local Contracts
- Content-Type for all SCIM endpoints must be `application/scim+json`.
- Requests must be authenticated with the configured bearer token.
- User de-provisioning via `PATCH` with `active: false` updates user status to `inactive`.

## Verification
- `go test -v ./internal/scim/...`

## Child DOX Index
None.
