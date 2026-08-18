# SSO

## Purpose
Provides unified Single Sign-On federation for KySignOn, Generic OpenID Connect (Google, Microsoft Entra ID, Okta, Keycloak), and SAML 2.0 Service Provider (SP).

## Ownership
Owns OIDC PKCE authorization flows, ID token claims extraction, KySignOn HMAC-SHA256 signed directory sync webhooks, and SAML metadata/assertion processing.

## Local Contracts
- `KySignOnClient.HandleSyncWebhook` verifies HMAC-SHA256 signatures before modifying local user state.
- PKCE with `S256` is enforced on all OAuth/OIDC authorization requests.

## Verification
- `go test -v ./internal/sso/...`

## Child DOX Index
None.
