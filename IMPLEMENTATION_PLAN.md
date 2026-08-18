# Ky Server Base - Implementation Plan

`ky_server_base` is the foundational starter and scaffold for all **Busnes.app** products within the KySecurity ecosystem.

## Core Requirements (from prompt.md)

1. **Base Scaffold**: Clean, modular Go backend + embedded React 19/TypeScript frontend starter.
2. **Cloud Mobile First**: PWA with Service Worker + native web wrapper support using 90-second ephemeral QR device pairing tech.
3. **SSO Support**: Full support for all normal SSO providers (Google, Microsoft 365, Okta, Keycloak, generic OIDC, SAML 2.0) and KySignOn with webhook replication.
4. **KyBackup as Feature 0**: Encrypted backup capsules, Shamir secret splitting, restore drill verification compatible with `kyrecovery-server`'s `ServiceAdapter`.
5. **SCIM 2.0 Provisioning**: RFC 7643 & RFC 7644 compliance (`/scim/v2/Users`, `/scim/v2/Groups`) for inbound enterprise directory sync.
6. **Swapping DBs on Demand**: Pluggable storage abstraction supporting SQLite (default, zero-CGO) and PostgreSQL (for clustered heavy enterprise workloads) with automated migrations.
7. **KySecurity Design System**: Space Grotesk & IBM Plex Mono typography with dynamic theme selector (Patina Ky, Cyber, Nord, Paper, OLED).

---

## Phase Breakdown

### Phase 1: Storage Layer & Pluggable Database Abstraction (DAL) [DONE]
- [x] Initialize `go.mod` (`ky_server_base`)
- [x] Configuration manager (`internal/config`) supporting SQLite & PostgreSQL
- [x] Storage interfaces (`internal/store/store.go` for Users, Sessions, Devices, SSO, SCIM, Audit, Settings)
- [x] SQLite backend (`internal/store/sqlstore.go`) with WAL mode & foreign keys
- [x] PostgreSQL backend (`internal/store/sqlstore.go`)
- [x] Schema migrations runner (`internal/store/migrations`)
- [x] Automated tests for database operations across dialects

### Phase 2: Authentication, SSO Engine & SCIM 2.0 [DONE]
- [x] Local auth & password management (Argon2id, brute-force rate limiting, PoW/Turnstile CAPTCHA)
- [x] Multi-Factor Authentication (RFC 6238 TOTP with AES-256-GCM encryption, recovery codes, push approval)
- [x] SSO Engine:
  - [x] KySignOn OIDC + PKCE + signed sync webhooks
  - [x] Generic OIDC/OAuth2 discovery and verification
  - [x] SAML 2.0 Service Provider (SP metadata & ACS)
- [x] SCIM 2.0 server (`/scim/v2/ServiceProviderConfig`, `/scim/v2/Schemas`, `/scim/v2/Users`, `/scim/v2/Groups`)

### Phase 3: Feature 0 — KyBackup & KyRecovery Integration [DONE]
- [x] AES-256-GCM encrypted backup capsule generator (`internal/backup/capsule.go`)
- [x] Shamir Secret Sharing $(k, n)$ threshold split keys (`internal/backup/shamir.go`)
- [x] Zero-Code pairing claim and self-declaring backup push client (`internal/backup/client.go`)
- [x] Automated self-test restore drill runner with SQLite integrity validation (`internal/backup/drill.go`)
- [x] Emergency offline printable HTML Recovery Kit generator (`internal/backup/recovery_kit.go`)

### Phase 4: Mobile-First PWA, Ephemeral QR Pairing & KySecurity Themes [DONE]
- [x] React 19 + TypeScript + Vite frontend with PWA manifest & Service Worker (`web/`)
- [x] Ephemeral 90-second QR device pairing modal (`/api/devices/pair/*` and `web/src/components/QRPairingModal.tsx`)
- [x] KySecurity color palette tokens (`web/src/styles/theme.css`) and dynamic theme switcher (`ThemeSwitcher.tsx`)
- [x] User & Admin dashboard components (Overview, Directory & SCIM, KyBackup, Settings)

### Phase 5: Verification, Packaging & DOX Closeout [DONE]
- [x] End-to-end integration test suite (`go test ./...`)
- [x] Multi-stage Dockerfile and Docker Compose configurations
- [x] Developer CLI tooling (`init-admin`, `backup-drill`, `export-recovery-kit`, `version`)
- [x] Complete DOX documentation hierarchy across all subtrees
