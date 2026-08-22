# Config

## Purpose
Manages environment and file-based configuration loading, defaults, and type conversions for ky_server_base.

## Ownership
Owns environment variable parsing, configuration validation, default fallbacks, and security key generations.

## Local Contracts
- `LoadFromEnv() (*Config, error)` must supply safe, valid defaults for all subsystems.
- Never log plaintext secrets or sensitive tokens.
- Production startup requires explicit, durable `KY_SESSION_SECRET` and `KY_ENCRYPTION_KEY` values.

## Verification
- `go test -v ./internal/config/...`

## Child DOX Index
None.
