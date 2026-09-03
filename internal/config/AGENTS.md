# Config

## Purpose
Manages environment and file-based configuration loading, defaults, and type conversions for ky_server_base.

## Ownership
Owns environment variable parsing, configuration validation, default fallbacks, and security key generations.

## Local Contracts
- `LoadFromEnv() (*Config, error)` must supply safe, valid defaults for all subsystems.
- Never log plaintext secrets or sensitive tokens.
- Production startup requires an explicit, durable `KY_SESSION_SECRET`. The encryption key comes from `KY_ENCRYPTION_KEY` when set, otherwise from the keyfile at `<DataDir>/encryption.key`, which `keyfile.LoadOrCreate` mints on first start; either is a valid production configuration.

## Verification
- `go test -v ./internal/config/...`

## Child DOX Index
None.
