# Devices

## Purpose
Manages 90-second ephemeral QR-code device pairing protocols and push notification client registration.

## Ownership
Owns ephemeral PIN code generation, QR payload creation, device verification, and push token linking.

## Local Contracts
- Pairing codes are 6-digit random PINs with strict 90-second TTL (`InitPairing`).
- Expired or claimed codes are invalidated immediately.

## Verification
- `go test -v ./internal/devices/...`

## Child DOX Index
None.
