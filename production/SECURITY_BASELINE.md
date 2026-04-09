# Production Security Baseline

This file defines the minimum required production controls for this firmware.

## Build mode

- Build with `-DFIRMWARE_PRODUCTION=ON`.
- Production mode enforces stricter crypto engine readiness checks.
- Settings debug snapshot/restore helpers are disabled in production build.

## Cryptography and keys

- `crypto_engine_set_master_key()` must be called during secure boot/provisioning.
- `crypto_engine_set_device_secret()` must be called with per-device entropy.
- ATECC slot binding via `crypto_engine_bind_atecc_slot()` must succeed before
  handling sensitive operations in production mode.
- Key material and temporary buffers must be zeroized after use.

## USB/session channel

- Require successful session authentication before processing sensitive requests.
- Reject replayed or tampered payloads.

## Secure boot/update

- Enable signature enforcement and anti-rollback policy before accepting images.
- Keep minimum version threshold and current version monotonic.

## Storage

- Use atomic storage writes and latest-valid-record reads.
- Reject schema mismatches and corrupted payloads.
- Ensure encrypted settings payloads pass tag/auth checks before use.

