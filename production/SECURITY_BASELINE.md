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

## Secure Boot and Update

- Firmware images must be signed using ECDSA P-256.
- Signature verification is performed against a public key stored securely.
- The firmware signature is read from the last flash sector using SPI HAL.
- An anti-rollback mechanism is enforced using a version counter stored in ATECC608A slot 7.
- Firmware with a version lower than the stored counter is rejected.
- The minimum allowed firmware version can be configured via policy.

## USB/session channel

- Require successful session authentication before processing sensitive commands.
- Reject replayed or tampered payloads.
- USB disconnect immediately locks the device.

## Storage

- Use atomic storage writes and latest-valid-record reads.
- Reject schema mismatches and corrupted payloads.
- Ensure encrypted settings payloads pass tag/auth checks before use.
- All credential and sensitive data buffers are zeroized after use.
