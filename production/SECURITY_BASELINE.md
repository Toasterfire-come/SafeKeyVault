# Production Security Baseline

This file defines the minimum required production controls for this firmware.

## Build mode

- Build with `-DFIRMWARE_PRODUCTION=ON`.
- Production mode enforces stricter crypto engine readiness checks and critical failures result in `Error_Handler` calls.
- Settings debug snapshot/restore helpers are disabled in production build.
- Compiler warnings are treated as errors (`-Wall -Werror`).

## Cryptography and keys

- Master key provisioning: `crypto_engine_set_master_key_slot_ready()` should only be called after the master key is securely provisioned in `ATECC608A_SLOT_MASTER_KEY` on the ATECC.
- Device secret provisioning: `crypto_engine_set_device_secret()` must be called with per-device entropy and successfully write to `ATECC608A_SLOT_DEVICE_SECRET`.
- ATECC slot binding via `crypto_engine_bind_atecc_slot()` must succeed before handling sensitive operations in production mode.
- All key material and sensitive temporary buffers are securely zeroized after use using `security_secure_zero()`.
- Nonce generation for encryption functions integrates device-unique secrets where possible and monotonic counters.

## Secure Boot and Update

- Firmware images must be signed using ECDSA P-256.
- Signature verification is performed against a public key stored securely.
- The firmware signature is read from the last flash sector using SPI HAL.
- An anti-rollback mechanism is enforced using a version counter stored in `ATECC608A_SLOT_VERSION_COUNTER` (slot 7).
- Firmware with a version strictly lower than the stored counter is rejected. Re-flashing the *current* running version is allowed if it matches the stored and current version.
- Failure to read or write the anti-rollback counter in production results in `Error_Handler`.

## USB/session channel

- Require successful session authentication via `usb_session_start()` and `usb_session_authenticate()` before processing sensitive commands.
- Replay attacks are mitigated by checking `nonce` values (`cmd->nonce > g_last_nonce`).
- Tampering is detected using authenticated encryption (AEAD) with message authentication codes (MACs).
- USB disconnect (from `HAL_PCD_DisconnectCallback`) immediately locks the device via `state_machine_lock()`.

## Storage

- Atomic storage writes (`storage_backend_write_atomic()`) and latest-valid-record reads (`storage_backend_read_latest()`) are used.
- Schema mismatches and corrupted (CRC invalid) payloads are rejected (`settings_store_load()`).
- Encrypted settings and TOTP payloads pass tag/authentication checks before use via AEAD.
- All credential and sensitive data buffers are zeroized after use.
- `storage_backend_wipe()` securely zeroes internal state.

## FIDO2

- Authenticator attestation utilizes secure element-backed key generation (`crypto_engine_generate_ec_keypair()`) and secure key storage.
- FIDO2 assertions involve signing `clientDataHash` and `authenticatorData` using a private key stored in `ATECC608A_SLOT_FIDO_PRIVKEY` (slot 3).
- Relying Party ID hash and User Hash are verified (`fido2_get_assertion()`).
- `signCount` is a strictly monotonic counter incremented by the authenticator (`g_fido2.sign_counter`).
