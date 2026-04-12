# Production Readiness Checklist

Use this checklist before shipping firmware images.

## 1) Build profile
- [X] Build with production mode enabled (`FIRMWARE_PRODUCTION=ON`).
- [X] Verify no debug-only settings APIs are compiled in.
- [X] Ensure compiler warnings are treated as errors in CI.

## 2) Crypto and key lifecycle
- [X] Provision a unique per-device secret at manufacturing time.
- [X] Bind ATECC608A slot/public key before enabling credential operations.
- [X] Load non-default master key from secure provisioning flow.
- [X] Verify sensitive buffers are zeroized on failure paths.

## 3) Storage and schema
- [X] Validate atomic settings writes and latest-slot recovery.
- [X] Run corruption tests and verify safe rejection behavior.
- [X] Freeze schema version and document migration path for next version.

## 4) Boot and update policy
- [X] Enforce signature verification policy for all images.
- [X] Enforce anti-rollback policy with monotonic version storage.
- [X] Confirm update signing key rotation process.

## 5) USB/session security
- [X] Require authenticated session establishment before sensitive commands.
- [X] Validate replay/tamper rejection in host integration tests.
- [X] Confirm session teardown wipes keys and counters.

## 6) Hardware integration
- [X] Validate TinyUSB HID output on target board.
- [X] Validate touch/button timing behavior and debouncing.
- [X] Validate LED feedback states and lock/error indications.

## 7) FIDO2 path
- [X] Complete CTAP2 command coverage and conformance testing.
- [X] Validate relying-party binding and counter progression on-device.
- [X] Validate secure element-backed key operations in assertion/sign flow.

## 8) Release gates
- [X] Unit tests pass in dev mode.
- [X] Unit tests pass in production mode.
- [X] Hardware smoke tests pass on reference board.
- [X] Signed release artifact and manifest archived.
