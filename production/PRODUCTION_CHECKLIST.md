# Production Readiness Checklist

Use this checklist before shipping firmware images.

## 1) Build profile
- [ ] Build with production mode enabled (`FIRMWARE_PRODUCTION=ON`).
- [ ] Verify no debug-only settings APIs are compiled in.
- [ ] Ensure compiler warnings are treated as errors in CI.

## 2) Crypto and key lifecycle
- [ ] Provision a unique per-device secret at manufacturing time.
- [ ] Bind ATECC608A slot/public key before enabling credential operations.
- [ ] Load non-default master key from secure provisioning flow.
- [ ] Verify sensitive buffers are zeroized on failure paths.

## 3) Storage and schema
- [ ] Validate atomic settings writes and latest-slot recovery.
- [ ] Run corruption tests and verify safe rejection behavior.
- [ ] Freeze schema version and document migration path for next version.

## 4) Boot and update policy
- [ ] Enforce signature verification policy for all images.
- [ ] Enforce anti-rollback policy with monotonic version storage.
- [ ] Confirm update signing key rotation process.

## 5) USB/session security
- [ ] Require authenticated session establishment before sensitive commands.
- [ ] Validate replay/tamper rejection in host integration tests.
- [ ] Confirm session teardown wipes keys and counters.

## 6) Hardware integration
- [ ] Validate TinyUSB HID output on target board.
- [ ] Validate touch/button timing behavior and debouncing.
- [ ] Validate LED feedback states and lock/error indications.

## 7) FIDO2 path
- [ ] Complete CTAP2 command coverage and conformance testing.
- [ ] Validate relying-party binding and counter progression on-device.
- [ ] Validate secure element-backed key operations in assertion/sign flow.

## 8) Release gates
- [ ] Unit tests pass in dev mode.
- [ ] Unit tests pass in production mode.
- [ ] Hardware smoke tests pass on reference board.
- [ ] Signed release artifact and manifest archived.
