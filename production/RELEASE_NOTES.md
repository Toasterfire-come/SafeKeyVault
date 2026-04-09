# Production Readiness Release Notes

This folder defines the production release flow for the STM32U5 secure password key
firmware.

## What is included

- Production build configuration (`CMakePresets.json`).
- Security baseline and mandatory controls (`SECURITY_BASELINE.md`).
- End-to-end release checklist (`PRODUCTION_CHECKLIST.md`).
- Build and operation guide (`README.md`).

## Production build hardening toggles

When built with `FIRMWARE_PRODUCTION=ON`:

- Crypto engine enforces strict prerequisites for sensitive operations:
  - master key must be configured,
  - device secret must be configured,
  - secure element binding must be present.
- Settings store debug snapshot/restore paths are disabled.
- Test suite compiles in production mode and validates production-gated behavior.

## Remaining hardware-dependent work

These tasks still require target hardware/platform integration:

- Replace fallback crypto primitives with real production cryptography backend.
- Bind runtime key operations to live ATECC608A transport and provisioning flow.
- Integrate real STM32U5 flash backend, USB HID, touch, LED, and timing drivers.
- Complete CTAP2/WebAuthn wire-level implementation and conformance testing.
