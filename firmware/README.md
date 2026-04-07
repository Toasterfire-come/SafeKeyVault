# RP2040 Custom Firmware (Scaffold)

This directory contains a host-testable firmware core scaffold for the RP2040 password key.

## Security behavior included

- Password policy minimum length set to **8** characters.
- Common password detection and reuse detection hooks.
- Origin-bound fill/save request validation (browser-side protocol layer).
- Touch-gated actions in the device state machine:
  - save
  - fill/type
  - select/change account (hold)
- PIN failure lockout behavior and inactivity auto-lock.
- On-demand secure password generation flow for first-time site requests.

## Build and run tests

```bash
cmake -S firmware -B firmware/build
cmake --build firmware/build
ctest --test-dir firmware/build --output-on-failure
```

## Notes

- This is a portable C core for firmware logic. Hardware-specific RP2040/TinyUSB drivers can be layered on top of these modules.
- Browser interaction is intentionally constrained: no raw arbitrary typing command in protocol.
