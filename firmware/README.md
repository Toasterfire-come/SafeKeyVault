# RP2040 Custom Firmware (Scaffold)

This directory contains a host-testable firmware core scaffold for the RP2040 password key.

## Security behavior included

- Password policy minimum length set to **8** characters.
- Common password detection and reuse detection hooks.
- Origin-bound record validation for safe credential mapping.
- **Single button press** triggers password fill from the current selected credential.
- **Button hold** opens device settings/password-modify popup mode.
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
- UI interaction model is intentionally simple: one press to fill, one hold to open settings/modify.
