# Test Plan

## Firmware host tests

- Build:
  - `cmake -S firmware -B firmware/build`
  - `cmake --build firmware/build`
- Run:
  - `ctest --test-dir firmware/build --output-on-failure`

Coverage includes:
- lockout and wipe behavior
- settings roundtrip and persistence checksum
- password policy and generator
- vault operations
- action engine save/fill/generate/select
- single-button press/hold model behavior
- UI feedback mapping
- command codec + rate limiter + constant-time compare checks

## Device-only workflow checks

Manual verification:
- plug device over USB-C and confirm standard HID keyboard enumeration
- unlock with 5-digit PIN from on-device input path
- press once to trigger password fill for active site context
- press once with unknown/absent site context and verify settings popup opens instead of fill
- hold press to open settings/modify popup on-device
- from popup, change password/settings and confirm persistence and updated fill output

Security checks:
- no dependency on browser extension or host companion app
- all sensitive actions are bound to one press (fill) or hold (settings/modify)
- lockout/wipe/autolock behavior remains enforced

