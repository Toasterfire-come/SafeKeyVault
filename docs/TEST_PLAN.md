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
- auto-popup/manual-popup behavior
- UI feedback mapping
- command codec + rate limiter + constant-time compare checks

## Device-only workflow checks

Manual verification:
- plug device over USB-C and confirm standard HID keyboard enumeration
- unlock with 5-digit PIN from on-device input path
- save credential via on-device flow and confirm touch/hold authorization
- fill current-site credential through on-device action (touch-gated typing)
- generate password on-device for new origin and save via hold confirmation
- select next credential using hold gesture and verify next fill behavior

Security checks:
- no dependency on browser extension or host companion app
- all sensitive actions require physical interaction
- lockout/wipe/autolock behavior remains enforced

