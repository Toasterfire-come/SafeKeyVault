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

## Browser extension checks

Manual verification:
- extension loads in Chromium from unpacked directory
- popup opens and can connect via WebHID
- content script can detect basic login forms
- only background script performs privileged HID operations

Security checks:
- no `eval`/remote code
- minimal permissions
- no direct page JS to HID path

