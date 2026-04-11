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

## Production build tests

- Build with production profile:
  - `cmake -S firmware -B firmware/build-prod -DCMAKE_TOOLCHAIN_FILE=<path_to_your_stm32_toolchain_file>`
  - `cmake --build firmware/build-prod`
- Run tests in production mode:
  - `ctest --test-dir firmware/build-prod --output-on-failure`
- Verify production-specific hardening:
  - Crypto engine requires master key, device secret, and secure element binding.
  - Debug interfaces (snapshot/restore) are disabled.
  - All sensitive operations are gated by these prerequisites.

## Hardware integration tests

- Flash firmware to STM32U5 board.
- Verify USB enumeration as HID device.
- Test all interactive workflows:
  - PIN entry and unlock.
  - Credential save, fill, generate.
  - Settings access and modification.
  - Touch authentication prompts.
- Verify LED feedback for all states (locked, unlocked, error, typing, etc.).
- Test FIDO2/WebAuthn flows with a compatible relying party.
- Test TOTP code generation and copy functionality.
- Stress test with rapid commands and long-running operations.
- Verify air-gap security: no external communication beyond USB HID.
