# Firmware Architecture (Current)

## Core modules

- `state_machine`: lock/unlock, lockout/wipe progression, touch transitions.
- `action_engine`: executes validated browser commands with touch/hold confirmation.
- `password_store` + `vault`: credential storage helpers and wipe path.
- `security_policy`: password checks (min length 8, common/reuse warning paths).
- `browser_protocol`: origin and command validation.
- `command_codec`: strict fixed-bounds parse/serialize for HID payload framing.
- `rate_limiter`: abuse throttling primitive per command channel.
- `settings_store`: persistent runtime settings with checksum verification.
- `ui_feedback`: state/action -> LED/status mapping.

## Security posture

- No credential fill on origin mismatch.
- No sensitive action while locked/locked-out/wiped.
- Touch/hold confirmations gate sensitive actions.
- PIN failures trigger lockout, then optional wipe.

## Known limitations

- Crypto layer still uses stub implementations for host tests.
- FIDO2/WebAuthn transport and authenticator logic not yet implemented.
- ATECC608A-backed key paths not yet integrated.
