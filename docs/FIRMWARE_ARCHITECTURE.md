# Firmware Architecture (Current)

## Core modules

- `state_machine`: lock/unlock, lockout/wipe progression, touch transitions.
- `action_engine`: executes on-device save/fill/generate/select actions with a strict single-button model.
- `password_store` + `vault`: credential storage helpers and wipe path.
- `security_policy`: password checks (min length 8, common/reuse warning paths).
- `browser_protocol`: retained strict input validation for origin/credential record fields.
- `command_codec`: retained strict fixed-bounds parse/serialize for host test framing.
- `rate_limiter`: abuse throttling primitive per command channel.
- `settings_store`: persistent runtime settings with checksum verification.
- `ui_feedback`: state/action -> LED/status mapping.

## Security posture

- No credential fill on origin mismatch.
- No sensitive action while locked/locked-out/wiped.
- Single press triggers password fill for the active credential context.
- If no known credential context exists for the current site/app, single press opens settings instead of filling.
- Hold opens settings/modify mode, where configuration changes and credential password updates are applied.
- PIN failures trigger lockout, then optional wipe.
- Plug-and-play flow is device-driven; no browser extension dependency.

## Known limitations

- Crypto layer still uses stub implementations for host tests.
- FIDO2/WebAuthn transport and authenticator logic not yet implemented.
- ATECC608A-backed key paths not yet integrated.
