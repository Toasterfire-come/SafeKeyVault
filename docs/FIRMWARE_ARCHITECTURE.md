# Firmware Architecture (Current)

## Core modules

- `state_machine`: lock/unlock, lockout/wipe progression, touch transitions.
- `action_engine`: executes on-device save/fill/generate/select actions with a strict single-button model.
- `password_store` + `vault`: credential storage helpers and wipe path.
- `crypto_engine`: production-oriented crypto abstraction with AEAD/KDF interfaces
  and ATECC binding points; currently backed by host-safe fallback primitives.
- `security_policy`: password checks (min length 8, common/reuse warning paths).
- `browser_protocol`: retained strict input validation for origin/credential record fields.
- `command_codec`: retained strict fixed-bounds parse/serialize for host test framing.
- `rate_limiter`: abuse throttling primitive per command channel.
- `settings_store`: persistent runtime settings with encrypted/authenticated payload storage.
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

- Crypto backend still uses fallback primitives in this stage; production AEAD/KDF
  hardening and full ATECC command path are not yet enabled on target hardware.
- FIDO2/WebAuthn transport and authenticator logic not yet implemented.
- Live ATECC608A transport integration for runtime key operations is not yet integrated.
