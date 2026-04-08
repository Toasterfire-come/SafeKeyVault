# Security Model (Current Implementation + Roadmap)

## Assets
- Stored credentials (origin, username, encrypted password blob).
- PIN-gated unlock state.
- Runtime settings (autolock, popup policy, lockout policy).

## Trust boundaries
- Browser webpage JS: untrusted.
- Browser extension privileged context: constrained but still host-side risk.
- Device firmware: trusted root for policy enforcement.

## Current enforced controls
- Origin-bound fill checks.
- Touch/hold confirmation gates for sensitive actions.
- PIN lockout with progressive delay.
- Optional wipe state after repeated failures.
- Command validation and bounded decoding.
- Basic rate limiting.
- Monotonic nonce replay rejection in action engine.
- Browser extension command allowlist with privileged HID only in background service worker.

## Known gaps
- Crypto is currently test-stubbed, not production AEAD.
- No secure boot / signed update flow yet.
- No production ATECC608A integration yet.
- No authenticated HID session/channel binding yet (nonce protects replay, not full MITM).

## Non-negotiable security invariants
1. Do not output credentials while locked or wiped.
2. Never fill credentials on origin mismatch.
3. Manual popup gate must be respected when enabled.
4. Command parser must reject malformed/oversized payloads.

