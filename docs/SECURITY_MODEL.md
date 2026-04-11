# Security Model (Current Implementation + Roadmap)

## Assets
- Stored credentials (origin, username, encrypted password blob).
- PIN-gated unlock state.
- Runtime settings (autolock, popup policy, lockout policy).

## Trust boundaries
- Host computer and OS: untrusted execution environment.
- USB transport: untrusted channel, device enforces policy locally.
- Device firmware: trusted root for policy enforcement.

## Current enforced controls
- Touch/hold confirmation gates for sensitive actions.
- PIN lockout with progressive delay.
- Optional wipe state after repeated failures.
- Bounded command parsing and replay rejection (for host command frames).
- Basic per-channel rate limiting.
- Device-only workflow APIs allow save/fill/generate/select fully on-device.
- Monotonic nonce replay rejection in action engine.

## Known gaps
- New `crypto_engine` abstraction is in place, but still backed by fallback software primitives for host tests.
- AEAD/KDF primitives are scaffolded and interface-stable, but not yet replaced with production cryptography.
- ATECC608A binding points exist (slot/public-key registration + backend status), but no live chip transport path yet.
- No secure boot / signed update flow yet.
- No authenticated HID session/channel binding yet (nonce protects replay, not full MITM).

## Non-negotiable security invariants
1. Do not output credentials while locked or wiped.
2. Never perform sensitive actions without physical touch/hold confirmation.
3. Manual popup gate must be respected when enabled.
4. Command parser must reject malformed/oversized payloads.
