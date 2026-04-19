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
- `crypto_engine` abstraction backed by production cryptography (hardware-backed).
- AEAD/KDF primitives implemented with production cryptography.
- ATECC608A integration for hardware security (slot/public-key registration, live chip transport).
- Secure boot and signed update flow implemented.
- Authenticated HID session/channel binding for full MITM protection.


## Non-negotiable security invariants
1. Do not output credentials while locked or wiped.
2. Never perform sensitive actions without physical touch/hold confirmation.
3. Manual popup gate must be respected when enabled.
4. Command parser must reject malformed/oversized payloads.
