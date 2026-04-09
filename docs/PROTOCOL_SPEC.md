# Device Input Command Protocol (v1)

This document defines the internal command encoding used by firmware modules
for host tests and device-control paths.

## Frame format

Current host-side framing is ASCII key/value pairs:

- `type=<COMMAND>;nonce=<N>;origin=<...>;username=<...>;password=<...>`

Rules:

- fields are separated by `;`
- key/value pairs are separated by `=`
- unsupported keys are rejected
- missing required fields are rejected
- maximum decoded frame size is `COMMAND_CODEC_MAX_FRAME` (512 bytes)

`nonce` is optional for device-only local calls. When present on remote/control
paths, firmware enforces monotonic progression to block replay.

## Commands

Supported command types:

- `REQUEST_FILL`: origin required
- `REQUEST_SAVE`: origin + username + password required
- `REQUEST_GENERATE`: origin required, username optional
- `REQUEST_SELECT_NEXT`: no required payloads

Device-local control actions are exposed through direct action engine APIs
rather than external extension messages.

## Validation

The firmware rejects commands when:

- command type is unknown/unsupported
- required fields are missing for that command type
- field values exceed fixed buffer sizes
- origin fails suspicious-origin checks (must be HTTPS and sane)
- nonce is stale (`nonce <= last_nonce`) when replay protection is active

## Security notes

- Protocol intentionally does not support arbitrary "type text" output.
- Sensitive operations remain touch/hold gated in firmware action engine.
- Current implementation has replay blocking via nonce where nonce-bearing
  control paths are used. Production hardening should add authenticated
  transport/session semantics for any external command ingress.
