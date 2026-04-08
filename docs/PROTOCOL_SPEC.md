# Browser HID Command Protocol (v1)

This document defines the browser-to-device command encoding used by the
firmware command codec module.

## Frame format

Current host-side framing is ASCII key/value pairs:

- `type=<COMMAND>;nonce=<N>;origin=<...>;username=<...>;password=<...>`

Rules:

- fields are separated by `;`
- key/value pairs are separated by `=`
- unsupported keys are rejected
- missing required fields are rejected
- maximum decoded frame size is `COMMAND_CODEC_MAX_FRAME` (512 bytes)

`nonce` is a monotonic unsigned integer maintained by the extension
background worker and used by firmware to block replayed commands.

## Commands

Supported command types:

- `REQUEST_FILL`: origin required
- `REQUEST_SAVE`: origin + username + password required
- `REQUEST_GENERATE`: origin required, username optional
- `REQUEST_SELECT_NEXT`: no required payloads

Extension control messages that map to device commands but are not part of
the firmware `BrowserCommandType` enum include:

- `arm_manual_popup`
- `confirm_tap`
- `confirm_hold`
- `change_pin`

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
- Browser page JS is untrusted; the extension is the only allowed path to HID.
- Current implementation has replay blocking via nonce. Production hardening
  should add authenticated transport/session semantics on top.
