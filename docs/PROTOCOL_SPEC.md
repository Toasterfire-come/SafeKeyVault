# Browser HID Command Protocol (v1)

This document defines the browser-to-device command encoding used by the
firmware command codec module.

## Frame format

- Byte 0: command type (`BrowserCommandType`)
- Byte 1: origin length (0..95)
- Byte 2: username length (0..95)
- Byte 3: password length (0..127)
- Bytes 4..N: UTF-8 payload blobs:
  - origin bytes
  - username bytes
  - password bytes

Maximum frame length is 320 bytes.

## Commands

- `REQUEST_FILL`: origin required
- `REQUEST_SAVE`: origin + username + password required
- `REQUEST_GENERATE`: origin required, username optional
- `REQUEST_SELECT_NEXT`: no required payloads

## Validation

The device side rejects frames when:

- payload lengths exceed field capacity
- command type is invalid
- required fields are missing
- total frame size is inconsistent with encoded lengths

Decoded commands are subsequently validated by browser protocol risk checks
(HTTPS requirement, suspicious origin checks).

## Security notes

- Protocol intentionally does not support generic "type arbitrary string".
- Sensitive operations remain touch/hold gated in firmware action engine.
- For production, wrap this command codec with replay protection and an
  authenticated transport/session layer.
