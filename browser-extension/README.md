# Browser Extension (MV3) - Secure Browser-Only Path

This extension provides a browser-only interaction surface for the RP2040
password key with privileged HID access isolated in the background service
worker.

## Security posture

- Manifest V3 service worker.
- No remote code, no eval, no inline script execution.
- Privileged HID operations are only performed by `background.js`.
- Content script acts as a constrained relay and never gains direct HID access.
- Command routing is allowlisted and bounded.
- Monotonic nonce is attached to outbound device commands for replay defense.

## Current command surfaces

Popup/content requests that can reach the background layer:

- `CONNECT_DEVICE`
- `REQUEST_FILL`
- `REQUEST_SAVE`
- `REQUEST_GENERATE`
- `ARM_MANUAL_POPUP`
- `CONFIRM_TAP`
- `CONFIRM_HOLD`
- `REQUEST_CHANGE_PIN`

Background then maps these to constrained device command tokens (e.g.
`request_fill`, `request_save`, `confirm_hold`) and adds nonce metadata.

## Notes

- This is still a development skeleton; transport and response parsing are
  simplified for host-side testing.
- Production hardening should include authenticated framing and stricter
  response verification in the HID path.
