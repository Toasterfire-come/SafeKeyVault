# Browser Extension (MV3) - Secure Skeleton

This extension is a hardened skeleton for browser-only interaction with the RP2040 password key.

## Security posture

- Manifest V3 service worker
- Minimal permissions (`storage`, `activeTab`)
- Optional host permissions for top-level HTTP/HTTPS pages
- No remote code, no eval, no inline script execution
- Commands are constrained to a whitelist:
  - `REQUEST_FILL`
  - `REQUEST_SAVE`
  - `REQUEST_GENERATE`
  - `REQUEST_SELECT_NEXT`

## Notes

- The current implementation mocks the transport layer for local testing.
- Production integration should implement WebHID HID reports in `background.js`.
- Content script never exposes privileged APIs to arbitrary page scripts.
