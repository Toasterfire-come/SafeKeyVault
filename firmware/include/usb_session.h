#ifndef USB_SESSION_H
#define USB_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t session_id;
  uint8_t challenge[16];
  size_t challenge_len;
} usb_session_challenge_t;

typedef struct {
  bool authenticated;
  uint32_t session_id;
  uint32_t verified_frames;
} usb_session_state_t;

// USB Descriptor Types
#define USB_DESC_TYPE_DEVICE                 0x01
#define USB_DESC_TYPE_CONFIGURATION          0x02
#define USB_DESC_TYPE_STRING                0x03
#define USB_DESC_TYPE_INTERFACE              0x04
#define USB_DESC_TYPE_ENDPOINT               0x05
#define USB_DESC_TYPE_DEVICE_QUALIFIER      0x06
#define USB_DESC_TYPE_OTHER_SPEED_CONFIG    0x07
#define USB_DESC_TYPE_INTERFACE_POWER       0x08
#define USB_DESC_TYPE_IAD                   0x0B

// USB HID Report Types
#define USB_HID_REPORT_TYPE_INPUT           0x01
#define USB_HID_REPORT_TYPE_OUTPUT          0x02
#define USB_HID_REPORT_TYPE_FEATURE         0x03

// USB HID Report IDs
#define USB_HID_REPORT_ID_PIN_PROMPT        0x01
#define USB_HID_REPORT_ID_POPUP_TRIGGER     0x02
#define USB_HID_REPORT_ID_PIN_RESPONSE      0x03
#define USB_HID_REPORT_ID_CREDENTIAL_LIST_REQUEST 0x04
#define USB_HID_REPORT_ID_CREDENTIAL_LIST_RESPONSE 0x05
#define USB_HID_REPORT_ID_SETTINGS_READ     0x06
#define USB_HID_REPORT_ID_SETTINGS_WRITE    0x07
#define USB_HID_REPORT_ID_TOTP_REQUEST      0x08
#define USB_HID_REPORT_ID_TOTP_RESPONSE    0x09
#define USB_HID_REPORT_ID_AUTOFILL_REQUEST 0x0A
#define USB_HID_REPORT_ID_STATUS           0x0B

// USB Mass Storage Class Codes
#define USB_MSC_CLASS_CODE                 0x08
#define USB_MSC_SUBCLASS_CODE_BOT          0x06
#define USB_MSC_PROTOCOL_CODE_BOT          0x50

// USB HID Class Codes
#define USB_HID_CLASS_CODE                 0x03
#define USB_HID_SUBCLASS_CODE_NONE         0x00
#define USB_HID_SUBCLASS_CODE_BOOT         0x01
#define USB_HID_PROTOCOL_CODE_NONE         0x00
#define USB_HID_PROTOCOL_CODE_KEYBOARD     0x01
#define USB_HID_PROTOCOL_CODE_MOUSE        0x02

void usb_session_init(void);
bool usb_session_start(usb_session_challenge_t *out_challenge);
bool usb_session_debug_compute_expected_response(const usb_session_challenge_t *challenge,
                                                 uint8_t *out_response,
                                                 size_t out_len);
bool usb_session_authenticate(const uint8_t *response, size_t response_len);
bool usb_session_is_authenticated(void);
bool usb_session_get_state(usb_session_state_t *out_state);
bool usb_session_sign_payload(const uint8_t *payload,
                              size_t payload_len,
                              uint8_t *out_mac,
                              size_t mac_len);
bool usb_session_verify_payload(const uint8_t *payload,
                                size_t payload_len,
                                const uint8_t *mac,
                                size_t mac_len);
void usb_session_end(void);

#endif /* USB_SESSION_H */
