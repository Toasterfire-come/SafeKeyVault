#include "usb_session.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h"
#include "security_utils.h"

static usb_session_state_t g_session;

static void build_session_aad(const usb_session_state_t *state,
                              uint32_t counter,
                              uint8_t aad[16]) {
  memset(aad, 0, 16u);
  if (state != NULL) {
    memcpy(aad, &state->session_id, sizeof(state->session_id));
  }
  memcpy(aad + 4u, &counter, sizeof(counter));
}

static uint32_t g_expected_client_counter;
static uint8_t g_challenge[16];
static size_t g_challenge_len;

// USB Descriptor Definitions
static const uint8_t usb_device_descriptor[] = {
    0x12,                       // bLength
    USB_DESC_TYPE_DEVICE,       // bDescriptorType
    0x00, 0x02,                 // bcdUSB (USB 2.0)
    USB_HID_CLASS_CODE,         // bDeviceClass (HID)
    0x00,                       // bDeviceSubClass
    0x00,                       // bDeviceProtocol
    0x40,                       // bMaxPacketSize0 (64 bytes)
    0x0483,                     // idVendor (STMicroelectronics)
    0x5740,                     // idProduct (Custom product ID)
    0x0200,                     // bcdDevice (2.00)
    0x01,                       // iManufacturer (String Index 1)
    0x02,                       // iProduct (String Index 2)
    0x03,                       // iSerialNumber (String Index 3)
    0x01                        // bNumConfigurations (1)
};

static const uint8_t usb_configuration_descriptor[] = {
    // Configuration Descriptor
    0x09,                       // bLength
    USB_DESC_TYPE_CONFIGURATION,// bDescriptorType
    0x43, 0x00,                 // wTotalLength (67 bytes)
    0x03,                       // bNumInterfaces (3)
    0x01,                       // bConfigurationValue
    0x00,                       // iConfiguration (String Index 0)
    0xC0,                       // bmAttributes (Self-powered)
    0x32,                       // bMaxPower (100mA)

    // Interface Association Descriptor (IAD) for HID Keyboard
    0x08,                       // bLength
    USB_DESC_TYPE_IAD,          // bDescriptorType
    0x00,                       // bFirstInterface
    0x01,                       // bInterfaceCount
    USB_HID_CLASS_CODE,         // bFunctionClass (HID)
    USB_HID_SUBCLASS_CODE_NONE, // bFunctionSubClass
    USB_HID_PROTOCOL_CODE_NONE, // bFunctionProtocol
    0x00,                       // iFunction (String Index 0)

    // Interface Descriptor (HID Keyboard)
    0x09,                       // bLength
    USB_DESC_TYPE_INTERFACE,    // bDescriptorType
    0x00,                       // bInterfaceNumber
    0x00,                       // bAlternateSetting
    0x01,                       // bNumEndpoints
    USB_HID_CLASS_CODE,         // bInterfaceClass (HID)
    USB_HID_SUBCLASS_CODE_NONE, // bInterfaceSubClass
    USB_HID_PROTOCOL_CODE_KEYBOARD, // bInterfaceProtocol (Keyboard)
    0x00,                       // iInterface (String Index 0)

    // HID Descriptor (HID Keyboard)
    0x09,                       // bLength
    0x21,                       // bDescriptorType (HID)
    0x11, 0x01,                 // bcdHID (1.11)
    0x00,                       // bCountryCode
    0x01,                       // bNumDescriptors
    0x22,                       // bDescriptorType (Report)
    0x3F, 0x00,                 // wDescriptorLength (63 bytes)

    // Endpoint Descriptor (HID Keyboard)
    0x07,                       // bLength
    USB_DESC_TYPE_ENDPOINT,     // bDescriptorType
    0x81,                       // bEndpointAddress (IN endpoint 1)
    0x03,                       // bmAttributes (Interrupt)
    0x08, 0x00,                 // wMaxPacketSize (8 bytes)
    0x0A,                       // bInterval (10ms)

    // Interface Association Descriptor (IAD) for Custom HID
    0x08,                       // bLength
    USB_DESC_TYPE_IAD,          // bDescriptorType
    0x01,                       // bFirstInterface
    0x01,                       // bInterfaceCount
    USB_HID_CLASS_CODE,         // bFunctionClass (HID)
    USB_HID_SUBCLASS_CODE_NONE, // bFunctionSubClass
    USB_HID_PROTOCOL_CODE_NONE, // bFunctionProtocol
    0x00,                       // iFunction (String Index 0)

    // Interface Descriptor (Custom HID)
    0x09,                       // bLength
    USB_DESC_TYPE_INTERFACE,    // bDescriptorType
    0x01,                       // bInterfaceNumber
    0x00,                       // bAlternateSetting
    0x02,                       // bNumEndpoints
    USB_HID_CLASS_CODE,         // bInterfaceClass (HID)
    USB_HID_SUBCLASS_CODE_NONE, // bInterfaceSubClass
    USB_HID_PROTOCOL_CODE_NONE, // bInterfaceProtocol
    0x00,                       // iInterface (String Index 0)

    // HID Descriptor (Custom HID)
    0x09,                       // bLength
    0x21,                       // bDescriptorType (HID)
    0x11, 0x01,                 // bcdHID (1.11)
    0x00,                       // bCountryCode
    0x01,                       // bNumDescriptors
    0x22,                       // bDescriptorType (Report)
    0x40, 0x00,                 // wDescriptorLength (64 bytes)

    // Endpoint Descriptor (Custom HID IN)
    0x07,                       // bLength
    USB_DESC_TYPE_ENDPOINT,     // bDescriptorType
    0x82,                       // bEndpointAddress (IN endpoint 2)
    0x03,                       // bmAttributes (Interrupt)
    0x40, 0x00,                 // wMaxPacketSize (64 bytes)
    0x0A,                       // bInterval (10ms)

    // Endpoint Descriptor (Custom HID OUT)
    0x07,                       // bLength
    USB_DESC_TYPE_ENDPOINT,     // bDescriptorType
    0x02,                       // bEndpointAddress (OUT endpoint 2)
    0x03,                       // bmAttributes (Interrupt)
    0x40, 0x00,                 // wMaxPacketSize (64 bytes)
    0x0A,                       // bInterval (10ms)

    // Interface Association Descriptor (IAD) for Mass Storage
    0x08,                       // bLength
    USB_DESC_TYPE_IAD,          // bDescriptorType
    0x02,                       // bFirstInterface
    0x01,                       // bInterfaceCount
    USB_MSC_CLASS_CODE,         // bFunctionClass (Mass Storage)
    USB_MSC_SUBCLASS_CODE_BOT, // bFunctionSubClass (BOT)
    USB_MSC_PROTOCOL_CODE_BOT, // bFunctionProtocol (BOT)
    0x00,                       // iFunction (String Index 0)

    // Interface Descriptor (Mass Storage)
    0x09,                       // bLength
    USB_DESC_TYPE_INTERFACE,    // bDescriptorType
    0x02,                       // bInterfaceNumber
    0x00,                       // bAlternateSetting
    0x02,                       // bNumEndpoints
    USB_MSC_CLASS_CODE,         // bInterfaceClass (Mass Storage)
    USB_MSC_SUBCLASS_CODE_BOT, // bInterfaceSubClass (BOT)
    USB_MSC_PROTOCOL_CODE_BOT, // bInterfaceProtocol (BOT)
    0x00,                       // iInterface (String Index 0)

    // Endpoint Descriptor (Mass Storage Bulk IN)
    0x07,                       // bLength
    USB_DESC_TYPE_ENDPOINT,     // bDescriptorType
    0x83,                       // bEndpointAddress (IN endpoint 3)
    0x02,                       // bmAttributes (Bulk)
    0x40, 0x00,                 // wMaxPacketSize (64 bytes)
    0x00,                       // bInterval (ignored for Bulk)

    // Endpoint Descriptor (Mass Storage Bulk OUT)
    0x07,                       // bLength
    USB_DESC_TYPE_ENDPOINT,     // bDescriptorType
    0x03,                       // bEndpointAddress (OUT endpoint 3)
    0x02,                       // bmAttributes (Bulk)
    0x40, 0x00,                 // wMaxPacketSize (64 bytes)
    0x00                        // bInterval (ignored for Bulk)
};

static const uint8_t usb_string_descriptor_langid[] = {
    0x04,                       // bLength
    USB_DESC_TYPE_STRING,       // bDescriptorType
    0x09, 0x04                  // wLANGID (English)
};

static const uint8_t usb_string_descriptor_manufacturer[] = {
    0x1A,                       // bLength
    USB_DESC_TYPE_STRING,       // bDescriptorType
    'S', 0x00, 'T', 0x00, 'M', 0x00, 'i', 0x00, 'c', 0x00, 'r', 0x00, 'o', 0x00, 'e', 0x00, 'l', 0x00, 'e', 0x00, 'c', 0x00, 't', 0x00, 'r', 0x00, 'o', 0x00, 'n', 0x00, 'i', 0x00, 'c', 0x00, 's', 0x00
};

static const uint8_t usb_string_descriptor_product[] = {
    0x1E,                       // bLength
    USB_DESC_TYPE_STRING,       // bDescriptorType
    'U', 0x00, 'S', 0x00, 'B', 0x00, ' ', 0x00, 'C', 0x00, 'o', 0x00, 'm', 0x00, 'p', 0x00, 'o', 0x00, 's', 0x00, 'i', 0x00, 't', 0x00, 'e', 0x00, ' ', 0x00, 'D', 0x00, 'e', 0x00, 'v', 0x00, 'i', 0x00, 'c', 0x00, 'e', 0x00
};

static const uint8_t usb_string_descriptor_serial[] = {
    0x12,                       // bLength
    USB_DESC_TYPE_STRING,       // bDescriptorType
    '0', 0x00, '0', 0x00, '0', 0x00, '0', 0x00, '0', 0x00, '0', 0x00, '0', 0x00, '0', 0x00, '0', 0x00, '1', 0x00
};

static const uint8_t usb_hid_report_descriptor_keyboard[] = {
    0x05, 0x01,                 // USAGE_PAGE (Generic Desktop)
    0x09, 0x06,                 // USAGE (Keyboard)
    0xA1, 0x01,                 // COLLECTION (Application)
    0x05, 0x07,                 // USAGE_PAGE (Keyboard)
    0x19, 0xE0,                 // USAGE_MINIMUM (Keyboard LeftControl)
    0x29, 0xE7,                 // USAGE_MAXIMUM (Keyboard Right GUI)
    0x15, 0x00,                 // LOGICAL_MINIMUM (0)
    0x25, 0x01,                 // LOGICAL_MAXIMUM (1)
    0x75, 0x01,                 // REPORT_SIZE (1)
    0x95, 0x08,                 // REPORT_COUNT (8)
    0x81, 0x02,                 // INPUT (Data,Var,Abs)
    0x95, 0x01,                 // REPORT_COUNT (1)
    0x75, 0x08,                 // REPORT_SIZE (8)
    0x81, 0x01,                 // INPUT (Cnst,Ary,Abs)
    0x95, 0x05,                 // REPORT_COUNT (5)
    0x75, 0x08,                 // REPORT_SIZE (8)
    0x15, 0x00,                 // LOGICAL_MINIMUM (0)
    0x25, 0x65,                 // LOGICAL_MAXIMUM (101)
    0x05, 0x07,                 // USAGE_PAGE (Keyboard)
    0x19, 0x00,                 // USAGE_MINIMUM (Reserved (no event indicated))
    0x29, 0x65,                 // USAGE_MAXIMUM (Keyboard Application)
    0x81, 0x00,                 // INPUT (Data,Ary,Abs)
    0xC0                        // END_COLLECTION
};

static const uint8_t usb_hid_report_descriptor_custom[] = {
    0x06, 0x00, 0xFF,           // USAGE_PAGE (Vendor Defined Page 1)
    0x09, 0x01,                 // USAGE (Vendor Usage 1)
    0xA1, 0x01,                 // COLLECTION (Application)
    0x85, USB_HID_REPORT_ID_PIN_PROMPT, // REPORT_ID (PIN_PROMPT)
    0x15, 0x00,                 // LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00,           // LOGICAL_MAXIMUM (255)
    0x75, 0x08,                 // REPORT_SIZE (8)
    0x95, 0x3F,                 // REPORT_COUNT (63)
    0x09, 0x01,                 // USAGE (Vendor Usage 1)
    0x91, 0x82,                 // OUTPUT (Data,Var,Abs,NPrf)
    0x85, USB_HID_REPORT_ID_POPUP_TRIGGER, // REPORT_ID (POPUP_TRIGGER)
    0x95, 0x3F,                 // REPORT_COUNT (63)
    0x09, 0x02,                 // USAGE (Vendor Usage 2)
    0x91, 0x82,                 // OUTPUT (Data,Var,Abs,NPrf)
    0x85, USB_HID_REPORT_ID_PIN_RESPONSE, // REPORT_ID (PIN_RESPONSE)
    0x95, 0x3F,                 // REPORT_COUNT (63)
    0x09, 0x03,                 // USAGE (Vendor Usage 3)
    0x81, 0x82,                 // INPUT (Data,Var,Abs,NWrp,Lin,Pref)
    0x85, USB_HID_REPORT_ID_CREDENTIAL_LIST_REQUEST, // REPORT_ID (CREDENTIAL_LIST_REQUEST)
    0x95, 0x3F,                 // REPORT_COUNT (63)
    0x09, 0x04,                 // USAGE (Vendor Usage 4)
    0x91, 0x82,                 // OUTPUT (Data,Var,Abs,NPrf)
    0x85, USB_HID_REPORT_ID_CREDENTIAL_LIST_RESPONSE, // REPORT_ID (CREDENTIAL_LIST_RESPONSE)
    0x95, 0x3F,                 // REPORT_COUNT (63)
    0x09, 0x05,                 // USAGE (Vendor Usage 5)
    0x81, 0x82,                 // INPUT (Data,Var,Abs,NWrp,Lin,Pref)
    0x85, USB_HID_REPORT_ID_SETTINGS_READ, // REPORT_ID (SETTINGS_READ)
    0x95, 0x3F,                 // REPORT_COUNT (63)
    0x09, 0x06,                 // USAGE (Vendor Usage 6)
    0x91, 0x82,                 // OUTPUT (Data,Var,Abs,NPrf)
    0x85, USB_HID_REPORT_ID_SETTINGS_WRITE, // REPORT_ID (SETTINGS_WRITE)
    0x95, 0x3F,                 // REPORT_COUNT (63)
    0x09, 0x07,                 // USAGE (Vendor Usage 7)
    0x91, 0x82,                 // OUTPUT (Data,Var,Abs,NPrf)
    0x85, USB_HID_REPORT_ID_TOTP_REQUEST, // REPORT_ID (TOTP_REQUEST)
    0x95, 0x3F,                 // REPORT_COUNT (63)
    0x09, 0x08,                 // USAGE (Vendor Usage 8)
    0x91, 0x82,                 // OUTPUT (Data,Var,Abs,NPrf)
    0x85, USB_HID_REPORT_ID_TOTP_RESPONSE, // REPORT_ID (TOTP_RESPONSE)
    0x95, 0x3F,                 // REPORT_COUNT (63)
    0x09, 0x09,                 // USAGE (Vendor Usage 9)
    0x81, 0x82,                 // INPUT (Data,Var,Abs,NWrp,Lin,Pref)
    0x85, USB_HID_REPORT_ID_AUTOFILL_REQUEST, // REPORT_ID (AUTOFILL_REQUEST)
    0x95, 0x3F,                 // REPORT_COUNT (63)
    0x09, 0x0A,                 // USAGE (Vendor Usage 10)
    0x91, 0x82,                 // OUTPUT (Data,Var,Abs,NPrf)
    0x85, USB_HID_REPORT_ID_STATUS, // REPORT_ID (STATUS)
    0x95, 0x3F,                 // REPORT_COUNT (63)
    0x09, 0x0B,                 // USAGE (Vendor Usage 11)
    0x81, 0x82,                 // INPUT (Data,Var,Abs,NWrp,Lin,Pref)
    0xC0                        // END_COLLECTION
};

void usb_session_init(void) {
  memset(&g_session, 0, sizeof(g_session));
  g_expected_client_counter = 0u;
  memset(g_challenge, 0, sizeof(g_challenge));
  g_challenge_len = 0u;
}

bool usb_session_start(usb_session_challenge_t *out_challenge) {
  uint8_t seed[16] = {0};
  uint8_t hash[16] = {0};
  if (out_challenge == NULL) {
    return false;
  }
  memset(&g_session, 0, sizeof(g_session));
  g_session.session_id = 1u;
  g_expected_client_counter = 1u;
  g_session.authenticated = false;
  g_challenge_len = 16u;
  memcpy(seed, "usb-session-seed", 16u);
  crypto_engine_hash16(seed, sizeof(seed), hash);
  memcpy(g_challenge, hash, 16u);
  out_challenge->session_id = g_session.session_id;
  out_challenge->challenge_len = g_challenge_len;
  memcpy(out_challenge->challenge, g_challenge, g_challenge_len);
  security_secure_zero(seed, sizeof(seed));
  security_secure_zero(hash, sizeof(hash));
  return true;
}

bool usb_session_debug_compute_expected_response(const usb_session_challenge_t *challenge,
                                                 uint8_t *out_response,
                                                 size_t out_len) {
  uint8_t digest[16];
  if (challenge == NULL || out_response == NULL || out_len < 16u) {
    return false;
  }
  crypto_engine_hash16(challenge->challenge, challenge->challenge_len, digest);
  memcpy(out_response, digest, 16u);
  security_secure_zero(digest, sizeof(digest));
  return true;
}

bool usb_session_authenticate(const uint8_t *host_response, size_t response_len) {
  usb_session_challenge_t current = {0};
  uint8_t expected[16];
  if (host_response == NULL || response_len < 16u) {
    return false;
  }
  current.session_id = g_session.session_id;
  current.challenge_len = g_challenge_len;
  memcpy(current.challenge, g_challenge, current.challenge_len);
  if (!usb_session_debug_compute_expected_response(&current, expected, sizeof(expected))) {
    return false;
  }
  if (!sec_consttime_memeq(expected, host_response, 16u)) {
    security_secure_zero(expected, sizeof(expected));
    return false;
  }
  g_session.authenticated = true;
  security_secure_zero(expected, sizeof(expected));
  return true;
}

bool usb_session_is_authenticated(void) {
  return g_session.authenticated;
}

bool usb_session_get_state(usb_session_state_t *out_state) {
  if (out_state == NULL) {
    return false;
  }
  *out_state = g_session;
  return true;
}

bool usb_session_sign_payload(const uint8_t *payload,
                              size_t payload_len,
                              uint8_t *out_mac,
                              size_t mac_len) {
  uint8_t aad[16];
  uint8_t scratch[32];
  size_t scratch_len = sizeof(scratch);
  if (!g_session.authenticated || payload == NULL || out_mac == NULL || mac_len < 16u) {
    return false;
  }
  build_session_aad(&g_session, g_expected_client_counter, aad);
  if (!crypto_engine_encrypt_aead(payload, payload_len,
                                  aad, sizeof(aad),
                                  scratch, sizeof(scratch), &scratch_len, out_mac)) {
    return false;
  }
  security_secure_zero(scratch, sizeof(scratch));
  security_secure_zero(aad, sizeof(aad));
  return true;
}

bool usb_session_verify_payload(const uint8_t *payload,
                                size_t payload_len,
                                const uint8_t *mac,
                                size_t mac_len) {
  uint8_t expected[16];
  uint8_t aad[16];
  uint8_t scratch[32];
  size_t scratch_len = sizeof(scratch);
  if (!g_session.authenticated || payload == NULL || mac == NULL || mac_len < 16u) {
    return false;
  }
  build_session_aad(&g_session, g_expected_client_counter, aad);
  if (!crypto_engine_encrypt_aead(payload, payload_len,
                                  aad, sizeof(aad),
                                  scratch, sizeof(scratch), &scratch_len, expected)) {
    return false;
  }
  security_secure_zero(scratch, sizeof(scratch));
  security_secure_zero(aad, sizeof(aad));
  if (!sec_consttime_memeq(expected, mac, 16u)) {
    security_secure_zero(expected, sizeof(expected));
    return false;
  }
  g_expected_client_counter++;
  g_session.verified_frames = g_expected_client_counter - 1u;
  security_secure_zero(expected, sizeof(expected));
  return true;
}

void usb_session_end(void) {
  security_secure_zero(&g_session, sizeof(g_session));
  g_expected_client_counter = 0u;
  security_secure_zero(g_challenge, sizeof(g_challenge));
  g_challenge_len = 0u;
}
