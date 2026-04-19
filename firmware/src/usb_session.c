#include "usb_session.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h"
#include "security_utils.h"
#include "stm32u5xx_hal.h" // Include HAL header for HAL functions

static usb_session_state_t g_session;

static void build_session_aad(const usb_session_state_t *state,
                              uint32_t counter,
                              uint8_t aad[16]) {
  memset(aad, 0, 16u);
  if (state != NULL) { // Ensure state is valid before dereferencing
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

// Removed usb_hid_report_descriptor_keyboard and usb_hid_report_descriptor_custom
// These descriptors are now managed by pcd_hal.c for HID keyboard functionality.
// The USB composite device configuration moved to pcd_hal.c to centralize USB descriptor management.

void usb_session_init(void) {
  // Use secure_zero to ensure sensitive data is not left in memory
  security_secure_zero(&g_session, sizeof(g_session));
  g_expected_client_counter = 0u;
  security_secure_zero(g_challenge, sizeof(g_challenge)); // Zeroize challenge
  g_challenge_len = 0u;
}

bool usb_session_start(usb_session_challenge_t *out_challenge) {
  uint8_t seed[32] = {0}; // Increased size to accommodate UID and Tick
  uint8_t hash[16] = {0};
  bool success = false;

  if (out_challenge == NULL) {
    return false;
  }

  // Securely zeroize global session state before starting a new session
  security_secure_zero(&g_session, sizeof(g_session));
  g_session.session_id = 1u; // Session ID can be incremented or randomized
  g_expected_client_counter = 1u;
  g_session.authenticated = false;
  g_challenge_len = 16u;

  // Derive seed from HAL_UID and HAL_GetTick() for better randomness
  // Concatenate HAL UID parts and current tick value
  memcpy(seed, &HAL_GetUIDw0(), sizeof(HAL_GetUIDw0()));
  memcpy(seed + 4, &HAL_GetUIDw1(), sizeof(HAL_GetUIDw1()));
  memcpy(seed + 8, &HAL_GetUIDw2(), sizeof(HAL_GetUIDw2()));
  memcpy(seed + 12, &HAL_GetTick(), sizeof(HAL_GetTick()));

  // Hash the derived seed to create the challenge
  crypto_engine_hash16(seed, sizeof(seed), hash);

  // Copy hash to global challenge and output challenge
  memcpy(g_challenge, hash, sizeof(g_challenge)); // Use sizeof(g_challenge) to ensure full copy
  out_challenge->session_id = g_session.session_id;
  out_challenge->challenge_len = g_challenge_len;
  memcpy(out_challenge->challenge, g_challenge, g_challenge_len);
  success = true;

  // Securely zeroize sensitive intermediate buffers
  security_secure_zero(seed, sizeof(seed));
  security_secure_zero(hash, sizeof(hash));

  return success;
}

bool usb_session_authenticate(const uint8_t *host_response, size_t response_len) {
  usb_session_challenge_t current = {0}; // Initialize for security
  uint8_t expected[16] = {0}; // Initialize for security
  bool success = false;

  if (host_response == NULL || response_len < 16u) {
    goto end;
  }
  current.session_id = g_session.session_id;
  current.challenge_len = g_challenge_len;
  memcpy(current.challenge, g_challenge, current.challenge_len); // Copy challenge

  // Compute expected response
  crypto_engine_hash16(current.challenge, current.challenge_len, expected);

  // Perform constant-time comparison of the host response with the expected response
  if (!sec_consttime_memeq(expected, host_response, 16u)) {
    goto end; // Authentication failed
  }

  g_session.authenticated = true;
  success = true;

end:
  security_secure_zero(expected, sizeof(expected)); // Zeroize sensitive expected response
  return success;
}

bool usb_session_is_authenticated(void) {
  // This state is not considered sensitive, no zeroization needed for return value
  return g_session.authenticated;
}

bool usb_session_get_state(usb_session_state_t *out_state) {
  if (out_state == NULL) {
    return false;
  }
  *out_state = g_session; // Copy the current session state
  return true;
}

bool usb_session_sign_payload(const uint8_t *payload,
                              size_t payload_len,
                              uint8_t *out_mac,
                              size_t mac_len) {
  uint8_t aad[16] = {0}; // Initialize for security
  uint8_t scratch[32] = {0}; // Initialize for security
  size_t scratch_len = sizeof(scratch);
  bool success = false;

  if (!g_session.authenticated || payload == NULL || out_mac == NULL || mac_len < 16u) {
    goto end;
  }
  // Validate payload_len against scratch buffer capacity
  if (payload_len > sizeof(scratch)) {
    goto end;
  }

  build_session_aad(&g_session, g_expected_client_counter, aad);

  if (!crypto_engine_encrypt_aead(payload, payload_len,
                                  aad, sizeof(aad),
                                  scratch, sizeof(scratch), &scratch_len, out_mac)) {
    goto end; // AEAD encryption failed
  }
  success = true;

end:
  security_secure_zero(scratch, sizeof(scratch)); // Zeroize sensitive scratch buffer
  security_secure_zero(aad, sizeof(aad)); // Zeroize sensitive AAD
  // out_mac is an output, not zeroized here. Caller handles its sensitivity.
  return success;
}

bool usb_session_verify_payload(const uint8_t *payload,
                                size_t payload_len,
                                const uint8_t *mac,
                                size_t mac_len) {
  uint8_t expected_mac[16] = {0}; // Use a distinct name and initialize for security
  uint8_t aad[16] = {0}; // Initialize for security
  uint8_t scratch[32] = {0}; // Initialize for security
  size_t scratch_len = sizeof(scratch);
  bool success = false;

  if (!g_session.authenticated || payload == NULL || mac == NULL || mac_len < 16u) {
    goto end;
  }
  // Validate payload_len against scratch buffer capacity
  if (payload_len > sizeof(scratch)) {
    goto end;
  }

  build_session_aad(&g_session, g_expected_client_counter, aad);

  // Re-encrypt the payload to produce the expected MAC for verification
  if (!crypto_engine_encrypt_aead(payload, payload_len,
                                  aad, sizeof(aad),
                                  scratch, sizeof(scratch), &scratch_len, expected_mac)) {
    goto end; // AEAD encryption failed during verification
  }

  // Perform constant-time comparison of the provided MAC with the expected MAC
  if (!sec_consttime_memeq(expected_mac, mac, 16u)) {
    goto end; // MAC verification failed
  }

  // If verification passes, increment the counter and update session state
  g_expected_client_counter++;
  g_session.verified_frames = g_expected_client_counter - 1u;
  success = true;

end:
  security_secure_zero(scratch, sizeof(scratch));    // Zeroize sensitive scratch buffer
  security_secure_zero(aad, sizeof(aad));          // Zeroize sensitive AAD
  security_secure_zero(expected_mac, sizeof(expected_mac)); // Zeroize sensitive expected MAC
  return success;
}

void usb_session_end(void) {
  // Use secure_zero to ensure sensitive data is not left in memory
  security_secure_zero(&g_session, sizeof(g_session));
  g_expected_client_counter = 0u; // Reset counter
  security_secure_zero(g_challenge, sizeof(g_challenge)); // Zeroize challenge
  g_challenge_len = 0u; // Reset challenge length
}
