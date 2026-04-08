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
