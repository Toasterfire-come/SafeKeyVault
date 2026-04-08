#ifndef USB_SESSION_H
#define USB_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t server_nonce;
  uint32_t expected_client_counter;
  bool established;
} usb_session_t;

typedef struct {
  bool ok;
  uint32_t challenge;
} usb_session_handshake_t;

void usb_session_init(usb_session_t *session);
usb_session_handshake_t usb_session_begin(usb_session_t *session, uint32_t host_nonce);
bool usb_session_validate_message(usb_session_t *session,
                                  uint32_t client_counter,
                                  const uint8_t *payload,
                                  size_t payload_len,
                                  const uint8_t mac[16]);
void usb_session_close(usb_session_t *session);

#endif /* USB_SESSION_H */
