#include "usb_session.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h"

#define SESSION_NONCE_WINDOW 32u

typedef struct {
  bool active;
  uint32_t session_id;
  uint8_t session_key[32];
  uint8_t accepted_nonces[SESSION_NONCE_WINDOW];
} usb_session_state_t;

static usb_session_state_t g_usb_session;

static bool nonce_seen(uint8_t nonce) {
  size_t i;
  for (i = 0u; i < SESSION_NONCE_WINDOW; ++i) {
    if (g_usb_session.accepted_nonces[i] == nonce) {
      return true;
    }
  }
  return false;
}

static void nonce_remember(uint8_t nonce) {
  memmove(&g_usb_session.accepted_nonces[1],
          &g_usb_session.accepted_nonces[0],
          SESSION_NONCE_WINDOW - 1u);
  g_usb_session.accepted_nonces[0] = nonce;
}

void usb_session_init(void) {
  memset(&g_usb_session, 0, sizeof(g_usb_session));
}

bool usb_session_start(uint32_t session_id,
                       const uint8_t *client_nonce,
                       size_t client_nonce_len) {
  uint8_t salt[16] = {0};
  if (client_nonce == NULL || client_nonce_len == 0u) {
    return false;
  }
  memset(&g_usb_session, 0, sizeof(g_usb_session));
  if (client_nonce_len > sizeof(salt)) {
    client_nonce_len = sizeof(salt);
  }
  memcpy(salt, client_nonce, client_nonce_len);
  if (!crypto_engine_derive_pin_key("session-bootstrap",
                                    salt,
                                    sizeof(salt),
                                    g_usb_session.session_key)) {
    return false;
  }
  g_usb_session.active = true;
  g_usb_session.session_id = session_id;
  return true;
}

bool usb_session_is_active(void) {
  return g_usb_session.active;
}

bool usb_session_verify_frame(const uint8_t *frame,
                              size_t frame_len,
                              uint8_t nonce,
                              const uint8_t tag[16]) {
  uint8_t expected[16];
  size_t out_len = sizeof(expected);
  if (!g_usb_session.active || frame == NULL || tag == NULL || frame_len == 0u) {
    return false;
  }
  if (nonce_seen(nonce)) {
    return false;
  }
  if (!crypto_engine_encrypt_aead(frame,
                                  frame_len,
                                  g_usb_session.session_key,
                                  sizeof(g_usb_session.session_key),
                                  expected,
                                  sizeof(expected),
                                  &out_len,
                                  expected)) {
    return false;
  }
  if (out_len < 16u || memcmp(expected, tag, 16u) != 0) {
    return false;
  }
  nonce_remember(nonce);
  return true;
}

void usb_session_end(void) {
  memset(&g_usb_session, 0, sizeof(g_usb_session));
}
