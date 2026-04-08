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
