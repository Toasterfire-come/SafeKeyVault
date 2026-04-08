#include "fido2_authenticator.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h"

typedef struct {
  bool initialized;
  bool configured;
  uint8_t rp_hash[16];
  uint8_t user_hash[16];
  uint32_t sign_counter;
} fido2_state_t;

static fido2_state_t g_fido2;

void fido2_init(void) {
  memset(&g_fido2, 0, sizeof(g_fido2));
  g_fido2.initialized = true;
}

bool fido2_begin_registration(const uint8_t *rp_id,
                              size_t rp_id_len,
                              const uint8_t *user_id,
                              size_t user_id_len) {
  if (!g_fido2.initialized) {
    fido2_init();
  }
  if (rp_id == NULL || user_id == NULL || rp_id_len == 0u || user_id_len == 0u) {
    return false;
  }
  crypto_engine_hash16(rp_id, rp_id_len, g_fido2.rp_hash);
  crypto_engine_hash16(user_id, user_id_len, g_fido2.user_hash);
  g_fido2.configured = true;
  g_fido2.sign_counter = 0u;
  return true;
}

bool fido2_get_assertion(const uint8_t *client_data_hash,
                         size_t client_data_hash_len,
                         uint8_t *signature_out,
                         size_t *signature_len) {
  uint8_t envelope[64];
  if (!g_fido2.initialized || !g_fido2.configured) {
    return false;
  }
  if (client_data_hash == NULL || signature_out == NULL || signature_len == NULL) {
    return false;
  }
  if (*signature_len < 16u) {
    return false;
  }
  memset(envelope, 0, sizeof(envelope));
  memcpy(envelope, g_fido2.rp_hash, sizeof(g_fido2.rp_hash));
  memcpy(envelope + 16u, g_fido2.user_hash, sizeof(g_fido2.user_hash));
  if (client_data_hash_len > 16u) {
    client_data_hash_len = 16u;
  }
  memcpy(envelope + 32u, client_data_hash, client_data_hash_len);
  memcpy(envelope + 48u, &g_fido2.sign_counter, sizeof(g_fido2.sign_counter));
  crypto_engine_hash16(envelope, sizeof(envelope), signature_out);
  *signature_len = 16u;
  g_fido2.sign_counter++;
  return true;
}

void fido2_get_status(fido2_status_t *out_status) {
  if (out_status == NULL) {
    return;
  }
  out_status->initialized = g_fido2.initialized;
  out_status->configured = g_fido2.configured;
  out_status->sign_counter = g_fido2.sign_counter;
}

