#include "fido2_authenticator.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h"
#include "security_utils.h"

typedef struct {
  bool initialized;
  bool has_credential;
  uint8_t cred_id[64];
  size_t cred_id_len;
  uint8_t rp_hash[16];
  uint8_t user_hash[16];
  uint32_t sign_counter;
} fido2_state_t;

static fido2_state_t g_fido2;

void fido2_authenticator_init(void) {
  memset(&g_fido2, 0, sizeof(g_fido2));
  g_fido2.initialized = true;
}

bool fido2_create_credential(const char *rp_id,
                             const char *user_name,
                             const uint8_t *client_data_hash,
                             size_t hash_len,
                             fido2_credential_t *out_cred) {
  uint8_t seed[64];
  if (!g_fido2.initialized) {
    fido2_authenticator_init();
  }
  if (rp_id == NULL || user_name == NULL || client_data_hash == NULL || out_cred == NULL) {
    return false;
  }
  memset(seed, 0, sizeof(seed));
  memset(out_cred, 0, sizeof(*out_cred));

  crypto_engine_hash16((const uint8_t *)rp_id, strlen(rp_id), g_fido2.rp_hash);
  crypto_engine_hash16((const uint8_t *)user_name, strlen(user_name), g_fido2.user_hash);
  memcpy(seed, g_fido2.rp_hash, sizeof(g_fido2.rp_hash));
  memcpy(seed + 16u, g_fido2.user_hash, sizeof(g_fido2.user_hash));
  if (hash_len > 16u) {
    hash_len = 16u;
  }
  memcpy(seed + 32u, client_data_hash, hash_len);
  crypto_engine_hash16(seed, sizeof(seed), out_cred->id);
  out_cred->id_len = 16u;
  crypto_engine_hash16(out_cred->id, out_cred->id_len, out_cred->public_key);
  out_cred->public_key_len = 16u;

  memcpy(g_fido2.cred_id, out_cred->id, out_cred->id_len);
  g_fido2.cred_id_len = out_cred->id_len;
  g_fido2.has_credential = true;
  g_fido2.sign_counter = 0u;
  return true;
}

bool fido2_get_assertion(const char *rp_id,
                         const uint8_t *client_data_hash,
                         size_t hash_len,
                         fido2_assertion_t *out_assertion) {
  uint8_t envelope[64];
  uint8_t rp_hash[16];
  if (!g_fido2.initialized || !g_fido2.has_credential) {
    return false;
  }
  if (rp_id == NULL || client_data_hash == NULL || out_assertion == NULL) {
    return false;
  }
  memset(out_assertion, 0, sizeof(*out_assertion));
  crypto_engine_hash16((const uint8_t *)rp_id, strlen(rp_id), rp_hash);
  if (!sec_consttime_memeq(rp_hash, g_fido2.rp_hash, sizeof(rp_hash))) {
    return false;
  }

  memcpy(out_assertion->user_handle, g_fido2.user_hash, sizeof(g_fido2.user_hash));
  out_assertion->user_handle_len = sizeof(g_fido2.user_hash);

  memset(envelope, 0, sizeof(envelope));
  memcpy(envelope, g_fido2.cred_id, g_fido2.cred_id_len);
  if (hash_len > 16u) {
    hash_len = 16u;
  }
  memcpy(envelope + 16u, client_data_hash, hash_len);
  memcpy(envelope + 32u, &g_fido2.sign_counter, sizeof(g_fido2.sign_counter));
  crypto_engine_hash16(envelope, sizeof(envelope), out_assertion->signature);
  out_assertion->signature_len = 16u;
  out_assertion->sign_count = g_fido2.sign_counter;
  g_fido2.sign_counter++;
  return true;
}

