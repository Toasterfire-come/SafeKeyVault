#include "crypto_engine.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_stub.h"
#include "security_utils.h"

typedef struct {
  bool initialized;
  bool secure_element_bound;
  uint8_t secure_element_slot;
  uint8_t secure_element_pubkey[64];
  size_t secure_element_pubkey_len;
} crypto_engine_state_t;

static crypto_engine_state_t g_crypto_state;

void crypto_engine_init(void) {
  memset(&g_crypto_state, 0, sizeof(g_crypto_state));
  g_crypto_state.initialized = true;
}

void crypto_engine_set_master_key(const uint8_t *key, size_t key_len) {
  crypto_stub_set_master_key(key, key_len);
}

bool crypto_engine_bind_atecc_slot(uint8_t slot_id,
                                   const uint8_t *public_key,
                                   size_t public_key_len) {
  if (!g_crypto_state.initialized) {
    crypto_engine_init();
  }
  if (public_key == NULL || public_key_len == 0u || public_key_len > sizeof(g_crypto_state.secure_element_pubkey)) {
    return false;
  }
  g_crypto_state.secure_element_slot = slot_id;
  memcpy(g_crypto_state.secure_element_pubkey, public_key, public_key_len);
  g_crypto_state.secure_element_pubkey_len = public_key_len;
  g_crypto_state.secure_element_bound = true;
  return true;
}

crypto_engine_status_t crypto_engine_get_status(void) {
  crypto_engine_status_t status;
  memset(&status, 0, sizeof(status));
  status.backend = g_crypto_state.secure_element_bound
                       ? CRYPTO_BACKEND_ATECC608A
                       : CRYPTO_BACKEND_SOFTWARE_FALLBACK;
  status.aead_interface_ready = true;
  status.kdf_interface_ready = true;
  status.secure_element_bound = g_crypto_state.secure_element_bound;
  return status;
}

bool crypto_engine_encrypt_password(const char *plaintext,
                                    char *ciphertext_out,
                                    size_t out_len) {
  return crypto_stub_encrypt_password(plaintext, ciphertext_out, out_len);
}

bool crypto_engine_decrypt_password(const char *ciphertext,
                                    char *plaintext_out,
                                    size_t out_len) {
  return crypto_stub_decrypt_password(ciphertext, plaintext_out, out_len);
}

void crypto_engine_password_fingerprint(const char *password,
                                        uint8_t out_fp[16],
                                        size_t out_len) {
  crypto_stub_password_fingerprint(password, out_fp, out_len);
}

void crypto_engine_hash16(const uint8_t *data, size_t data_len, uint8_t out_fp[16]) {
  crypto_stub_hash16(data, data_len, out_fp);
}

bool crypto_engine_derive_pin_key(const char *pin,
                                  const uint8_t *salt,
                                  size_t salt_len,
                                  uint8_t out_key[32]) {
  uint8_t hash_a[16];
  uint8_t hash_b[16];
  uint8_t mix[64];
  size_t pin_len = 0u;
  size_t i;

  if (pin == NULL || out_key == NULL) {
    return false;
  }
  pin_len = strlen(pin);
  memset(mix, 0, sizeof(mix));
  if (pin_len > sizeof(mix)) {
    pin_len = sizeof(mix);
  }
  memcpy(mix, pin, pin_len);
  if (salt != NULL && salt_len > 0u) {
    size_t copy_len = salt_len;
    if (copy_len > (sizeof(mix) - pin_len)) {
      copy_len = sizeof(mix) - pin_len;
    }
    memcpy(mix + pin_len, salt, copy_len);
  }
  crypto_stub_hash16(mix, sizeof(mix), hash_a);
  crypto_stub_hash16(hash_a, sizeof(hash_a), hash_b);
  for (i = 0u; i < 16u; ++i) {
    out_key[i] = hash_a[i];
    out_key[i + 16u] = hash_b[i];
  }
  security_secure_zero(hash_a, sizeof(hash_a));
  security_secure_zero(hash_b, sizeof(hash_b));
  security_secure_zero(mix, sizeof(mix));
  return true;
}

bool crypto_engine_encrypt_aead(const uint8_t *plaintext,
                                size_t plaintext_len,
                                const uint8_t *aad,
                                size_t aad_len,
                                uint8_t *ciphertext,
                                size_t *ciphertext_len,
                                uint8_t out_tag[16]) {
  size_t i;
  uint8_t mac_input[64];
  if (plaintext == NULL || ciphertext == NULL || ciphertext_len == NULL || out_tag == NULL) {
    return false;
  }
  if (*ciphertext_len < plaintext_len) {
    return false;
  }
  for (i = 0u; i < plaintext_len; ++i) {
    ciphertext[i] = plaintext[i] ^ 0xA5u;
  }
  *ciphertext_len = plaintext_len;
  memset(mac_input, 0, sizeof(mac_input));
  for (i = 0u; i < plaintext_len && i < sizeof(mac_input); ++i) {
    mac_input[i] ^= plaintext[i];
  }
  for (i = 0u; i < aad_len && i < sizeof(mac_input); ++i) {
    mac_input[i] ^= aad[i];
  }
  crypto_stub_hash16(mac_input, sizeof(mac_input), out_tag);
  security_secure_zero(mac_input, sizeof(mac_input));
  return true;
}

bool crypto_engine_decrypt_aead(const uint8_t *ciphertext,
                                size_t ciphertext_len,
                                const uint8_t *aad,
                                size_t aad_len,
                                const uint8_t tag[16],
                                uint8_t *plaintext,
                                size_t *plaintext_len) {
  size_t i;
  uint8_t expected_tag[16];
  uint8_t mac_input[64];

  if (ciphertext == NULL || plaintext == NULL || plaintext_len == NULL || tag == NULL) {
    return false;
  }
  if (*plaintext_len < ciphertext_len) {
    return false;
  }
  for (i = 0u; i < ciphertext_len; ++i) {
    plaintext[i] = ciphertext[i] ^ 0xA5u;
  }
  *plaintext_len = ciphertext_len;

  memset(mac_input, 0, sizeof(mac_input));
  for (i = 0u; i < ciphertext_len && i < sizeof(mac_input); ++i) {
    mac_input[i] ^= plaintext[i];
  }
  for (i = 0u; i < aad_len && i < sizeof(mac_input); ++i) {
    mac_input[i] ^= aad[i];
  }
  crypto_stub_hash16(mac_input, sizeof(mac_input), expected_tag);
  if (!sec_consttime_memeq(expected_tag, tag, 16u)) {
    security_secure_zero(expected_tag, sizeof(expected_tag));
    security_secure_zero(mac_input, sizeof(mac_input));
    security_secure_zero(plaintext, ciphertext_len);
    return false;
  }
  security_secure_zero(expected_tag, sizeof(expected_tag));
  security_secure_zero(mac_input, sizeof(mac_input));
  return true;
}
