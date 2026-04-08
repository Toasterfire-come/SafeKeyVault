#include "crypto_engine.h"

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "crypto_stub.h"
#include "security_policy.h"
#include "security_utils.h"

typedef struct {
  bool initialized;
  bool secure_element_bound;
  uint8_t secure_element_slot;
  uint8_t secure_element_pubkey[64];
  size_t secure_element_pubkey_len;
} crypto_engine_state_t;

static crypto_engine_state_t g_crypto_state;
static uint32_t g_password_nonce_counter = 1u;

static size_t bounded_strlen(const char *s, size_t max_len) {
  size_t i = 0u;
  if (s == NULL) {
    return 0u;
  }
  while (i < max_len && s[i] != '\0') {
    i++;
  }
  return i;
}

static bool hex_encode(const uint8_t *in,
                       size_t in_len,
                       char *out,
                       size_t out_cap,
                       size_t *out_len) {
  static const char k_hex[] = "0123456789abcdef";
  size_t i;
  if (in == NULL || out == NULL || out_cap == 0u) {
    return false;
  }
  if ((in_len * 2u) + 1u > out_cap) {
    return false;
  }
  for (i = 0u; i < in_len; ++i) {
    out[(i * 2u)] = k_hex[(in[i] >> 4u) & 0x0Fu];
    out[(i * 2u) + 1u] = k_hex[in[i] & 0x0Fu];
  }
  out[in_len * 2u] = '\0';
  if (out_len != NULL) {
    *out_len = in_len * 2u;
  }
  return true;
}

static int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return (c - 'a') + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return (c - 'A') + 10;
  }
  return -1;
}

static bool hex_decode(const char *in,
                       size_t in_len,
                       uint8_t *out,
                       size_t out_cap,
                       size_t *out_len) {
  size_t i;
  if (in == NULL || out == NULL) {
    return false;
  }
  if ((in_len % 2u) != 0u) {
    return false;
  }
  if ((in_len / 2u) > out_cap) {
    return false;
  }
  for (i = 0u; i < in_len; i += 2u) {
    int hi = hex_value(in[i]);
    int lo = hex_value(in[i + 1u]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out[i / 2u] = (uint8_t)(((uint8_t)hi << 4u) | (uint8_t)lo);
  }
  if (out_len != NULL) {
    *out_len = in_len / 2u;
  }
  return true;
}

static void next_password_nonce(uint8_t nonce[12]) {
  uint8_t seed[16];
  uint8_t hash[16];
  if (nonce == NULL) {
    return;
  }
  memset(seed, 0, sizeof(seed));
  memcpy(seed, &g_password_nonce_counter, sizeof(g_password_nonce_counter));
  g_password_nonce_counter++;
  crypto_stub_hash16(seed, sizeof(seed), hash);
  memcpy(nonce, hash, 12u);
  security_secure_zero(seed, sizeof(seed));
  security_secure_zero(hash, sizeof(hash));
}

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
  uint8_t nonce[12];
  uint8_t tag[16];
  uint8_t ciphertext[PASSWORD_MAX_LENGTH];
  size_t plaintext_len;
  size_t ciphertext_len = sizeof(ciphertext);
  char nonce_hex[25];
  char tag_hex[33];
  char ciphertext_hex[(PASSWORD_MAX_LENGTH * 2u) + 1u];
  int n;

  if (plaintext == NULL || ciphertext_out == NULL || out_len == 0u) {
    return false;
  }
  plaintext_len = bounded_strlen(plaintext, PASSWORD_MAX_LENGTH);
  if (plaintext_len == 0u || plaintext[plaintext_len] != '\0') {
    return false;
  }

  next_password_nonce(nonce);
  if (!crypto_engine_encrypt_aead((const uint8_t *)plaintext, plaintext_len,
                                  nonce, sizeof(nonce),
                                  ciphertext, sizeof(ciphertext),
                                  &ciphertext_len, tag)) {
    return false;
  }
  if (!hex_encode(nonce, sizeof(nonce), nonce_hex, sizeof(nonce_hex), NULL) ||
      !hex_encode(tag, sizeof(tag), tag_hex, sizeof(tag_hex), NULL) ||
      !hex_encode(ciphertext, ciphertext_len, ciphertext_hex, sizeof(ciphertext_hex), NULL)) {
    security_secure_zero(ciphertext, sizeof(ciphertext));
    security_secure_zero(tag, sizeof(tag));
    security_secure_zero(nonce, sizeof(nonce));
    return false;
  }
  n = snprintf(ciphertext_out, out_len, "v1:%s:%s:%s", nonce_hex, tag_hex, ciphertext_hex);
  security_secure_zero(ciphertext, sizeof(ciphertext));
  security_secure_zero(tag, sizeof(tag));
  security_secure_zero(nonce, sizeof(nonce));
  return n > 0 && (size_t)n < out_len;
}

bool crypto_engine_decrypt_password(const char *ciphertext,
                                    char *plaintext_out,
                                    size_t out_len) {
  const char *nonce_hex;
  const char *tag_hex;
  const char *ciphertext_hex;
  const char *sep1;
  const char *sep2;
  size_t nonce_hex_len;
  size_t tag_hex_len;
  size_t ciphertext_hex_len;
  uint8_t nonce[12];
  uint8_t tag[16];
  uint8_t ciphertext_bytes[PASSWORD_MAX_LENGTH];
  size_t ciphertext_len = 0u;
  size_t plaintext_len;

  if (ciphertext == NULL || plaintext_out == NULL || out_len < 2u) {
    return false;
  }
  plaintext_out[0] = '\0';
  if (strncmp(ciphertext, "v1:", 3u) != 0) {
    return false;
  }

  nonce_hex = ciphertext + 3u;
  sep1 = strchr(nonce_hex, ':');
  if (sep1 == NULL) {
    return false;
  }
  tag_hex = sep1 + 1u;
  sep2 = strchr(tag_hex, ':');
  if (sep2 == NULL) {
    return false;
  }
  ciphertext_hex = sep2 + 1u;

  nonce_hex_len = (size_t)(sep1 - nonce_hex);
  tag_hex_len = (size_t)(sep2 - tag_hex);
  ciphertext_hex_len = strlen(ciphertext_hex);

  if (nonce_hex_len != 24u || tag_hex_len != 32u || ciphertext_hex_len == 0u) {
    return false;
  }
  if (!hex_decode(nonce_hex, nonce_hex_len, nonce, sizeof(nonce), NULL) ||
      !hex_decode(tag_hex, tag_hex_len, tag, sizeof(tag), NULL) ||
      !hex_decode(ciphertext_hex, ciphertext_hex_len, ciphertext_bytes, sizeof(ciphertext_bytes), &ciphertext_len)) {
    return false;
  }

  plaintext_len = out_len - 1u;
  if (!crypto_engine_decrypt_aead(ciphertext_bytes, ciphertext_len,
                                  nonce, sizeof(nonce),
                                  tag,
                                  (uint8_t *)plaintext_out, plaintext_len,
                                  &plaintext_len)) {
    security_secure_zero(ciphertext_bytes, sizeof(ciphertext_bytes));
    security_secure_zero(tag, sizeof(tag));
    security_secure_zero(nonce, sizeof(nonce));
    return false;
  }
  plaintext_out[plaintext_len] = '\0';
  security_secure_zero(ciphertext_bytes, sizeof(ciphertext_bytes));
  security_secure_zero(tag, sizeof(tag));
  security_secure_zero(nonce, sizeof(nonce));
  return true;
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
                                size_t ciphertext_capacity,
                                size_t *ciphertext_len,
                                uint8_t out_tag[16]) {
  size_t i;
  uint8_t mac_input[64];
  if (plaintext == NULL || ciphertext == NULL || ciphertext_len == NULL || out_tag == NULL) {
    return false;
  }
  if (ciphertext_capacity < plaintext_len || *ciphertext_len < plaintext_len) {
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
                                size_t plaintext_capacity,
                                size_t *plaintext_len) {
  size_t i;
  uint8_t expected_tag[16];
  uint8_t mac_input[64];

  if (ciphertext == NULL || plaintext == NULL || plaintext_len == NULL || tag == NULL) {
    return false;
  }
  if (plaintext_capacity < ciphertext_len || *plaintext_len < ciphertext_len) {
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
