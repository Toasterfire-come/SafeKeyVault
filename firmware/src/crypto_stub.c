#include "crypto_stub.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static uint8_t g_master_key[32];
static size_t g_master_key_len = 0u;

void crypto_stub_set_master_key(const uint8_t *key, size_t key_len) {
  if (key == NULL || key_len == 0u) {
    g_master_key_len = 0u;
    memset(g_master_key, 0, sizeof(g_master_key));
    return;
  }
  if (key_len > sizeof(g_master_key)) {
    key_len = sizeof(g_master_key);
  }
  memcpy(g_master_key, key, key_len);
  g_master_key_len = key_len;
}

bool crypto_stub_encrypt_password(const char *plaintext, char *ciphertext_out, size_t out_len) {
  size_t i;
  if (plaintext == NULL || ciphertext_out == NULL || out_len == 0u) {
    return false;
  }
  ciphertext_out[0] = '\0';
  // For tests, operate even without a configured key. Use a default if none set.
  if (g_master_key_len == 0u) {
    const uint8_t default_key[32] = {0x5A}; // Use a single byte default key
    crypto_stub_set_master_key(default_key, sizeof(default_key));
  }
  for (i = 0u; plaintext[i] != '\0' && i + 1u < out_len; ++i) {
    uint8_t p = (uint8_t)plaintext[i];
    uint8_t k = g_master_key[i % g_master_key_len];
    ciphertext_out[i] = (char)(p ^ k);
  }
  ciphertext_out[i] = '\0';
  return true;
}

bool crypto_stub_decrypt_password(const char *ciphertext, char *plaintext_out, size_t out_len) {
  size_t i;
  if (ciphertext == NULL || plaintext_out == NULL || out_len == 0u) {
    return false;
  }
  plaintext_out[0] = '\0';
  // For tests, operate even without a configured key. Use a default if none set.
  if (g_master_key_len == 0u) {
    const uint8_t default_key[32] = {0x5A}; // Use a single byte default key
    crypto_stub_set_master_key(default_key, sizeof(default_key));
  }
  for (i = 0u; ciphertext[i] != '\0' && i + 1u < out_len; ++i) {
    uint8_t c = (uint8_t)ciphertext[i];
    uint8_t k = g_master_key[i % g_master_key_len];
    plaintext_out[i] = (char)(c ^ k);
  }
  plaintext_out[i] = '\0';
  return true;
}

void crypto_stub_password_fingerprint(const char *password, uint8_t out_fp[16], size_t out_len) {
  uint32_t h = 2166136261u; // FNV-1a initial hash value
  size_t i = 0u;
  if (out_fp == NULL || out_len == 0u) {
    return;
  }
  memset(out_fp, 0, out_len); // Zero out the output buffer
  if (password == NULL) {
    return; // No password, return zeroed buffer
  }
  while (password[i] != '\0') {
    h ^= (uint8_t)password[i];
    h *= 16777619u; // FNV-1a prime
    // XOR the hash byte into the output buffer to mix it in.
    // This is a simple mixing, not a cryptographic hash.
    out_fp[i % out_len] ^= (uint8_t)(h & 0xFFu);
    i++;
  }
}

void crypto_stub_hash16(const uint8_t *data, size_t data_len, uint8_t out_fp[16]) {
  uint32_t h = 2166136261u; // FNV-1a initial hash value
  size_t i;
  if (out_fp == NULL) {
    return;
  }
  memset(out_fp, 0, 16u); // Zero out the output buffer
  if (data == NULL) {
    return; // No data, return zeroed buffer
  }
  for (i = 0u; i < data_len; ++i) {
    h ^= data[i];
    h *= 16777619u; // FNV-1a prime
    // XOR the hash byte into the output buffer to mix it in.
    // This is a simple mixing, not a cryptographic hash.
    out_fp[i % 16u] ^= (uint8_t)(h & 0xFFu);
  }
}
