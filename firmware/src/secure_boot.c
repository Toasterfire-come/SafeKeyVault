#include "secure_boot.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h"

typedef struct {
  bool initialized;
  bool key_set;
  uint8_t verify_key[64];
  size_t verify_key_len;
  uint32_t min_allowed_version;
} secure_boot_state_t;

static secure_boot_state_t g_secure_boot;

void secure_boot_init(void) {
  memset(&g_secure_boot, 0, sizeof(g_secure_boot));
  g_secure_boot.initialized = true;
}

void secure_boot_set_min_version(uint32_t min_version) {
  if (!g_secure_boot.initialized) {
    secure_boot_init();
  }
  g_secure_boot.min_allowed_version = min_version;
}

bool secure_boot_set_verify_key(const uint8_t *key, size_t key_len) {
  if (key == NULL || key_len == 0u || key_len > sizeof(g_secure_boot.verify_key)) {
    return false;
  }
  if (!g_secure_boot.initialized) {
    secure_boot_init();
  }
  memcpy(g_secure_boot.verify_key, key, key_len);
  g_secure_boot.verify_key_len = key_len;
  g_secure_boot.key_set = true;
  return true;
}

bool secure_boot_verify_image(const secure_boot_image_t *image,
                              const uint8_t *signature,
                              size_t signature_len) {
  uint8_t digest[16];
  uint8_t expected_sig[16];
  if (!g_secure_boot.initialized || image == NULL || signature == NULL) {
    return false;
  }
  if (!g_secure_boot.key_set) {
    return false;
  }
  if (image->payload == NULL || image->payload_len == 0u) {
    return false;
  }
  if (image->version < g_secure_boot.min_allowed_version) {
    return false;
  }
  if (signature_len != sizeof(expected_sig)) {
    return false;
  }

  crypto_engine_hash16(image->payload, image->payload_len, digest);
  for (size_t i = 0u; i < sizeof(expected_sig); ++i) {
    expected_sig[i] = digest[i] ^ g_secure_boot.verify_key[i % g_secure_boot.verify_key_len];
  }
  return sec_consttime_memeq(expected_sig, signature, sizeof(expected_sig));
}

