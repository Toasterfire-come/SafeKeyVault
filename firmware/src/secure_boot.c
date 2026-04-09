#include "secure_boot.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h"
#include "security_utils.h"

typedef struct {
  bool initialized;
  secure_boot_policy_t policy;
  uint8_t signing_pubkey[64];
  size_t signing_pubkey_len;
  bool signing_key_set;
  uint32_t current_version;
} secure_boot_state_t;

static secure_boot_state_t g_secure_boot;

void secure_boot_init(void) {
  memset(&g_secure_boot, 0, sizeof(g_secure_boot));
  g_secure_boot.initialized = true;
}

void secure_boot_set_policy(const secure_boot_policy_t *policy) {
  if (!g_secure_boot.initialized) {
    secure_boot_init();
  }
  if (policy == NULL) {
    return;
  }
  g_secure_boot.policy = *policy;
}

void secure_boot_set_current_version(uint32_t version) {
  if (!g_secure_boot.initialized) {
    secure_boot_init();
  }
  g_secure_boot.current_version = version;
}

bool secure_boot_set_signing_pubkey(const uint8_t *pubkey, size_t pubkey_len) {
  if (pubkey == NULL || pubkey_len == 0u || pubkey_len > sizeof(g_secure_boot.signing_pubkey)) {
    return false;
  }
  if (!g_secure_boot.initialized) {
    secure_boot_init();
  }
  memcpy(g_secure_boot.signing_pubkey, pubkey, pubkey_len);
  g_secure_boot.signing_pubkey_len = pubkey_len;
  g_secure_boot.signing_key_set = true;
  return true;
}

bool secure_boot_verify_manifest(const secure_boot_manifest_t *manifest,
                                 const uint8_t *payload_hash,
                                 size_t payload_hash_len,
                                 secure_boot_result_t *out_result) {
  uint8_t expected_sig[16];
  size_t i;

  if (out_result == NULL) {
    return false;
  }
  memset(out_result, 0, sizeof(*out_result));
  if (!g_secure_boot.initialized || manifest == NULL || payload_hash == NULL) {
    return false;
  }
  if (payload_hash_len == 0u) {
    return false;
  }
  if (g_secure_boot.policy.enforce_antiroolback) {
    out_result->antiroolback_ok =
        (manifest->version >= g_secure_boot.policy.min_allowed_version) &&
        (manifest->version >= g_secure_boot.current_version);
  } else {
    out_result->antiroolback_ok = true;
  }

  if (!g_secure_boot.policy.enforce_signature) {
    out_result->signature_valid = true;
  } else {
    if (!g_secure_boot.signing_key_set) {
      out_result->signature_valid = false;
    } else {
      memset(expected_sig, 0, sizeof(expected_sig));
      for (i = 0u; i < sizeof(expected_sig) && i < payload_hash_len; ++i) {
        expected_sig[i] = payload_hash[i] ^ g_secure_boot.signing_pubkey[i % g_secure_boot.signing_pubkey_len];
      }
      out_result->signature_valid = sec_consttime_memeq(expected_sig,
                                                        payload_hash,
                                                        sizeof(expected_sig));
    }
  }

  out_result->accepted = out_result->signature_valid && out_result->antiroolback_ok;
  return true;
}

