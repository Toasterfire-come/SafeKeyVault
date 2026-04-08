#ifndef SECURE_BOOT_H
#define SECURE_BOOT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t version;
  uint32_t payload_size;
} secure_boot_manifest_t;

typedef struct {
  bool enforce_signature;
  bool enforce_antiroolback;
  uint32_t min_allowed_version;
} secure_boot_policy_t;

typedef struct {
  bool signature_valid;
  bool antiroolback_ok;
  bool accepted;
} secure_boot_result_t;

void secure_boot_init(void);
void secure_boot_set_policy(const secure_boot_policy_t *policy);
bool secure_boot_set_signing_pubkey(const uint8_t *pubkey, size_t pubkey_len);
void secure_boot_set_current_version(uint32_t current_version);
bool secure_boot_verify_manifest(const secure_boot_manifest_t *manifest,
                                 const uint8_t *payload_hash,
                                 size_t payload_hash_len,
                                 secure_boot_result_t *out_result);

#endif /* SECURE_BOOT_H */
