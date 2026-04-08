#ifndef SECURE_BOOT_H
#define SECURE_BOOT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t image_version;
  uint32_t minimum_allowed_version;
  uint8_t image_hash[32];
  uint8_t signature[64];
  uint8_t signer_pubkey[64];
  size_t signer_pubkey_len;
} secure_boot_image_t;

void secure_boot_init(uint32_t minimum_allowed_version);
bool secure_boot_set_minimum_version(uint32_t minimum_allowed_version);
uint32_t secure_boot_get_minimum_version(void);
bool secure_boot_verify_image(const secure_boot_image_t *image);

#endif /* SECURE_BOOT_H */
