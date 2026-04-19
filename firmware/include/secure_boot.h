#ifndef SECURE_BOOT_H
#define SECURE_BOOT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Define the size of the ECDSA P-256 signature
#define ECDSA_P256_SIGNATURE_LEN 64u
// Define the size of the firmware image hash
#define FIRMWARE_HASH_LEN 32u

// Assuming these are defined elsewhere, e.g., in a board configuration header
#define FLASH_SECTOR_SIZE 4096u // Example sector size
#define FLASH_LAST_SECTOR_ADDRESS 0x08000000 // Example address of the last sector

typedef struct {
  uint32_t version;
  uint32_t payload_size;
} secure_boot_manifest_t;

typedef struct {
  bool enforce_signature;
  bool enforce_antirollback;
  uint32_t min_allowed_version;
} secure_boot_policy_t;

typedef struct {
  bool signature_valid;
  bool antirollback_ok; // Corrected typo from antiroolback_ok
  bool accepted;
} secure_boot_result_t;

void secure_boot_init(void);
void secure_boot_set_policy(const secure_boot_policy_t *policy);
// secure_boot_set_signing_pubkey is removed as the public key will be passed directly during verification.
void secure_boot_set_current_version(uint32_t current_version); // Sets the current version of the running firmware.

/**
 * @brief Verifies the authenticity and integrity of a new firmware manifest.
 *
 * This function performs signature verification and anti-rollback checks.
 *
 * @param new_firmware_version The version number of the new firmware being verified.
 * @param manifest_hash The cryptographic hash of the firmware manifest.
 * @param manifest_hash_len The length of the manifest_hash (expected 32 bytes for SHA256).
 * @param manifest_signature The ECDSA signature of the manifest_hash.
 * @param manifest_signature_len The length of the manifest_signature (expected 64 bytes for P256).
 * @param trusted_public_key The trusted public key used to verify the signature.
 * @param trusted_public_key_len The length of the trusted_public_key (expected 64 bytes for P256).
 * @param out_result Pointer to a secure_boot_result_t structure to store detailed verification results.
 * @return true if all verification checks pass and the firmware is accepted, false otherwise.
 */
bool secure_boot_verify_manifest(uint32_t new_firmware_version,
                                 const uint8_t *manifest_hash,
                                 size_t manifest_hash_len,
                                 const uint8_t *manifest_signature,
                                 size_t manifest_signature_len,
                                 const uint8_t *trusted_public_key,
                                 size_t trusted_public_key_len,
                                 secure_boot_result_t *out_result);

#endif /* SECURE_BOOT_H */
