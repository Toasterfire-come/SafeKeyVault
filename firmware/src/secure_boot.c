#include "secure_boot.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h"
#include "security_utils.h"
#include "spi_hal.h" // Assuming SPI HAL for flash access
#include "atecc608a_driver.h" // Assuming ATECC608A driver
#include "build_config.h" // For FIRMWARE_PRODUCTION

// Define the size of the ECDSA P-256 signature (64 bytes for R and S components)
#define ECDSA_P256_SIGNATURE_LEN 64u
// Define the size of the firmware image hash
#define FIRMWARE_HASH_LEN 32u
// Define the ATECC608A slot for storing the anti-rollback version counter
#define ATECC608A_SLOT_VERSION_COUNTER 7u
// Define the size of the version counter stored in the ATECC slot
#define VERSION_COUNTER_LEN sizeof(uint32_t)

// Define the offset for the firmware signature in the last flash sector.
// This assumes the signature is located at a specific offset within the last sector.
// In a real system, this offset would be determined by the linker script or build process.
#define FIRMWARE_SIGNATURE_OFFSET (FLASH_SECTOR_SIZE - ECDSA_P256_SIGNATURE_LEN)

typedef struct {
  bool initialized;
  secure_boot_policy_t policy;
  uint8_t signing_pubkey[64]; // Public key for signature verification
  size_t signing_pubkey_len;
  bool signing_key_set;
  uint32_t current_version; // Current firmware version
} secure_boot_state_t;

static secure_boot_state_t g_secure_boot;

// Function to read the firmware signature from the last flash sector
static bool read_firmware_signature(uint8_t signature[ECDSA_P256_SIGNATURE_LEN]) {
    uint8_t flash_sector_buffer[FLASH_SECTOR_SIZE]; // Assuming FLASH_SECTOR_SIZE is defined elsewhere
    size_t bytes_read;

    // Read the last flash sector
    if (spi_hal_read_sector(FLASH_LAST_SECTOR_ADDRESS, flash_sector_buffer, sizeof(flash_sector_buffer), &bytes_read) != SPI_HAL_SUCCESS) {
#if !FIRMWARE_PRODUCTION
        // Example debug logging:
        // printf("Secure Boot: Failed to read firmware signature from flash.\n");
#endif
        return false; // Failed to read flash sector
    }

    // Extract the signature from the buffer
    if (bytes_read < (FIRMWARE_SIGNATURE_OFFSET + ECDSA_P256_SIGNATURE_LEN)) {
#if !FIRMWARE_PRODUCTION
        // Example debug logging:
        // printf("Secure Boot: Not enough data in flash sector for signature.\n");
#endif
        return false; // Not enough data in the sector for the signature
    }
    memcpy(signature, flash_sector_buffer + FIRMWARE_SIGNATURE_OFFSET, ECDSA_P256_SIGNATURE_LEN);
    return true;
}

// Function to read the firmware version from the ATECC608A slot
static bool read_version_from_atecc(uint32_t *version) {
    uint8_t version_data[VERSION_COUNTER_LEN];
    if (!g_secure_boot.initialized || !g_secure_boot.policy.enforce_antiroolback) {
        return false;
    }

    if (atecc608a_read_slot(ATECC608A_SLOT_VERSION_COUNTER, version_data, VERSION_COUNTER_LEN) == ATECC608A_SUCCESS) {
        memcpy(version, version_data, VERSION_COUNTER_LEN);
        return true;
    }
#if !FIRMWARE_PRODUCTION
    // Example debug logging:
    // printf("Secure Boot: Failed to read version counter from ATECC.\n");
#endif
    return false; // Indicate failure to read
}

// Function to write the firmware version to the ATECC608A slot
static bool write_version_to_atecc(uint32_t version) {
    uint8_t version_data[VERSION_COUNTER_LEN];
    if (!g_secure_boot.initialized || !g_secure_boot.policy.enforce_antiroolback) {
        return false;
    }

    memcpy(version_data, &version, VERSION_COUNTER_LEN);
    if (atecc608a_write_slot(ATECC608A_SLOT_VERSION_COUNTER, version_data, VERSION_COUNTER_LEN) == ATECC608A_SUCCESS) {
        return true;
    }
#if !FIRMWARE_PRODUCTION
    // Example debug logging:
    // printf("Secure Boot: Failed to write version counter to ATECC.\n");
#endif
    return false; // Indicate failure to write
}


void secure_boot_init(void) {
  memset(&g_secure_boot, 0, sizeof(g_secure_boot));
  g_secure_boot.initialized = true;
  // Initialize policy with defaults, can be overridden by secure_boot_set_policy
  g_secure_boot.policy.enforce_signature = true;
  g_secure_boot.policy.enforce_antiroolback = true;
  g_secure_boot.policy.min_allowed_version = 0; // No minimum by default

  // Initialize hardware drivers
  spi_hal_init();
  atecc608a_init();
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
  uint8_t firmware_signature[ECDSA_P256_SIGNATURE_LEN];
  uint32_t stored_version;
  bool signature_ok = false;
  bool rollback_ok = false;

  if (out_result == NULL) {
    return false;
  }
  memset(out_result, 0, sizeof(*out_result));
  if (!g_secure_boot.initialized || manifest == NULL || payload_hash == NULL) {
    return false;
  }
  if (payload_hash_len != FIRMWARE_HASH_LEN) {
#if !FIRMWARE_PRODUCTION
    // Example debug logging:
    // printf("Secure Boot: Payload hash length mismatch (%zu != %d).\n", payload_hash_len, FIRMWARE_HASH_LEN);
#endif
    return false; // Hash length mismatch
  }

  // 1. Verify Firmware Signature
  if (g_secure_boot.policy.enforce_signature) {
    if (!g_secure_boot.signing_key_set) {
      // Signing public key not set, cannot verify signature
      out_result->signature_valid = false;
#if !FIRMWARE_PRODUCTION
      // Example debug logging:
      // printf("Secure Boot: Signature verification failed - signing key not set.\n");
#endif
    } else {
      // Read signature from the last flash sector
      if (read_firmware_signature(firmware_signature)) {
        // Verify signature using ECDSA P-256 via crypto engine
        if (crypto_engine_ecdsa_verify(g_secure_boot.signing_pubkey,
                                       g_secure_boot.signing_pubkey_len,
                                       payload_hash,
                                       payload_hash_len,
                                       firmware_signature,
                                       ECDSA_P256_SIGNATURE_LEN)) {
          signature_ok = true;
        }
      }
      out_result->signature_valid = signature_ok;
#if !FIRMWARE_PRODUCTION
      if (!signature_ok) {
          // Example debug logging:
          // printf("Secure Boot: Signature verification failed.\n");
      }
#endif
    }
  } else {
    out_result->signature_valid = true; // Signature enforcement is disabled
  }

  // 2. Verify Anti-Rollback Counter
  if (g_secure_boot.policy.enforce_antiroolback) {
    // Read the stored version from ATECC608A slot 7
    if (read_version_from_atecc(&stored_version)) {
        // Check if the manifest version is greater than or equal to the stored version
        if (manifest->version >= stored_version) {
            rollback_ok = true;
        }
    } else {
        // If version cannot be read from ATECC, assume it's okay if min_allowed_version is 0
        // or if the manifest version meets the minimum policy.
        if (manifest->version >= g_secure_boot.policy.min_allowed_version) {
            rollback_ok = true;
        }
    }
    out_result->antirollback_ok = rollback_ok;
#if !FIRMWARE_PRODUCTION
    if (!rollback_ok) {
        // Example debug logging:
        // printf("Secure Boot: Anti-rollback check failed (Manifest version: %u, Stored version: %u).\n", manifest->version, stored_version);
    }
#endif
  } else {
    out_result->antirollback_ok = true; // Anti-rollback enforcement is disabled
  }

  // 3. Final Acceptance
  out_result->accepted = out_result->signature_valid && out_result->antirollback_ok;

  // If the new firmware is accepted, update the version counter in ATECC
  if (out_result->accepted && g_secure_boot.policy.enforce_antiroolback) {
      if (!write_version_to_atecc(manifest->version)) {
          // Failed to update version counter, this is a critical error.
          // The device might enter a locked state or require manual intervention.
          out_result->accepted = false; // Reject if version update fails
#if !FIRMWARE_PRODUCTION
          // Example debug logging:
          // printf("Secure Boot: CRITICAL - Failed to update version counter after acceptance.\n");
#endif
      }
  }

  return true;
}
