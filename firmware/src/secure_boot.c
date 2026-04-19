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

// Include necessary headers
#include "secure_boot.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h"      // For crypto_engine_ecdsa_verify
#include "security_utils.h"     // For security_secure_zero
#include "atecc608a_driver.h"   // For ATECC access for anti-rollback
#include "build_config.h"       // For FIRMWARE_PRODUCTION
#include "main.h"               // For Error_Handler and other global definitions if needed

// Define the ATECC608A slot for storing the anti-rollback version counter
#define ATECC608A_SLOT_VERSION_COUNTER 7u
// Define the size of the version counter stored in the ATECC slot
#define VERSION_COUNTER_LEN sizeof(uint32_t)

typedef struct {
  bool initialized;
  secure_boot_policy_t policy;
  uint32_t current_running_version; // Current RUNNING firmware version for anti-rollback logic
} secure_boot_state_t;

static secure_boot_state_t g_secure_boot;

// Function to read the firmware version from the ATECC608A slot
static bool read_version_from_atecc(uint32_t *version) {
    uint8_t version_data[VERSION_COUNTER_LEN] = {0}; // Initialize for security
    bool success = false;

    // ATECC availability checked by atecc608a_read_slot.
    // Policy enforcement is handled by the caller.
    if (version == NULL) {
        goto end;
    }

    if (atecc608a_read_slot(ATECC608A_SLOT_VERSION_COUNTER, version_data, VERSION_COUNTER_LEN)) {
        memcpy(version, version_data, VERSION_COUNTER_LEN);
        success = true;
    }
end:
    security_secure_zero(version_data, sizeof(version_data)); // Zeroize sensitive version data
    return success;
}

// Function to write the firmware version to the ATECC608A slot
static bool write_version_to_atecc(uint32_t version) {
    uint8_t version_data[VERSION_COUNTER_LEN] = {0}; // Initialize for security
    bool success = false;

    // ATECC availability checked by atecc608a_write_slot.
    // Policy enforcement is handled by the caller.
    
    memcpy(version_data, &version, VERSION_COUNTER_LEN);
    if (atecc608a_write_slot(ATECC608A_SLOT_VERSION_COUNTER, version_data, VERSION_COUNTER_LEN)) {
        success = true;
    }
end:
    security_secure_zero(version_data, sizeof(version_data)); // Zeroize sensitive version data
    return success;
}


void secure_boot_init(void) {
  memset(&g_secure_boot, 0, sizeof(g_secure_boot));
  g_secure_boot.initialized = true;
  g_secure_boot.policy.enforce_signature = true;
  g_secure_boot.policy.enforce_antirollback = true;
  g_secure_boot.policy.min_allowed_version = 0; // No minimum by default

  // Check ATECC availability for anti-rollback. If not available in production, it's critical.
  if (!atecc608a_is_available()) {
#if FIRMWARE_PRODUCTION
      Error_Handler(); // Halt if ATECC is unavailable in production, as anti-rollback may fail.
#else
      // In dev, anti-rollback may not be enforced if ATECC is absent.
      g_secure_boot.policy.enforce_antirollback = false;
#endif
  }

  // Read the current stored anti-rollback version from ATECC slot 7 immediately upon init.
  // This value determines the minimum allowed version for any new firmware.
  uint32_t stored_version_on_init = 0;
  if (g_secure_boot.policy.enforce_antirollback && !read_version_from_atecc(&stored_version_on_init)) {
#if FIRMWARE_PRODUCTION
      // In production, failure to read the version counter is a critical error.
      // Halt the device. (Error_Handler will reset/lock device)
      Error_Handler();
#else
      // In development, assume 0 as an initial version if read fails for an enforced policy.
      // Or, we might disable anti-rollback during dev if ATECC read fails.
      stored_version_on_init = 0;
#endif
  }
  g_secure_boot.current_running_version = stored_version_on_init;
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
  g_secure_boot.current_running_version = version;
}

// `secure_boot_set_signing_pubkey` is removed as the public key is passed directly to `secure_boot_verify_manifest`.

bool secure_boot_verify_manifest(uint32_t new_firmware_version,
                                 const uint8_t *manifest_hash,
                                 size_t manifest_hash_len,
                                 const uint8_t *manifest_signature,
                                 size_t manifest_signature_len,
                                 const uint8_t *trusted_public_key,
                                 size_t trusted_public_key_len,
                                 secure_boot_result_t *out_result) {
  uint32_t stored_min_version = 0; // Version from ATECC anti-rollback
  bool signature_ok = false;
  bool rollback_ok = false;
  bool overall_success = false;

  if (out_result == NULL) {
    return false;
  }
  memset(out_result, 0, sizeof(*out_result)); // Zeroize result structure
  
  // Basic parameter validation
  if (!g_secure_boot.initialized || manifest_hash == NULL || manifest_signature == NULL || trusted_public_key == NULL) {
    return false;
  }
  // FIRMWARE_HASH_LEN and ECDSA_P256_SIGNATURE_LEN are defined in secure_boot.h.
  // The trusted_public_key_len for P256 is 64 bytes.
  if (manifest_hash_len != FIRMWARE_HASH_LEN || manifest_signature_len != ECDSA_P256_SIGNATURE_LEN || trusted_public_key_len != 64) {
#if !FIRMWARE_PRODUCTION
    // printf("Secure Boot: Input length mismatch.\n");
#endif
    return false;
  }

  // 1. Verify Firmware Signature using crypto_engine_ecdsa_verify
  if (g_secure_boot.policy.enforce_signature) {
    // Check if ATECC is available and ready for verification first
    if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_ECDSA_VERIFY)) {
#if FIRMWARE_PRODUCTION
        Error_Handler(); // Cannot perform signature verification securely
#endif
        return false; // Cannot proceed without secure element capability
    }

    if (crypto_engine_ecdsa_verify(trusted_public_key,
                                   trusted_public_key_len,
                                   manifest_hash,
                                   manifest_hash_len,
                                   manifest_signature,
                                   manifest_signature_len)) {
      signature_ok = true;
    } else {
      signature_ok = false;
    }
  } else {
    signature_ok = true; // Signature enforcement is disabled
  }
  out_result->signature_valid = signature_ok;


  // 2. Verify Anti-Rollback Counter
  if (g_secure_boot.policy.enforce_antirollback) {
    if (read_version_from_atecc(&stored_min_version)) {
        if (new_firmware_version < stored_min_version) {
            rollback_ok = false; // Downgrade detected, immediately reject
        } else { // new_firmware_version >= stored_min_version
            rollback_ok = true; // Upgrade or same version allowed
        }
    } else {
        // If version cannot be read from ATECC in production, it's a critical error.
#if FIRMWARE_PRODUCTION
        Error_Handler(); // Halt as anti-rollback cannot be checked securely.
#endif
        rollback_ok = false; // Cannot proceed without a reliable anti-rollback counter.
    }
    out_result->antirollback_ok = rollback_ok;
  } else {
    out_result->antirollback_ok = true; // Anti-rollback enforcement is disabled
  }

  // 3. Final Acceptance
  out_result->accepted = out_result->signature_valid && out_result->antirollback_ok;

  // If the new firmware is accepted AND anti-rollback is enforced, update the version counter in ATECC
  if (out_result->accepted && g_secure_boot.policy.enforce_antirollback) {
      // Only write if the new firmware version is greater than the currently stored minimum version.
      if (new_firmware_version > stored_min_version) {
          if (!write_version_to_atecc(new_firmware_version)) {
              // Failed to update version counter. This is a critical error.
              out_result->accepted = false; // Reject if version update fails
#if FIRMWARE_PRODUCTION
              Error_Handler(); // Critical error: cannot update anti-rollback counter.
#endif
          }
      }
  }
  overall_success = out_result->accepted; // Overall success reflects final acceptance.

  return overall_success;
}
