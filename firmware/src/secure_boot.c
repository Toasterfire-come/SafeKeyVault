#include "secure_boot.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h"
#include "security_utils.h"
#include "spi_hal.h" // Assuming SPI HAL for flash access
#include "atecc608a_driver.h" // Assuming ATECC608A driver
#include "build_config.h" // For FIRMWARE_PRODUCTION
#include "main.h" // For Error_Handler

// Define the size of the ECDSA P-256 signature (64 bytes for R and S components)
#define ECDSA_P256_SIGNATURE_LEN 64u
// Define the size of the firmware image hash
#define FIRMWARE_HASH_LEN 32u
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
        return false; // Invalid argument
    }

    // Check if ATECC is available before attempting to read
    if (!atecc608a_is_available()) {
#if !FIRMWARE_PRODUCTION
        // printf("Secure Boot: ATECC not available for reading version.\n");
#endif
        return false;
    }

    if (atecc608a_read_slot(ATECC608A_SLOT_VERSION_COUNTER, version_data, VERSION_COUNTER_LEN)) {
        memcpy(version, version_data, VERSION_COUNTER_LEN);
        success = true;
    } else {
#if !FIRMWARE_PRODUCTION
        // printf("Secure Boot: Failed to read version from ATECC slot %d.\n", ATECC608A_SLOT_VERSION_COUNTER);
#endif
    }
    security_secure_zero(version_data, sizeof(version_data)); // Zeroize sensitive version data
    return success;
}

// Function to write the firmware version to the ATECC608A slot
static bool write_version_to_atecc(uint32_t version) {
    uint8_t version_data[VERSION_COUNTER_LEN] = {0}; // Initialize for security
    bool success = false;

    // ATECC availability checked by atecc608a_write_slot.
    // Policy enforcement is handled by the caller.
    
    // Check if ATECC is available before attempting to write
    if (!atecc608a_is_available()) {
#if !FIRMWARE_PRODUCTION
        // printf("Secure Boot: ATECC not available for writing version.\n");
#endif
        return false;
    }

    memcpy(version_data, &version, VERSION_COUNTER_LEN);
    if (atecc608a_write_slot(ATECC608A_SLOT_VERSION_COUNTER, version_data, VERSION_COUNTER_LEN)) {
        success = true;
    } else {
#if !FIRMWARE_PRODUCTION
        // printf("Secure Boot: Failed to write version %u to ATECC slot %d.\n", version, ATECC608A_SLOT_VERSION_COUNTER);
#endif
    }
    security_secure_zero(version_data, sizeof(version_data)); // Zeroize sensitive version data
    return success;
}


void secure_boot_init(void) {
  memset(&g_secure_boot, 0, sizeof(g_secure_boot));
  g_secure_boot.initialized = true;
  // Default policy: enforce signature and anti-rollback
  g_secure_boot.policy.enforce_signature = true;
  g_secure_boot.policy.enforce_antirollback = true;
  g_secure_boot.policy.min_allowed_version = 0; // No minimum by default

  // Check ATECC availability for anti-rollback. If not available in production, it's critical.
  if (!atecc608a_is_available()) {
#if FIRMWARE_PRODUCTION
      // In production, if anti-rollback is enforced and ATECC is unavailable, it's a critical failure.
      Error_Handler();
#else
      // In development, we might disable anti-rollback if ATECC is absent, or log a warning.
      // For now, we'll allow it to proceed but note that anti-rollback checks might fail.
      // printf("Secure Boot Warning: ATECC not available. Anti-rollback checks may fail.\n");
      g_secure_boot.policy.enforce_antirollback = false; // Disable if ATECC is not available
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
      // In development, if reading fails, we might assume version 0 or log a warning.
      // printf("Secure Boot Warning: Failed to read initial anti-rollback version from ATECC. Assuming version 0.\n");
      stored_version_on_init = 0; // Assume 0 if read fails in dev
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

  // Re-evaluate ATECC availability if policy changes anti-rollback enforcement
  if (!g_secure_boot.policy.enforce_antirollback && !atecc608a_is_available()) {
      // If anti-rollback is now disabled and ATECC is unavailable, no issue.
  } else if (g_secure_boot.policy.enforce_antirollback && !atecc608a_is_available()) {
#if FIRMWARE_PRODUCTION
      // If anti-rollback is enforced and ATECC becomes unavailable, it's a critical error.
      Error_Handler();
#endif
  }
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
    return false; // Invalid argument
  }
  memset(out_result, 0, sizeof(*out_result)); // Zeroize result structure
  
  // Basic parameter validation
  if (!g_secure_boot.initialized || manifest_hash == NULL || manifest_signature == NULL || trusted_public_key == NULL) {
#if !FIRMWARE_PRODUCTION
    // printf("Secure Boot Error: Invalid parameters for verification.\n");
#endif
    return false;
  }
  // FIRMWARE_HASH_LEN and ECDSA_P256_SIGNATURE_LEN are defined in secure_boot.h.
  // The trusted_public_key_len for P256 is 64 bytes.
  if (manifest_hash_len != FIRMWARE_HASH_LEN || manifest_signature_len != ECDSA_P256_SIGNATURE_LEN || trusted_public_key_len != 64) {
#if !FIRMWARE_PRODUCTION
    // printf("Secure Boot Error: Input length mismatch. Hash: %zu, Sig: %zu, PubKey: %zu\n", manifest_hash_len, manifest_signature_len, trusted_public_key_len);
#endif
    return false;
  }

  // 1. Verify Firmware Signature using crypto_engine_ecdsa_verify
  if (g_secure_boot.policy.enforce_signature) {
    // Check if ATECC is available and ready for verification first
    if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_ECDSA_VERIFY)) {
#if FIRMWARE_PRODUCTION
        // In production, if signature enforcement is on and crypto hardware is not ready, it's a critical failure.
        Error_Handler();
#endif
        // printf("Secure Boot Error: Crypto hardware not ready for signature verification.\n");
        out_result->signature_valid = false;
        signature_ok = false; // Cannot proceed without secure element capability
    } else {
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
        out_result->signature_valid = signature_ok;
    }
  } else {
    signature_ok = true; // Signature enforcement is disabled
    out_result->signature_valid = true;
  }

  // 2. Verify Anti-Rollback Counter
  if (g_secure_boot.policy.enforce_antirollback) {
    if (read_version_from_atecc(&stored_min_version)) {
        if (new_firmware_version < stored_min_version) {
            rollback_ok = false; // Downgrade detected, immediately reject
#if !FIRMWARE_PRODUCTION
            // printf("Secure Boot: Anti-rollback failure. New version %u < Stored version %u\n", new_firmware_version, stored_min_version);
#endif
        } else { // new_firmware_version >= stored_min_version
            rollback_ok = true; // Upgrade or same version allowed
#if !FIRMWARE_PRODUCTION
            // printf("Secure Boot: Anti-rollback check passed. New version %u >= Stored version %u\n", new_firmware_version, stored_min_version);
#endif
        }
    } else {
        // If version cannot be read from ATECC in production, it's a critical error.
#if FIRMWARE_PRODUCTION
        Error_Handler(); // Halt as anti-rollback cannot be checked securely.
#endif
        // printf("Secure Boot Error: Failed to read anti-rollback version from ATECC.\n");
        rollback_ok = false; // Cannot proceed without a reliable anti-rollback counter.
    }
    out_result->antirollback_ok = rollback_ok;
  } else {
    rollback_ok = true; // Anti-rollback enforcement is disabled
    out_result->antirollback_ok = true;
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
          } else {
#if !FIRMWARE_PRODUCTION
              // printf("Secure Boot: Successfully updated anti-rollback version to %u in ATECC.\n", new_firmware_version);
#endif
              // Update the internal state to reflect the new version
              g_secure_boot.current_running_version = new_firmware_version;
          }
      } else {
          // New firmware version is not greater than the stored version.
          // This could happen if the same firmware is being re-flashed.
          // No update to ATECC is needed, and it's still considered accepted.
#if !FIRMWARE_PRODUCTION
          // printf("Secure Boot: New firmware version %u is not greater than stored version %u. No ATECC update needed.\n", new_firmware_version, stored_min_version);
#endif
      }
  }
  overall_success = out_result->accepted; // Overall success reflects final acceptance.

  return overall_success;
}
