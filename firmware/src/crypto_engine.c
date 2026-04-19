#include "crypto_engine.h"

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "build_config.h"
#include "crypto_stub.h" // For non-production fallbacks, if direct engine used.
#include "security_policy.h" // For PASSWORD_MAX_LENGTH, etc.
#include "security_utils.h" // For sec_consttime_memeq, security_secure_zero
#include "spi_hal.h"        // For potential flash access needed by ATECC communication
#include "atecc608a_driver.h" // Actual ATECC608A driver functions

// Define ATECC608A slots based on security model. These are examples/placeholders.
#define ATECC608A_SLOT_MASTER_KEY       0u // Primary AEAD key slot
#define ATECC608A_SLOT_DEVICE_SECRET    1u // Device-unique secret for KDFs
#define ATECC608A_SLOT_SIGNING_PRIVKEY  2u // Private key for device attestation/signing
#define ATECC608A_SLOT_FIDO_PRIVKEY_BASE 3u // Base slot for FIDO2 credential private keys

// The global Error_Handler() is defined in main.c to handle fatal, unrecoverable errors.
// All critical errors in production under FIRMWARE_PRODUCTION should call this global function.
// Helper for string length with bounds check
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

// Helper for hex encoding
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
  if ((in_len * 2u) + 1u > out_cap) { // Need 2 chars per byte + null terminator
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

// Helper for hex decoding (single character)
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

// Helper for hex decoding (string to bytes)
static bool hex_decode(const char *in,
                       size_t in_len,
                       uint8_t *out,
                       size_t out_cap,
                       size_t *out_len) {
  size_t i;
  if (in == NULL || out == NULL) {
    return false;
  }
  if ((in_len % 2u) != 0u) { // Must be even number of hex characters
    return false;
  }
  if ((in_len / 2u) > out_cap) { // Decoded bytes must fit in output buffer
    return false;
  }
  for (i = 0u; i < in_len; i += 2u) {
    int hi = hex_value(in[i]);
    int lo = hex_value(in[i + 1u]);
    if (hi < 0 || lo < 0) { // Invalid hex character
      return false;
    }
    out[i / 2u] = (uint8_t)(((uint8_t)hi << 4u) | (uint8_t)lo);
  }
  if (out_len != NULL) {
    *out_len = in_len / 2u;
  }
  return true;
}

typedef struct {
  bool initialized;
  // Indicates if the secure element is present and functional
  bool secure_element_available;
  // Indicates if the master encryption key (for AEAD) is securely provisioned in ATECC
  bool master_key_provisioned;
  // Indicates if the device secret (for KDF) is securely provisioned in ATECC
  bool device_secret_provisioned;

  // The following state is more for demonstrating binding, might not be needed in final
  // implementation if binding is transparently managed by the driver.
  uint8_t bound_secure_element_slot;
  uint8_t bound_secure_element_pubkey[64];
  size_t bound_secure_element_pubkey_len;

} crypto_engine_state_t;

static crypto_engine_state_t g_crypto_state;

// Simple counter for Additional Authenticated Data (AAD) for password encryption.
// In a true AEAD with ATECC, the nonce part might be generated internally by ATECC.
// Here, we use a counter for part of the AAD.
static uint32_t g_password_encryption_aad_counter = 1u;

static bool crypto_engine_ready_for_sensitive_ops(void) {
  // In production, operations MUST be secure.
  // This means crypto engine must be initialized, secure element available,
  // master encryption key and device secret securely provisioned.
#if FIRMWARE_PRODUCTION
  return g_crypto_state.initialized &&
         g_crypto_state.secure_element_available &&
         g_crypto_state.master_key_provisioned &&
         g_crypto_state.device_secret_provisioned;
#else
  // In dev, allow more flexibility for testing purposes.
  // The 'initialized' flag here indicates base readiness, further checks are done per operation
  // for actual ATECC availability if that path is taken.
  return g_crypto_state.initialized;
#endif
}


static void next_password_aad(uint8_t aad_out[12]) {
  // This function is for constructing an AAD for password encryption.
  // We combine a simple monotonic counter (host-side) with a portion of the device secret.
  // This provides some entropy and ensures different passwords (or same password encrypted at different times)
  // will have different AADs.

  uint8_t combined_seed[32]; // Use a larger seed for better mixing, e.g., for SHA256 input
  uint8_t hash_output[32]; // Use SHA256 for stronger mixing

  memset(combined_seed, 0, sizeof(combined_seed));

  // Mix monotonic counter (4 bytes)
  memcpy(combined_seed, &g_password_encryption_aad_counter, sizeof(g_password_encryption_aad_counter));
  g_password_encryption_aad_counter++; // Increment for the next use

  // Mix in a component from the device secret (8 bytes), read securely from ATECC
  if (g_crypto_state.device_secret_provisioned) {
    uint8_t device_secret_component[8]; // Part of the device secret
    // Check for ATECC availability and read the component
    if (atecc608a_is_available() && atecc608a_read_slot(ATECC608A_SLOT_DEVICE_SECRET, device_secret_component, sizeof(device_secret_component))) {
        // Overlay the secret component into the combined_seed after the counter.
        size_t current_seed_len = sizeof(g_password_encryption_aad_counter);
        memcpy(combined_seed + current_seed_len, device_secret_component, sizeof(device_secret_component));
        security_secure_zero(device_secret_component, sizeof(device_secret_component)); // Zeroize sensitive data
    } else {
        // If secure element isn't available, provisioned, or read fails in production, this is a critical error.
#if FIRMWARE_PRODUCTION
        Error_Handler(); // Fatal: cannot generate secure AAD without device secret
        security_secure_zero(aad_out, 12);
        security_secure_zero(combined_seed, sizeof(combined_seed));
        return;
#else
        // In dev, if device secret not read, proceed with just counter (less secure AAD).
#endif
    }
  } else {
    // g_crypto_state.device_secret_provisioned is false and we are in production. This is a fatal error.
#if FIRMWARE_PRODUCTION
    Error_Handler(); // Fatal: device secret must be provisioned.
    security_secure_zero(aad_out, 12);
    security_secure_zero(combined_seed, sizeof(combined_seed));
    return;
#else
    // In dev mode, proceed with just counter (less secure AAD).
#endif
  }

  // Hash the combined seed using the crypto engine's SHA256 (ATECC or software fallback)
  crypto_engine_hash256(combined_seed, sizeof(combined_seed), hash_output);

  // Use the first 12 bytes of the hash as the AAD
  memcpy(aad_out, hash_output, 12);

  security_secure_zero(combined_seed, sizeof(combined_seed));
  security_secure_zero(hash_output, sizeof(hash_output));
}


void crypto_engine_init(void) {
    memset(&g_crypto_state, 0, sizeof(g_crypto_state));
    g_crypto_state.initialized = true;

    // Initialize `spi_hal` once (assuming it's for ATECC comms or general platform SPI)
    spi_hal_init();
    atecc608a_init(); // Initialize the ATECC608A driver routines

    // Check if the secure element is present and functional by running self-test.
    if (atecc608a_self_test()) {
        g_crypto_state.secure_element_available = true;
    } else {
        g_crypto_state.secure_element_available = false;
#if FIRMWARE_PRODUCTION
        Error_Handler(); // Critical failure for production.
#else
        // In development, allow proceeding without secure element, possibly with software fallbacks.
#endif
    }

    // Update provisioning status based on actual ATECC state.
    // If ATECC is not available, these will return false from `atecc608a_is_slot_provisioned`.
    g_crypto_state.master_key_provisioned = atecc608a_is_slot_provisioned(ATECC608A_SLOT_MASTER_KEY);
    g_crypto_state.device_secret_provisioned = atecc608a_is_slot_provisioned(ATECC608A_SLOT_DEVICE_SECRET);
}

// Function to indicate that the master key should be resident in ATECC608A_SLOT_MASTER_KEY.
// This function doesn't actually 'set' a key in RAM, but rather checks and updates its provisioned status.
// In production firmware, this function would likely be called after provisioning or during initialization.
void crypto_engine_set_master_key_slot_ready(void) {
    // Re-check the slot provisioning status using the ATECC driver.
    if (atecc608a_is_available() && atecc608a_is_slot_provisioned(ATECC608A_SLOT_MASTER_KEY)) {
        g_crypto_state.master_key_provisioned = true;
    } else {
        // Log an error or handle the case where the master key is not provisioned but expected.
        g_crypto_state.master_key_provisioned = false;
#if FIRMWARE_PRODUCTION
        Error_Handler(); // Fatal: Master key must be provisioned in production for secure operation.
#endif
    }
}

bool crypto_engine_set_device_secret(const uint8_t *secret, size_t secret_len) {
    if (!g_crypto_state.initialized) {
        crypto_engine_init();
    }
    if (!atecc608a_is_available()) {
        return false; // Cannot set device secret without secure element availability.
    }

    // The device secret itself will now be written to an ATECC slot.
    // It should not be stored in plaintext RAM.
    if (secret == NULL || secret_len == 0u || secret_len > 32u) { // ATECC slots generally handle up to 32 bytes (GCM key size)
        return false;
    }

    // Attempt to write the secret to the designated ATECC slot.
    // The ATECC driver must ensure secure storage and prevent plaintext extraction.
    // The `atecc608a_write_slot` function now returns bool.
    if (atecc608a_write_slot(ATECC608A_SLOT_DEVICE_SECRET, secret, secret_len)) {
        g_crypto_state.device_secret_provisioned = true;
        return true;
    } else {
        g_crypto_state.device_secret_provisioned = false;
        return false;
    }
}

// The concept of "binding an ATECC slot" needs to be clarified by the specific ATECC use case.
// Assuming it means registering a public key associated with a slot or a configuration.
// This function is kept for API compatibility but its exact implementation meaning for ATECC binding needs to be defined.
bool crypto_engine_bind_atecc_slot(uint8_t slot_id,
                                   const uint8_t *public_key,
                                   size_t public_key_len) {
  if (!g_crypto_state.initialized) {
    crypto_engine_init();
  }
  if (!atecc608a_is_available()) { // Check if ATECC is generally available
    return false;
  }
  if (public_key == NULL || public_key_len == 0u || public_key_len > sizeof(g_crypto_state.bound_secure_element_pubkey)) {
    return false;
  }

  // This operation may involve configuring an ATECC slot, validating a key, or storing public key details.
  // The `atecc608a_bind_slot` function in the driver layer now takes only slot_id.
  // If `public_key` is part of the secure element binding, the ATECC driver would ideally manage it internally.
  // For this mock implementation, we'll assume the driver's default `atecc608a_bind_slot` is sufficient for marking.
  // If required, `public_key` could be written to a configuration zone or another specific slot.
  if (atecc608a_bind_slot(slot_id)) { // The driver's `atecc608a_bind_slot` returns bool.
      g_crypto_state.bound_secure_element_slot = slot_id;
      // Mirroring the public key in crypto_engine_state_t for compatibility, although ATECC might store it securely.
      memcpy(g_crypto_state.bound_secure_element_pubkey, public_key, public_key_len);
      g_crypto_state.bound_secure_element_pubkey_len = public_key_len;
      return true;
  }
  return false;
}

crypto_engine_status_t crypto_engine_get_status(void) {
  crypto_engine_status_t status;
  memset(&status, 0, sizeof(status));
  status.backend = g_crypto_state.secure_element_available
                       ? CRYPTO_BACKEND_ATECC608A
                       : CRYPTO_BACKEND_SOFTWARE_FALLBACK;
  // These indicate if the respective functionalities are ready on the ATECC.
  // We use `atecc608a_is_ready()` defined in the ATECC driver to query specific function readiness.
  if (atecc608a_is_available()) {
    status.aead_interface_ready = atecc608a_is_ready(CRYPTO_FUNCTION_AEAD);
    status.kdf_interface_ready = atecc608a_is_ready(CRYPTO_FUNCTION_KDF);
  } else {
    status.aead_interface_ready = false;
    status.kdf_interface_ready = false;
  }
  // The 'secure_element_bound' flag reflects the general availability of the secure element.
  status.secure_element_bound = g_crypto_state.secure_element_available;
  status.production_mode = (FIRMWARE_PRODUCTION != 0);
  return status;
}

// Internal helper function for password encryption with string formatting
static bool crypto_engine_encrypt_aead_with_password_formatting(const char *plaintext,
                                                                 char *ciphertext_out,
                                                                 size_t out_len) {
  uint8_t aad[12]; // Additional Authenticated Data (AAD)
  uint8_t tag[16];
  uint8_t raw_ciphertext[PASSWORD_MAX_LENGTH]; // Raw encrypted bytes
  size_t plaintext_len;
  size_t raw_ciphertext_len = sizeof(raw_ciphertext);
  char aad_hex[25]; // Hex-encoded AAD (12 bytes * 2 chars/byte + 1 null)
  char tag_hex[33]; // Hex-encoded Tag (16 bytes * 2 chars/byte + 1 null)
  char raw_ciphertext_hex[(PASSWORD_MAX_LENGTH * 2u) + 1u]; // Hex-encoded ciphertext
  int n_chars_written; // For snprintf return value

  if (plaintext == NULL || ciphertext_out == NULL || out_len == 0u) {
    return false;
  }
  if (!crypto_engine_ready_for_sensitive_ops()) {
    return false;
  }
  plaintext_len = bounded_strlen(plaintext, PASSWORD_MAX_LENGTH);
  if (plaintext_len == 0u || plaintext[plaintext_len] != '\0') {
    return false;
  }

  next_password_aad(aad); // Generate AAD; mix of counter + device secret.

  bool success = false;

#if FIRMWARE_PRODUCTION
  // In production, ensure ATECC is available, AEAD function is ready, and master key is provisioned.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_AEAD) || !g_crypto_state.master_key_provisioned) {
      Error_Handler(); // Critical error in production: ATECC not ready for AEAD encryption.
      return false;
  }
  // Use ATECC608A for AEAD encryption.
  // The ATECC (or its driver) is assumed to manage the actual nonce internally or accept a fixed/deterministic nonce if needed.
  // `atecc608a_encrypt_aead` signature is updated to take `ciphertext_capacity` and `*ciphertext_len`.
  success = atecc608a_encrypt_aead(ATECC608A_SLOT_MASTER_KEY, // Master key handle/slot
                                 (const uint8_t *)plaintext, plaintext_len,
                                 aad, sizeof(aad),
                                 NULL, 0, // Nonce and nonce_len are handled by ATECC driver internally or are static for this operation.
                                 raw_ciphertext, sizeof(raw_ciphertext), &raw_ciphertext_len, tag);
#else
  // Fallback for development builds (not secure for production)
  // This section is removed as per the request.
  // If FIRMWARE_PRODUCTION is 0, the code will proceed to the ATECC call.
  // If ATECC is not available, `atecc608a_is_available()` will be false, leading to Error_Handler().
  // This means in dev mode, if ATECC is not available, this function will error out.
  // If ATECC is available, it will attempt to use it.
  // The original dev fallback was removed.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_AEAD) || !g_crypto_state.master_key_provisioned) {
      Error_Handler(); // Critical error in production: Secure element or master key not ready for AEAD.
      return false;
  }
  // If ATECC is available, use it.
  success = atecc608a_encrypt_aead(ATECC608A_SLOT_MASTER_KEY, // Master key handle/slot
                                   plaintext, plaintext_len,
                                   aad, sizeof(aad),
                                   NULL, 0, // Nonce and nonce_len are handled by ATECC driver internally or are static for this operation.
                                   raw_ciphertext, sizeof(raw_ciphertext), &raw_ciphertext_len, tag);
#endif

  if (!success) {
    security_secure_zero(raw_ciphertext, sizeof(raw_ciphertext));
    security_secure_zero(tag, sizeof(tag));
    security_secure_zero(aad, sizeof(aad));
    return false;
  }

  // Handle post-encryption encoding: "v1:aad_hex:tag_hex:ciphertext_hex"
  // Ensure enough buffer space for hex encoded data plus separators and null terminator.
  // Total length: "v1:" (3) + aad_hex (24) + ":" (1) + tag_hex (32) + ":" (1) + ciphertext_hex (up to PASSWORD_MAX_LENGTH*2) + "\0" (1)
  // Max out_len required: 3 + 24 + 1 + 32 + 1 + (PASSWORD_MAX_LENGTH * 2) + 1 = 62 + (64*2) + 1 = 191
  // We need to check if out_len is sufficient to prevent buffer overflow with snprintf.
  if (out_len < (3u + sizeof(aad_hex) + 1u + sizeof(tag_hex) + 1u + (raw_ciphertext_len * 2u) + 1u)) {
      security_secure_zero(raw_ciphertext, sizeof(raw_ciphertext));
      security_secure_zero(tag, sizeof(tag));
      security_secure_zero(aad, sizeof(aad));
      return false; // Output buffer too small
  }


  if (!hex_encode(aad, sizeof(aad), aad_hex, sizeof(aad_hex), NULL) ||
      !hex_encode(tag, sizeof(tag), tag_hex, sizeof(tag_hex), NULL) ||
      !hex_encode(raw_ciphertext, raw_ciphertext_len, raw_ciphertext_hex, sizeof(raw_ciphertext_hex), NULL)) {
    security_secure_zero(raw_ciphertext, sizeof(raw_ciphertext));
    security_secure_zero(tag, sizeof(tag));
    security_secure_zero(aad, sizeof(aad));
    return false;
  }
  n_chars_written = snprintf(ciphertext_out, out_len, "v1:%s:%s:%s", aad_hex, tag_hex, raw_ciphertext_hex);
  
  // Zeroize sensitive intermediate data.
  security_secure_zero(raw_ciphertext, sizeof(raw_ciphertext));
  security_secure_zero(tag, sizeof(tag));
  security_secure_zero(aad, sizeof(aad));

  return n_chars_written > 0 && (size_t)n_chars_written < out_len;
}

// Public API for password encryption. This wraps the formatting helper.
bool crypto_engine_encrypt_password(const char *plaintext, char *ciphertext_out, size_t out_len) {
    return crypto_engine_encrypt_aead_with_password_formatting(plaintext, ciphertext_out, out_len);
}

void crypto_engine_password_fingerprint(const char *password,
                                        uint8_t out_fp[16],
                                        size_t out_len) {
  if (password == NULL || out_fp == NULL || out_len == 0u) {
    if (out_fp != NULL) {
      security_secure_zero(out_fp, out_len < 16 ? out_len : 16);
    }
    return;
  }

#if FIRMWARE_PRODUCTION
  // In production, ensure ATECC is available, KDF function is ready, and device secret is provisioned.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_KDF) || !g_crypto_state.device_secret_provisioned) {
    Error_Handler(); // Critical: Secure element not ready or not provisioned for production KDF operations.
    security_secure_zero(out_fp, out_len < 16 ? out_len : 16);
    return;
  }
  // In production, password fingerprinting should use a secure derivation from the ATECC.
  // This uses a KDF driven by the ATECC, mixing the password and device secret.
  // Hash the password as input to the ATECC KDF to avoid sending raw password.
  uint8_t password_hash_input[32];
  crypto_engine_hash256((const uint8_t*)password, strlen(password), password_hash_input);

  // Use the updated ATECC driver function `atecc608a_derive_key_slot_and_output`
  // which is designed to provide the derived key material directly.
  if (atecc608a_derive_key_slot_and_output(ATECC608A_SLOT_DEVICE_SECRET, // Base key for KDF from device secret
                                            password_hash_input, sizeof(password_hash_input), // Hashed password as KDF input
                                            out_fp, (out_len < 16) ? out_len : 16)) { // Output fingerprint
    // Success. Fingerprint is in out_fp.
  } else {
    Error_Handler(); // ATECC KDF failed.
    security_secure_zero(out_fp, (out_len < 16) ? out_len : 16);
  }
  security_secure_zero(password_hash_input, sizeof(password_hash_input));
#else
  // Fallback for development builds (not production secure)
  // This section is removed as per the request.
  // If FIRMWARE_PRODUCTION is 0, the code will proceed to the ATECC call.
  // If ATECC is not available, `atecc608a_is_available()` will be false, leading to Error_Handler().
  // This means in dev mode, if ATECC is not available, this function will error out.
  // If ATECC is available, it will attempt to use it.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_KDF) || !g_crypto_state.device_secret_provisioned) {
      Error_Handler(); // Critical: Secure element not ready or not provisioned for production KDF operations.
      security_secure_zero(out_fp, out_len < 16 ? out_len : 16);
      return;
  }
  // If ATECC is available, use it.
  uint8_t password_hash_input[32];
  crypto_engine_hash256((const uint8_t*)password, strlen(password), password_hash_input);
  if (atecc608a_derive_key_slot_and_output(ATECC608A_SLOT_DEVICE_SECRET, // Base key for KDF from device secret
                                            password_hash_input, sizeof(password_hash_input), // Hashed password as KDF input
                                            out_fp, (out_len < 16) ? out_len : 16)) { // Output fingerprint
    // Success. Fingerprint is in out_fp.
  } else {
    Error_Handler(); // ATECC KDF failed.
    security_secure_zero(out_fp, (out_len < 16) ? out_len : 16);
  }
  security_secure_zero(password_hash_input, sizeof(password_hash_input));
#endif
}

void crypto_engine_hash16(const uint8_t *data, size_t data_len, uint8_t out_fp[16]) {
  if (out_fp == NULL) {
    return;
  }
  memset(out_fp, 0, 16u); // Always zero out the output buffer first.

#if FIRMWARE_PRODUCTION
  // In production, ensure ATECC is available for general cryptographic operations.
  if (!atecc608a_is_available()) {
    Error_Handler(); // Critical error in production: Secure element not available.
    return;
  }
  // In production, use ATECC for SHA256 and truncate the result.
  uint8_t hash_full[32];
  atecc608a_sha256(data, data_len, hash_full); // Assuming this function is implemented in atecc driver
  memcpy(out_fp, hash_full, 16); // Truncate SHA256 to 16 bytes for hash16
  security_secure_zero(hash_full, sizeof(hash_full)); // Zeroize sensitive intermediate data
#else
  // Fallback for development builds (not production secure)
  // This section is removed as per the request.
  // If FIRMWARE_PRODUCTION is 0, the code will proceed to the ATECC call.
  // If ATECC is not available, `atecc608a_is_available()` will be false, leading to Error_Handler().
  // This means in dev mode, if ATECC is not available, this function will error out.
  // If ATECC is available, it will attempt to use it.
  if (!atecc608a_is_available()) {
    Error_Handler(); // Critical error in production: Secure element not available.
    return;
  }
  // If ATECC is available, use it.
  uint8_t hash_full[32];
  atecc608a_sha256(data, data_len, hash_full); // Assuming this function is implemented in atecc driver
  memcpy(out_fp, hash_full, 16); // Truncate SHA256 to 16 bytes for hash16
  security_secure_zero(hash_full, sizeof(hash_full)); // Zeroize sensitive intermediate data
#endif
}

// Public API for ECDSA verification
bool crypto_engine_ecdsa_verify(const uint8_t *public_key,    // Public key bytes or slot ID depending on ATECC API
                                size_t public_key_len,       // Length of public key bytes
                                const uint8_t *message_hash,  // Pre-hashed message (e.g., SHA256)
                                size_t message_hash_len,     // Length of message hash (e.g., 32 for SHA256)
                                const uint8_t *signature,    // ECDSA signature
                                size_t signature_len) {      // Length of signature (e.g., 64 for P-256 R+S)
#if FIRMWARE_PRODUCTION
  // In production, ensure ATECC is available and ready for ECDSA verification.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_ECDSA_VERIFY)) {
    Error_Handler(); // Critical error in production: Secure element not ready for ECDSA verification.
    return false;
  }
  // Use ATECC608A for ECDSA verification.
  // The `atecc608a_ecdsa_verify` function signature is simplified. We must match that.
  return atecc608a_ecdsa_verify(public_key, message_hash, signature);
#else
  // Fallback for testing/development
  // This section is removed as per the request.
  // If FIRMWARE_PRODUCTION is 0, the code will proceed to the ATECC call.
  // If ATECC is not available, `atecc608a_is_available()` will be false, leading to Error_Handler().
  // This means in dev mode, if ATECC is not available, this function will error out.
  // If ATECC is available, it will attempt to use it.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_ECDSA_VERIFY)) {
    Error_Handler(); // Critical error in production: Secure element not ready for ECDSA verification.
    return false;
  }
  // If ATECC is available, use it.
  return atecc608a_ecdsa_verify(public_key, message_hash, signature);
#endif
}

bool crypto_engine_generate_ec_keypair(uint8_t *public_key, size_t public_key_len) {
#if FIRMWARE_PRODUCTION
  // In production, ensure ATECC is available and ready for ECC key generation.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_ECC_GENERATE)) {
    Error_Handler(); // Critical error in production: Secure element not ready for ECC key generation.
    return false;
  }
  // Delegate to ATECC608A to generate a key pair. The private key remains internal to ATECC.
  // We specify the slot where the private key will be stored/generated, e.g., ATECC608A_SLOT_FIDO_PRIVKEY_BASE.
  // The `atecc608a_generate_ec_keypair` function signature is simplified.
  return atecc608a_generate_ec_keypair(ATECC608A_SLOT_FIDO_PRIVKEY_BASE, public_key);
#else
  // Fallback for testing/development
  // This section is removed as per the request.
  // If FIRMWARE_PRODUCTION is 0, the code will proceed to the ATECC call.
  // If ATECC is not available, `atecc608a_is_available()` will be false, leading to Error_Handler().
  // This means in dev mode, if ATECC is not available, this function will error out.
  // If ATECC is available, it will attempt to use it.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_ECC_GENERATE)) {
    Error_Handler(); // Critical error in production: Secure element not ready for ECC key generation.
    return false;
  }
  // If ATECC is available, use it.
  return atecc608a_generate_ec_keypair(ATECC608A_SLOT_FIDO_PRIVKEY_BASE, public_key);
#endif
}

bool crypto_engine_ecdsa_sign(uint8_t key_slot_id,
                              const uint8_t *message, size_t message_len,
                              uint8_t *signature, size_t signature_len) {
#if FIRMWARE_PRODUCTION
  // In production, ensure ATECC is available and ready for ECDSA signing.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_ECDSA_SIGN)) {
    Error_Handler(); // Critical error in production: Secure element not ready for ECDSA signing.
    return false;
  }
  // Delegate to ATECC608A for actual signing.
  // The 'key_slot_id' specifies which private key in the ATECC to use.
  // The message hash should be computed before calling this function.
  uint8_t message_hash[32];
  crypto_engine_hash256(message, message_len, message_hash); // Hash message before signing

  // The `atecc608a_ecdsa_sign` function signature is simplified to match common ATECC library calls.
  bool success = atecc608a_ecdsa_sign(key_slot_id, message_hash, signature);
  security_secure_zero(message_hash, sizeof(message_hash));
  return success;
#else
  // Fallback for testing/development
  // This section is removed as per the request.
  // If FIRMWARE_PRODUCTION is 0, the code will proceed to the ATECC call.
  // If ATECC is not available, `atecc608a_is_available()` will be false, leading to Error_Handler().
  // This means in dev mode, if ATECC is not available, this function will error out.
  // If ATECC is available, it will attempt to use it.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_ECDSA_SIGN)) {
    Error_Handler(); // Critical error in production: Secure element not ready for ECDSA signing.
    return false;
  }
  // If ATECC is available, use it.
  uint8_t message_hash[32];
  crypto_engine_hash256(message, message_len, message_hash); // Hash message before signing
  bool success = atecc608a_ecdsa_sign(key_slot_id, message_hash, signature);
  security_secure_zero(message_hash, sizeof(message_hash));
  return success;
#endif
}

void crypto_engine_hash256(const uint8_t *data, size_t data_len, uint8_t out_hash[32]) {
  if (out_hash == NULL) {
    return;
  }
  memset(out_hash, 0, 32);

#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_available) {
    // In production, if ATECC is not available, hashing cannot be performed securely.
    Error_Handler();
    return;
  }
  // In production, use ATECC608A for SHA-256 hashing if available via the driver.
  // The `atecc608a_sha256` function is assumed from the `atecc608a_driver.h`.
  atecc608a_sha256(data, data_len, out_hash);
#else
  // Fallback to software SHA256 for development builds.
  // This uses the internal static placeholder function if atecc608a_sha256 is not defined.
  // This section is removed as per the request.
  // If FIRMWARE_PRODUCTION is 0, the code will proceed to the ATECC call.
  // If ATECC is not available, `atecc608a_is_available()` will be false, leading to Error_Handler().
  // This means in dev mode, if ATECC is not available, this function will error out.
  // If ATECC is available, it will attempt to use it.
  if (!g_crypto_state.secure_element_available) {
      Error_Handler(); // Critical error in production: Secure element not available.
      return;
  }
  // If ATECC is available, use it.
  atecc608a_sha256(data, data_len, out_hash);
#endif
}

bool crypto_engine_read_atecc_slot(uint8_t slot_id, uint8_t *data, size_t data_len) {
    if (!atecc608a_is_available()) {
        return false;
    }
    // Assuming atecc608a_read_slot securely reads the specified slot content.
    // The `atecc608a_read_slot` function now returns bool.
    return atecc608a_read_slot(slot_id, data, data_len);
}

bool crypto_engine_write_atecc_slot(uint8_t slot_id, const uint8_t *data, size_t data_len) {
    if (!atecc608a_is_available()) {
        return false;
    }
    // Assuming atecc608a_write_slot securely writes content to the specified slot.
    // The `atecc608a_write_slot` function now returns bool.
    return atecc608a_write_slot(slot_id, data, data_len);
}


bool crypto_engine_derive_pin_key(const char *pin,
                                  const uint8_t *salt,
                                  size_t salt_len,
                                  uint8_t out_key[32]) {
  uint8_t mix_input[64]; // Input buffer for KDF (PIN + SECRET + SALT)
  size_t pin_len = 0u;
  size_t mix_input_current_len = 0u;

  if (pin == NULL || out_key == NULL) {
    return false;
  }
  pin_len = strlen(pin);
  if (pin_len == 0u) {
    return false;
  }

  memset(mix_input, 0, sizeof(mix_input));

  // Copy PIN to mix_input
  if (pin_len > sizeof(mix_input)) {
    pin_len = sizeof(mix_input); // Truncate PIN if too long
  }
  memcpy(mix_input, pin, pin_len);
  mix_input_current_len += pin_len;

  // Mix in a component from the device secret, read securely from ATECC
  if (g_crypto_state.device_secret_provisioned) {
    uint8_t device_secret_component[16]; // Use a portion (e.g., first 16 bytes) for mixing with PIN
    // Check for ATECC availability and read the component
    if (atecc608a_is_available() && atecc608a_read_slot(ATECC608A_SLOT_DEVICE_SECRET, device_secret_component, sizeof(device_secret_component))) {
        size_t copy_len = sizeof(device_secret_component);
        if (mix_input_current_len + copy_len > sizeof(mix_input)) {
            copy_len = sizeof(mix_input) - mix_input_current_len; // Ensure no buffer overflow
        }
        memcpy(mix_input + mix_input_current_len, device_secret_component, copy_len);
        mix_input_current_len += copy_len;
        security_secure_zero(device_secret_component, sizeof(device_secret_component)); // Zeroize sensitive data
    } else {
        // If device secret cannot be read from ATECC in production, KDF should fail.
#if FIRMWARE_PRODUCTION
        Error_Handler(); // Log and/or halt for critical failure
#endif
        security_secure_zero(mix_input, sizeof(mix_input));
        return false;
    }
  } else {
    // In production, device secret is mandatory for KDF operations, and here it was not provisioned.
#if FIRMWARE_PRODUCTION
    Error_Handler(); // Log and/or halt for critical failure
#endif
    security_secure_zero(mix_input, sizeof(mix_input));
    return false;
  }

  // Mix in salt if provided
  if (salt != NULL && salt_len > 0u) {
    size_t copy_len = salt_len;
    if (mix_input_current_len + copy_len > sizeof(mix_input)) {
      copy_len = sizeof(mix_input) - mix_input_current_len;
    }
    if (copy_len > 0u) {
      memcpy(mix_input + mix_input_current_len, salt, copy_len);
      mix_input_current_len += copy_len;
    }
  }

  // Perform the key derivation
  bool success = false;
#if FIRMWARE_PRODUCTION
  // In production, ensure ATECC is available, KDF function is ready, and device secret is provisioned.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_KDF) || !g_crypto_state.device_secret_provisioned) {
      Error_Handler(); // Critical error: Secure element not ready or not provisioned, or KDF not ready.
      security_secure_zero(mix_input, sizeof(mix_input));
      return false;
  }
  // Use ATECC608A for key derivation (PBKDF2 equivalent or similar KDF).
  // ATECC608A_SLOT_DEVICE_SECRET is the base key controlling the derivation.
  // `mix_input` acts as the variable input (PIN + SECRET + SALT).
  // We're adapting `atecc608a_derive_key_slot_and_output` for this.
  success = atecc608a_derive_key_slot_and_output(ATECC608A_SLOT_DEVICE_SECRET, // Slot holding the base key for KDF
                                                mix_input, mix_input_current_len, // Input data (PIN + secret + salt)
                                                out_key, 32); // Output derived 32 bytes
#else
  // Fallback for development builds (not production secure)
  // This section is removed as per the request.
  // If FIRMWARE_PRODUCTION is 0, the code will proceed to the ATECC call.
  // If ATECC is not available, `atecc608a_is_available()` will be false, leading to Error_Handler().
  // This means in dev mode, if ATECC is not available, this function will error out.
  // If ATECC is available, it will attempt to use it.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_KDF) || !g_crypto_state.device_secret_provisioned) {
      Error_Handler(); // Critical error: Secure element not ready or not provisioned, or KDF not ready.
      security_secure_zero(mix_input, sizeof(mix_input));
      return false;
  }
  // If ATECC is available, use it.
  success = atecc608a_derive_key_slot_and_output(ATECC608A_SLOT_DEVICE_SECRET, // Slot holding the base key for KDF
                                                mix_input, mix_input_current_len, // Input data (PIN + secret + salt)
                                                out_key, 32); // Output derived 32 bytes
#endif

  security_secure_zero(mix_input, sizeof(mix_input)); // Zeroize input to KDF
  return success;
}

// Primitive for AEAD encryption using ATECC or software fallback
bool crypto_engine_encrypt_aead(const uint8_t *plaintext,
                                size_t plaintext_len,
                                const uint8_t *aad,
                                size_t aad_len,
                                uint8_t *ciphertext,
                                size_t ciphertext_capacity,
                                size_t *ciphertext_len,
                                uint8_t out_tag[16]) {
  if (plaintext == NULL || ciphertext == NULL || ciphertext_len == NULL || out_tag == NULL) {
    return false;
  }
  if (!crypto_engine_ready_for_sensitive_ops()) {
    // Operations cannot proceed if sensitive crypto requirements are not met.
    return false;
  }
  if (ciphertext_capacity < plaintext_len) {
    // Ciphertext must be able to hold at least plaintext_len of data + AEAD overhead (which is tag for GCM).
    // For now, assuming ciphertext_capacity is for the plain text, but real AEAD has overhead.
    return false;
  }
  
  // Ensure output pointers are not aliased with input pointers for safety.
  // For simplicity assuming no overlap for now, but in a robust system this check would be necessary.

  bool success = false;
#if FIRMWARE_PRODUCTION
  // In production, ensure ATECC is available, AEAD function is ready, and master key is provisioned.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_AEAD) || !g_crypto_state.master_key_provisioned) {
      Error_Handler(); // Critical error in production: Secure element or master key not ready for AEAD.
      return false;
  }
  // Use ATECC608A for AEAD encryption.
  // The ATECC API typically handles internal nonce generation or mixes AAD with its own data.
  success = atecc608a_encrypt_aead(ATECC608A_SLOT_MASTER_KEY, // Master key handle/slot
                                   plaintext, plaintext_len,
                                   aad, aad_len,
                                   NULL, 0, // Nonce and nonce_len are handled by ATECC driver internally or are static for this operation.
                                   ciphertext, ciphertext_capacity, ciphertext_len, out_tag);
#else
  // Fallback for development builds (not secure for production)
  // This section is removed as per the request.
  // If FIRMWARE_PRODUCTION is 0, the code will proceed to the ATECC call.
  // If ATECC is not available, `atecc608a_is_available()` will be false, leading to Error_Handler().
  // This means in dev mode, if ATECC is not available, this function will error out.
  // If ATECC is available, it will attempt to use it.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_AEAD) || !g_crypto_state.master_key_provisioned) {
      Error_Handler(); // Critical error in production: Secure element or master key not ready for AEAD.
      return false;
  }
  // If ATECC is available, use it.
  success = atecc608a_encrypt_aead(ATECC608A_SLOT_MASTER_KEY, // Master key handle/slot
                                   plaintext, plaintext_len,
                                   aad, aad_len,
                                   NULL, 0, // Nonce and nonce_len are handled by ATECC driver internally or are static for this operation.
                                   ciphertext, ciphertext_capacity, ciphertext_len, out_tag);
#endif

  return success;
}

// Primitive for AEAD decryption using ATECC or software fallback
bool crypto_engine_decrypt_aead(const uint8_t *ciphertext,
                                size_t ciphertext_len,
                                const uint8_t *aad,
                                size_t aad_len,
                                const uint8_t tag[16],
                                uint8_t *plaintext,
                                size_t plaintext_capacity,
                                size_t *plaintext_len) {
  if (ciphertext == NULL || plaintext == NULL || plaintext_len == NULL || tag == NULL) {
    return false;
  }
  if (!crypto_engine_ready_for_sensitive_ops()) {
    // Operations cannot proceed if sensitive crypto requirements are not met.
    return false;
  }
  if (plaintext_capacity < ciphertext_len) {
    // Plaintext buffer must be able to hold at least ciphertext_len (assuming no decryption expansion).
    return false;
  }
  
  // Ensure output pointers are not aliased with input pointers for safety.

  bool success = false;

#if FIRMWARE_PRODUCTION
  // In production, ensure ATECC is available, AEAD function is ready, and master key is provisioned.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_AEAD) || !g_crypto_state.master_key_provisioned) {
      Error_Handler(); // Critical error in production: Secure element or master key not ready for AEAD.
      return false;
  }
  // Use ATECC608A for AEAD decryption.
  // ATECC is expected to verify the tag internally and only then return plaintext.
  success = atecc608a_decrypt_aead(ATECC608A_SLOT_MASTER_KEY, // Master key handle/slot
                                   ciphertext, ciphertext_len,
                                   aad, aad_len,
                                   NULL, 0, // Nonce and nonce_len are handled by ATECC driver internally or are static for this operation.
                                   tag, // ATECC driver must verify this tag internally during decryption
                                   plaintext, plaintext_capacity, plaintext_len);
#else
  // Fallback for development builds (not secure for production)
  // This section is removed as per the request.
  // If FIRMWARE_PRODUCTION is 0, the code will proceed to the ATECC call.
  // If ATECC is not available, `atecc608a_is_available()` will be false, leading to Error_Handler().
  // This means in dev mode, if ATECC is not available, this function will error out.
  // If ATECC is available, it will attempt to use it.
  if (!atecc608a_is_available() || !atecc608a_is_ready(CRYPTO_FUNCTION_AEAD) || !g_crypto_state.master_key_provisioned) {
      Error_Handler(); // Critical error in production: Secure element or master key not ready for AEAD.
      return false;
  }
  // If ATECC is available, use it.
  success = atecc608a_decrypt_aead(ATECC608A_SLOT_MASTER_KEY, // Master key handle/slot
                                   ciphertext, ciphertext_len,
                                   aad, aad_len,
                                   NULL, 0, // Nonce and nonce_len are handled by ATECC driver internally or are static for this operation.
                                   tag, // ATECC driver must verify this tag internally during decryption
                                   plaintext, plaintext_capacity, plaintext_len);
#endif

  if (!success) {
      security_secure_zero(plaintext, plaintext_capacity); // Ensure plaintext is zeroized on any failure path
      *plaintext_len = 0;
  }
  // Ensure the decrypted plaintext is null-terminated if it was a string.
  // This is handled by the calling `crypto_engine_decrypt_password` on its buffer.
  return success;
}

// Public API for password decryption. This parses formatted ciphertext and calls the AEAD primitive.
bool crypto_engine_decrypt_password(const char *ciphertext_formatted,
                                    char *plaintext_out,
                                    size_t out_len) {
  const char *aad_hex_str;
  const char *tag_hex_str;
  const char *raw_ciphertext_hex_str;
  const char *sep1;
  const char *sep2;
  size_t aad_hex_len;
  size_t tag_hex_len;
  size_t raw_ciphertext_hex_len;
  uint8_t aad_bytes[12];
  uint8_t tag_bytes[16];
  uint8_t raw_ciphertext_bytes[PASSWORD_MAX_LENGTH]; // Max size for raw ciphertext
  size_t raw_ciphertext_bytes_len = 0u;
  size_t decrypted_plaintext_len;

  if (ciphertext_formatted == NULL || plaintext_out == NULL || out_len < 2u) { // Need space for at least 1 char + null
    return false;
  }
  if (!crypto_engine_ready_for_sensitive_ops()) {
    return false;
  }
  plaintext_out[0] = '\0'; // Ensure null termination from start

  // Expected format: "v1:aad_hex:tag_hex:ciphertext_hex"
  if (strncmp(ciphertext_formatted, "v1:", 3u) != 0) {
    return false; // Wrong version or format prefix
  }

  aad_hex_str = ciphertext_formatted + 3u; // Skip "v1:"
  sep1 = strchr(aad_hex_str, ':');
  if (sep1 == NULL) {
    return false; // Malformed: Missing first separator
  }
  tag_hex_str = sep1 + 1u;
  sep2 = strchr(tag_hex_str, ':');
  if (sep2 == NULL) {
    return false; // Malformed: Missing second separator
  }
  raw_ciphertext_hex_str = sep2 + 1u;

  aad_hex_len = (size_t)(sep1 - aad_hex_str);
  tag_hex_len = (size_t)(sep2 - tag_hex_str);
  raw_ciphertext_hex_len = strlen(raw_ciphertext_hex_str);

  // Validate hex string lengths for AAD (12 bytes -> 24 hex chars) and Tag (16 bytes -> 32 hex chars).
  // Ciphertext hex length can vary but must be even and non-zero if ciphertext_hex_str exists.
  if (aad_hex_len != (sizeof(aad_bytes) * 2u) ||
      tag_hex_len != (sizeof(tag_bytes) * 2u) ||
      (raw_ciphertext_hex_len % 2u) != 0u || raw_ciphertext_hex_len == 0u) {
    return false;
  }

  // Decode hex strings to bytes
  if (!hex_decode(aad_hex_str, aad_hex_len, aad_bytes, sizeof(aad_bytes), NULL) ||
      !hex_decode(tag_hex_str, tag_hex_len, tag_bytes, sizeof(tag_bytes), NULL) ||
      !hex_decode(raw_ciphertext_hex_str, raw_ciphertext_hex_len, raw_ciphertext_bytes, sizeof(raw_ciphertext_bytes), &raw_ciphertext_bytes_len)) {
    // If decoding fails, ensure output is zeroized.
    security_secure_zero(raw_ciphertext_bytes, sizeof(raw_ciphertext_bytes));
    security_secure_zero(tag_bytes, sizeof(tag_bytes));
    security_secure_zero(aad_bytes, sizeof(aad_bytes));
    return false;
  }

  // Decrypt to plaintext_out buffer. Max length for plaintext_out is out_len - 1 (for null terminator).
  decrypted_plaintext_len = out_len - 1u;

  bool success = crypto_engine_decrypt_aead(raw_ciphertext_bytes, raw_ciphertext_bytes_len,
                                            aad_bytes, sizeof(aad_bytes), // AAD provided from parsed string
                                            tag_bytes, // Tag provided from parsed string
                                            (uint8_t *)plaintext_out, decrypted_plaintext_len, &decrypted_plaintext_len);
  
  if (success) {
      // Ensure the decrypted plaintext is null-terminated.
      plaintext_out[decrypted_plaintext_len] = '\0';
  } else {
      // Zeroize output plaintext on decryption failure.
      security_secure_zero(plaintext_out, out_len);
      plaintext_out[0] = '\0'; // Ensure it's empty string
  }

  // Zeroize all intermediate sensitive data used for decryption.
  security_secure_zero(raw_ciphertext_bytes, sizeof(raw_ciphertext_bytes));
  security_secure_zero(tag_bytes, sizeof(tag_bytes));
  security_secure_zero(aad_bytes, sizeof(aad_bytes));
  
  return success;
}
