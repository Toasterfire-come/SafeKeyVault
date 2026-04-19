#include "crypto_engine.h"

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "build_config.h"
#include "crypto_stub.h"
#include "security_policy.h"
#include "security_utils.h"
#include "spi_hal.h" // For potential flash access if needed by crypto
#include "atecc608a_driver.h" // Actual ATECC608A driver

// Define ATECC608A slots
#define ATECC608A_SLOT_MASTER_KEY       0u // Example: Master encryption key
#define ATECC608A_SLOT_DEVICE_SECRET    1u // Example: Device-unique secret
#define ATECC608A_SLOT_PUBKEY           2u // Example: Public key for device attestation
#define ATECC608A_SLOT_FIDO_PRIVKEY     3u // Example: Private key for FIDO2 credentials
#define ATECC608A_SLOT_DATA_AES         4u // Example: AES key for general data encryption
// ATECC608A_SLOT_CRED_PRIVKEY for FIDO2 credential private keys (example, might not be distinct per cred)
#define ATECC608A_SLOT_FIDO_PRIVKEY     3u

typedef struct {
  bool initialized;
  bool secure_element_bound;
  bool master_key_set;
  bool device_secret_set_in_atecc; // Indicates if device secret is provisioned in ATECC slot
  uint8_t secure_element_slot;
  uint8_t secure_element_pubkey[64];
  size_t secure_element_pubkey_len;
} crypto_engine_state_t;

static crypto_engine_state_t g_crypto_state;
static uint32_t g_password_nonce_counter = 1u;

static bool crypto_engine_ready_for_sensitive_ops(void) {
  // In production, operations MUST be secure.
  // This means crypto engine must be initialized, master key provisioned (in ATECC),
  // device secret provisioned (in ATECC), and the secure element must be bound.
#if FIRMWARE_PRODUCTION
  return g_crypto_state.initialized &&
         g_crypto_state.master_key_set &&
         g_crypto_state.device_secret_set_in_atecc &&
         g_crypto_state.secure_element_bound;
#else
  if (!g_crypto_state.initialized) {
    crypto_engine_init(); // Initialize if not already done in dev builds
  }
  // In non-production, allow more flexibility for testing purposes.
  // The master_key_set and device_secret_set_in_atecc flags are still important.
  return g_crypto_state.initialized && g_crypto_state.master_key_set && g_crypto_state.device_secret_set_in_atecc;
#endif
}

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
  if ((in_len * 2u) + 1u > out_cap) {
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

static bool hex_decode(const char *in,
                       size_t in_len,
                       uint8_t *out,
                       size_t out_cap,
                       size_t *out_len) {
  size_t i;
  if (in == NULL || out == NULL) {
    return false;
  }
  if ((in_len % 2u) != 0u) {
    return false;
  }
  if ((in_len / 2u) > out_cap) {
    return false;
  }
  for (i = 0u; i < in_len; i += 2u) {
    int hi = hex_value(in[i]);
    int lo = hex_value(in[i + 1u]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out[i / 2u] = (uint8_t)(((uint8_t)hi << 4u) | (uint8_t)lo);
  }
  if (out_len != NULL) {
    *out_len = in_len / 2u;
  }
  return true;
}

static void next_password_nonce(uint8_t nonce[12]) {
  uint8_t seed[16];
  uint8_t hash[16];
  if (nonce == NULL) {
    return;
  }
  memset(seed, 0, sizeof(seed));
  memcpy(seed, &g_password_nonce_counter, sizeof(g_password_nonce_counter));
  // Nonce generation for passwords must be unique per encryption and ideally derived from a secure element's TRNG or a monotonic counter.
  // For now, we mix a global counter with a part of the device secret, read from ATECC.
  uint8_t temp_device_component[8];
  if (g_crypto_state.device_secret_set_in_atecc &&
      crypto_engine_read_atecc_slot(ATECC608A_SLOT_DEVICE_SECRET, temp_device_component, sizeof(temp_device_component))) {
    for (size_t i = 0u; i < sizeof(temp_device_component) && (4u + i) < sizeof(seed); ++i) {
      seed[4u + i] ^= temp_device_component[i];
    }
  }
  g_password_nonce_counter++; // Increment counter for next unique nonce
#if FIRMWARE_PRODUCTION
  // In production, use the secure crypto engine for hashing.
  crypto_engine_hash16(seed, sizeof(seed), hash);
#else
  // In development, use the stub for nonce generation.
  crypto_stub_hash16(seed, sizeof(seed), hash);
#endif
  memcpy(nonce, hash, 12u); // Use first 12 bytes of hash as nonce
  security_secure_zero(seed, sizeof(seed));
  security_secure_zero(hash, sizeof(hash));
  security_secure_zero(temp_device_component, sizeof(temp_device_component));
}

void crypto_engine_init(void) {
  memset(&g_crypto_state, 0, sizeof(g_crypto_state));
  g_crypto_state.initialized = true;

  // Initialize hardware drivers
  spi_hal_init();
  atecc608a_init();

#if FIRMWARE_PRODUCTION
  g_crypto_state.master_key_set = false; // Master key must be securely provisioned, not hardcoded
#else
  // In development, a placeholder master key is used for non-critical operations
  // if a secure element isn't bound. This is a stub for dev environments.
  uint8_t dev_master_key[32] = {
      0x31u, 0x52u, 0xA4u, 0x18u, 0x09u, 0x7Fu, 0xC3u, 0x44u,
      0x8Eu, 0x20u, 0xB7u, 0x5Du, 0x11u, 0xE2u, 0x66u, 0x90u,
      0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u,
      0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu, 0x10u,
  };
  crypto_stub_set_master_key(dev_master_key, sizeof(dev_master_key));
  g_crypto_state.master_key_set = true; // For the stub only
  g_crypto_state.device_secret_set_in_atecc = true; // Assume a dev secret is set for stub
  security_secure_zero(dev_master_key, sizeof(dev_master_key));
#endif
}

// Function to indicate that the master key should be resident in ATECC608A_SLOT_MASTER_KEY
void crypto_engine_set_master_key_slot_ready(void) {
    // This function now merely indicates that a master key is expected to be
    // securely provisioned in the ATECC608A_SLOT_MASTER_KEY.
    // It does not handle actual key material in plaintext.
    g_crypto_state.master_key_set = true;
}

bool crypto_engine_set_device_secret(const uint8_t *secret, size_t secret_len) {
  if (!g_crypto_state.initialized) {
    crypto_engine_init();
  }
  // The device secret itself will now be written to an ATECC slot.
  // It should not be stored in plaintext RAM.
  if (secret == NULL || secret_len == 0u || secret_len > 32u) { // Assuming a max secret length of 32 for the ATECC slot
    return false;
  }

  // Attempt to write the secret to the designated ATECC slot.
  // The ATECC driver must ensure secure storage and prevent plaintext extraction.
  if (atecc608a_write_slot(ATECC608A_SLOT_DEVICE_SECRET, secret, secret_len) == ATECC608A_SUCCESS) {
      g_crypto_state.device_secret_set_in_atecc = true;
      // Mark master key as set since it can now be derived securely using the device secret
      g_crypto_state.master_key_set = true; // Indicates it's ready for derivation, not that a key has been loaded into RAM
      return true;
  } else {
      g_crypto_state.device_secret_set_in_atecc = false;
      return false;
  }
}

bool crypto_engine_bind_atecc_slot(uint8_t slot_id,
                                   const uint8_t *public_key,
                                   size_t public_key_len) {
  if (!g_crypto_state.initialized) {
    crypto_engine_init();
  }
  if (public_key == NULL || public_key_len == 0u || public_key_len > sizeof(g_crypto_state.secure_element_pubkey)) {
    return false;
  }

  if (atecc608a_bind_slot(slot_id, public_key, public_key_len) == ATECC608A_SUCCESS) {
      g_crypto_state.secure_element_slot = slot_id;
      memcpy(g_crypto_state.secure_element_pubkey, public_key, public_key_len);
      g_crypto_state.secure_element_pubkey_len = public_key_len;
      g_crypto_state.secure_element_bound = true;
      return true;
  }
  return false;
}

crypto_engine_status_t crypto_engine_get_status(void) {
  crypto_engine_status_t status;
  memset(&status, 0, sizeof(status));
  status.backend = g_crypto_state.secure_element_bound
                       ? CRYPTO_BACKEND_ATECC608A
                       : CRYPTO_BACKEND_SOFTWARE_FALLBACK;
  // Check if ATECC interfaces are ready
  status.aead_interface_ready = atecc608a_is_ready(ATECC608A_AEAD_INTERFACE);
  status.kdf_interface_ready = atecc608a_is_ready(ATECC608A_KDF_INTERFACE);
  status.secure_element_bound = g_crypto_state.secure_element_bound;
  status.production_mode = (FIRMWARE_PRODUCTION != 0);
  return status;
}

bool crypto_engine_encrypt_password(const char *plaintext,
                                    char *ciphertext_out,
                                    size_t out_len) {
  uint8_t nonce[12];
  uint8_t tag[16];
  uint8_t ciphertext[PASSWORD_MAX_LENGTH];
  size_t plaintext_len;
  size_t ciphertext_len = sizeof(ciphertext);
  char nonce_hex[25];
  char tag_hex[33];
  char ciphertext_hex[(PASSWORD_MAX_LENGTH * 2u) + 1u];
  int n;

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

  next_password_nonce(nonce); // This nonce generation using state should be moved to AEAD call or ATECC itself.
                             // For now, it will be used as AAD.

  bool success;
#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_bound) {
      return false; // In production, ATECC must always be used
  }
  // Use ATECC608A for AEAD encryption
  success = atecc608a_encrypt_aead(ATECC608A_SLOT_MASTER_KEY, // Master key is in slot 0
                                 (const uint8_t *)plaintext, plaintext_len,
                                 nonce, sizeof(nonce), // Nonce for AEAD is critical; ATECC should generate internally
                                 ciphertext, sizeof(ciphertext), &ciphertext_len, tag);
#else
  if (!g_crypto_state.secure_element_bound) {
      // Fallback to stub for development builds if ATECC is not bound or fails.
      // THIS IS NOT A SECURE IMPLEMENTATION FOR PRODUCTION.
      success = crypto_stub_encrypt_password(plaintext, (char*)ciphertext, sizeof(ciphertext));
      if (success) {
          crypto_stub_hash16(ciphertext, strlen((char*)ciphertext), tag); // Simulate tag
          ciphertext_len = strlen((char*)ciphertext); // Stub returns null-terminated string
      } else {
            // In dev mode, if stub fails, ensure output is cleared
            security_secure_zero(ciphertext, sizeof(ciphertext));
            security_secure_zero(tag, sizeof(tag));
            security_secure_zero(nonce, sizeof(nonce));
      }
  } else {
      // If ATECC is available in development, use it.
      success = atecc608a_encrypt_aead(ATECC608A_SLOT_MASTER_KEY,
                                     (const uint8_t *)plaintext, plaintext_len,
                                     nonce, sizeof(nonce), // Nonce for AEAD is critical
                                     ciphertext, sizeof(ciphertext), &ciphertext_len, tag);
  }
#endif

  if (!success) {
    security_secure_zero(ciphertext, sizeof(ciphertext));
    security_secure_zero(tag, sizeof(tag));
    security_secure_zero(nonce, sizeof(nonce));
    return false;
  }

  // Handle post-encryption encoding

  if (!hex_encode(nonce, sizeof(nonce), nonce_hex, sizeof(nonce_hex), NULL) ||
      !hex_encode(tag, sizeof(tag), tag_hex, sizeof(tag_hex), NULL) ||
      !hex_encode(ciphertext, ciphertext_len, ciphertext_hex, sizeof(ciphertext_hex), NULL)) {
    security_secure_zero(ciphertext, sizeof(ciphertext));
    security_secure_zero(tag, sizeof(tag));
    security_secure_zero(nonce, sizeof(nonce));
    return false;
  }
  n = snprintf(ciphertext_out, out_len, "v1:%s:%s:%s", nonce_hex, tag_hex, ciphertext_hex);
  security_secure_zero(ciphertext, sizeof(ciphertext));
  security_secure_zero(tag, sizeof(tag));
  security_secure_zero(nonce, sizeof(nonce));
  return n > 0 && (size_t)n < out_len;
}

// Removed duplicate/malformed crypto_engine_decrypt_password section
// The corrected crypto_engine_decrypt_password and crypto_engine_decrypt_aead functions
// are present below.

// Ensure the plaintext is an actual null-terminated string for strlen to be safe.
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
  if (!g_crypto_state.secure_element_available || !g_crypto_state.device_secret_provisioned) {
    Error_Handler(); // Critical: Secure element not ready for production ops
    security_secure_zero(out_fp, out_len < 16 ? out_len : 16);
    return;
  }
  // In production, password fingerprinting should use a secure derivation from the ATECC.
  // This uses a KDF driven by the ATECC, mixing the password and device secret.
  uint8_t derived_fingerprint_material[32]; // Use a larger buffer for KDF output
  if (atecc608a_derive_key_slot(ATECC608A_SLOT_DEVICE_SECRET, // Base key for KDF
                                (const uint8_t*)password, strlen(password), // Password as input to KDF
                                derived_fingerprint_material, sizeof(derived_fingerprint_material)) == ATECC608A_SUCCESS) {
    memcpy(out_fp, derived_fingerprint_material, (out_len < 16) ? out_len : 16);
  } else {
    Error_Handler();
    security_secure_zero(out_fp, out_len < 16 ? out_len : 16);
  }
  security_secure_zero(derived_fingerprint_material, sizeof(derived_fingerprint_material));
#else
  // Software fallback for development builds (not production secure)
  uint8_t sha_hash[32];
  crypto_engine_hash256((const uint8_t*)password, strlen(password), sha_hash);
  memcpy(out_fp, sha_hash, (out_len < 16) ? out_len : 16); // Truncate or copy fully
  security_secure_zero(sha_hash, sizeof(sha_hash));
#endif
}

void crypto_engine_hash16(const uint8_t *data, size_t data_len, uint8_t out_fp[16]) {
  if (out_fp == NULL) {
    return;
  }
  memset(out_fp, 0, 16u);

#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_available) {
    Error_Handler(); // Critical error in production
    return;
  }
  // In production, use ATECC for SHA256 and truncate.
  uint8_t hash_full[32];
  atecc608a_sha256(data, data_len, hash_full); // Assuming this function is implemented in atecc driver
  memcpy(out_fp, hash_full, 16);
  security_secure_zero(hash_full, sizeof(hash_full));
#else
  // Fallback in development uses a simple FNV-1a like hash, as in the previous stub for hash16 logic.
  uint32_t h = 2166136261u; // FNV-1a initial hash value
  size_t i;
  if (data == NULL) {
    return;
  }
  for (i = 0u; i < data_len; ++i) {
    h ^= data[i];
    h *= 16777619u; // FNV-1a prime
    out_fp[i % 16u] ^= (uint8_t)(h & 0xFFu);
  }
#endif
}

bool crypto_engine_ecdsa_verify(const uint8_t *public_key_or_slot_id, // Can be public key bytes or slot ID for verification
                                size_t public_key_or_slot_id_len,
                                const uint8_t *message_hash,
                                size_t message_hash_len,
                                const uint8_t *signature,
                                size_t signature_len) {
#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_available) {
    Error_Handler(); // Critical error in production
    return false;
  }
  // Use ATECC608A for ECDSA verification.
  // The interpretation of `public_key_or_slot_id` depends on the `atecc608a_ecdsa_verify` function signature.
  // Assuming it can take a direct public key or a slot ID for a stored public key.
  // Let's assume for secure boot scenario, the public_key is provided directly.
  return atecc608a_ecdsa_verify(public_key_or_slot_id,    // Usually the public key bytes for verification
                                public_key_or_slot_id_len,
                                message_hash, message_hash_len,
                                signature, signature_len) == ATECC608A_SUCCESS;
#else
  // Fallback for testing/development. The stub takes public_key and private_key.
  // This will assume the first argument is a public key.
  uint8_t dummy_priv_key[32] = {0}; // Not actually used by crypto_stub_ecdsa_verify if it implies slot.
  return crypto_stub_ecdsa_verify(public_key_or_slot_id, public_key_or_slot_id_len, // Stub expects public_key
                                  dummy_priv_key, sizeof(dummy_priv_key), message_hash,
                                  message_hash_len, signature, signature_len);
#endif
}

bool crypto_engine_generate_ec_keypair(uint8_t *public_key, size_t public_key_len) { // Private key argument removed
#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_available) {
    Error_Handler(); // Critical error in production
    return false;
  }
  // Delegate to ATECC608A to generate a key pair. The private key remains internal to ATECC.
  // We specify the slot where the private key will be stored/generated, e.g., ATECC608A_SLOT_FIDO_PRIVKEY_BASE.
  return atecc608a_generate_ec_keypair(ATECC608A_SLOT_FIDO_PRIVKEY_BASE, // Slot for private key
                                       public_key, public_key_len) == ATECC608A_SUCCESS;
#else
  // Fallback for testing/development. Call stub with dummy private key args.
  uint8_t dummy_private_key[32];
  bool result = crypto_stub_generate_ec_keypair(public_key, public_key_len, dummy_private_key, sizeof(dummy_private_key));
  security_secure_zero(dummy_private_key, sizeof(dummy_private_key)); // Zeroize just in case.
  return result;
#endif
}

bool crypto_engine_ecdsa_sign(const uint8_t key_slot_id, // Changed to key_slot_id
                              const uint8_t *message, size_t message_len,
                              uint8_t *signature, size_t signature_len) {
#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_available) {
    Error_Handler(); // Critical error in production
    return false;
  }
  // Delegate to ATECC608A for actual signing.
  // The 'key_slot_id' specifies which private key in the ATECC to use.
  // The message hash should be computed before calling this function.
  uint8_t message_hash[32];
  crypto_engine_hash256(message, message_len, message_hash); // Hash message before signing

  bool success = atecc608a_ecdsa_sign(key_slot_id, message_hash, sizeof(message_hash), signature, signature_len) == ATECC608A_SUCCESS;
  security_secure_zero(message_hash, sizeof(message_hash));
  return success;
#else
  // Fallback for testing/development. Call stub with dummy private key based on slot_id.
  uint8_t dummy_private_key[32]; // Simulate a private key based on slot_id if needed by stub.
  for (size_t i = 0; i < sizeof(dummy_private_key); ++i) {
      dummy_private_key[i] = (uint8_t)(key_slot_id + i); // Simple unique dummy for stub
  }
  bool result = crypto_stub_ecdsa_sign(dummy_private_key, sizeof(dummy_private_key), message, message_len, signature, signature_len);
  security_secure_zero(dummy_private_key, sizeof(dummy_private_key));
  return result;
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
  atecc608a_sha256(data, data_len, out_hash); // Calls our static placeholder or actual ATECC driver.
#endif
}

bool crypto_engine_read_atecc_slot(uint8_t slot_id, uint8_t *data, size_t data_len) {
    if (!g_crypto_state.secure_element_available) {
        return false;
    }
    return atecc608a_read_slot(slot_id, data, data_len) == ATECC608A_SUCCESS;
}

bool crypto_engine_write_atecc_slot(uint8_t slot_id, const uint8_t *data, size_t data_len) {
    if (!g_crypto_state.secure_element_available) {
        return false;
    }
    return atecc608a_write_slot(slot_id, data, data_len) == ATECC608A_SUCCESS;
}


bool crypto_engine_derive_pin_key(const char *pin,
                                  const uint8_t *salt,
                                  size_t salt_len,
                                  uint8_t out_key[32]) {
  uint8_t mix_input[64]; // Input buffer for KDF
  size_t pin_len = 0u;
  size_t mix_input_len = 0u;

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
  mix_input_len += pin_len;

  // Mix in a component from the device secret, read securely from ATECC
  if (g_crypto_state.device_secret_provisioned) {
    uint8_t device_secret_component[16]; // Use a portion for mixing with PIN
    if (atecc608a_read_slot(ATECC608A_SLOT_DEVICE_SECRET, device_secret_component, sizeof(device_secret_component)) == ATECC608A_SUCCESS) {
        size_t copy_len = sizeof(device_secret_component);
        if (mix_input_len + copy_len > sizeof(mix_input)) {
            copy_len = sizeof(mix_input) - mix_input_len;
        }
        memcpy(mix_input + mix_input_len, device_secret_component, copy_len);
        mix_input_len += copy_len;
        security_secure_zero(device_secret_component, sizeof(device_secret_component));
    } else {
        // If device secret cannot be read in production, this is a critical error.
#if FIRMWARE_PRODUCTION
        Error_Handler();
#endif
        security_secure_zero(mix_input, sizeof(mix_input));
        return false;
    }
  } else {
    // In production, device secret is mandatory for KDF operations.
#if FIRMWARE_PRODUCTION
    Error_Handler(); // Critical error: device secret not provisioned.
#endif
    security_secure_zero(mix_input, sizeof(mix_input));
    return false;
  }

  // Mix in salt if provided
  if (salt != NULL && salt_len > 0u) {
    size_t copy_len = salt_len;
    if (mix_input_len + copy_len > sizeof(mix_input)) {
      copy_len = sizeof(mix_input) - mix_input_len;
    }
    if (copy_len > 0u) {
      memcpy(mix_input + mix_input_len, salt, copy_len);
      mix_input_len += copy_len;
    }
  }

  // Perform the key derivation
  bool success = false;
#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_available || !g_crypto_state.device_secret_provisioned) {
      Error_Handler(); // Critical error in production
      security_secure_zero(mix_input, sizeof(mix_input));
      return false;
  }
  // Use ATECC608A for key derivation (PBKDF2 equivalent).
  // ATECC608A_SLOT_DEVICE_SECRET is the key controlling the derivation.
  // The 'mix_input' data acts as the password/salt for the KDF.
  // The ATECC is expected to provide 32-byte output and handle iterations securely.
  success = atecc608a_derive_key_slot(ATECC608A_SLOT_DEVICE_SECRET, // Slot holding the base key for KDF
                                      mix_input, mix_input_len, // Input data (PIN + secret + salt)
                                      out_key, 32) == ATECC608A_SUCCESS; // Output 32 bytes
#else
  // Fallback for development builds (not production secure)
  // Simple hash-based KDF for dev.
  uint8_t hash_output[64]; // Use a larger output for hash to ensure enough bytes for out_key
  crypto_engine_hash256(mix_input, mix_input_len, hash_output);
  crypto_engine_hash256(hash_output, sizeof(hash_output), hash_output + 32); // Simple expansion
  memcpy(out_key, hash_output, 32);
  security_secure_zero(hash_output, sizeof(hash_output));
  success = true;
#endif

  security_secure_zero(mix_input, sizeof(mix_input));
  return success;
}

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
    return false;
  }
  if (ciphertext_capacity < plaintext_len) {
    return false;
  }

  bool success = false;
#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_available || !g_crypto_state.master_key_provisioned) {
      Error_Handler(); // Critical error in production
      return false;
  }
  // Use ATECC608A for AEAD encryption.
  // ATECC should handle nonce generation internally if possible, or expect it as part of AAD construction.
  success = atecc608a_encrypt_aead(ATECC608A_SLOT_MASTER_KEY, // Master key handle/slot
                                   plaintext, plaintext_len,
                                   aad, aad_len,
                                   ciphertext, ciphertext_capacity, ciphertext_len, out_tag);
#else // Development/non-production build
  // Fallback for development builds (not secure for production)
  // This is a simple XOR-based stream cipher with HMAC-like tag derivation for testing.
  uint8_t dev_key_stream[64]; // Simple pseudo-random stream
  crypto_engine_hash256(aad, aad_len, dev_key_stream);
  crypto_engine_hash256(dev_key_stream, sizeof(dev_key_stream), dev_key_stream + 32); // Expand key stream

  for (size_t i = 0u; i < plaintext_len && i < ciphertext_capacity; ++i) {
      ciphertext[i] = plaintext[i] ^ dev_key_stream[i % sizeof(dev_key_stream)];
  }
  *ciphertext_len = plaintext_len;
  // Simulate tag generation (HMAC-like with dev_key_stream used as key)
  uint8_t tag_input_buffer[aad_len + *ciphertext_len];
  if (aad != NULL && aad_len > 0) {
      memcpy(tag_input_buffer, aad, aad_len);
  }
  memcpy(tag_input_buffer + aad_len, ciphertext, *ciphertext_len);
  uint8_t full_tag_hash[32];
  crypto_engine_hash256(tag_input_buffer, aad_len + *ciphertext_len, full_tag_hash);
  memcpy(out_tag, full_tag_hash, 16); // Truncate to 16 bytes for tag
  security_secure_zero(dev_key_stream, sizeof(dev_key_stream));
  security_secure_zero(tag_input_buffer, sizeof(tag_input_buffer));
  security_secure_zero(full_tag_hash, sizeof(full_tag_hash));
  success = true;
#endif

  return success;
}

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
    return false;
  }
  if (plaintext_capacity < ciphertext_len) {
    return false;
  }

  bool success = false;

#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_available || !g_crypto_state.master_key_provisioned) {
      Error_Handler(); // Critical error in production
      return false;
  }
  // Use ATECC608A for AEAD decryption.
  // ATECC is expected to verify the tag internally and only then return plaintext.
  success = atecc608a_decrypt_aead(ATECC608A_SLOT_MASTER_KEY, // Master key handle/slot
                                   ciphertext, ciphertext_len,
                                   aad, aad_len,
                                   tag, // ATECC driver must verify this tag internally during decryption
                                   plaintext, plaintext_capacity, plaintext_len);
#else // Development/non-production build
  // Fallback for development builds (not secure for production)
  // Inverse of the XOR-based stream cipher with HMAC-like tag verification.
  uint8_t dev_key_stream[64]; // Pseudo-random stream used for encryption simulation
  crypto_engine_hash256(aad, aad_len, dev_key_stream);
  crypto_engine_hash256(dev_key_stream, sizeof(dev_key_stream), dev_key_stream + 32); // Expand key stream

  for (size_t i = 0u; i < ciphertext_len && i < plaintext_capacity; ++i) {
      plaintext[i] = ciphertext[i] ^ dev_key_stream[i % sizeof(dev_key_stream)];
  }
  *plaintext_len = ciphertext_len;

  // Re-calculate the expected tag based on the decrypted plaintext and AAD (for verification)
  uint8_t calculated_tag_input_buffer[aad_len + *plaintext_len];
  if (aad != NULL && aad_len > 0) {
      memcpy(calculated_tag_input_buffer, aad, aad_len);
  }
  memcpy(calculated_tag_input_buffer + aad_len, plaintext, *plaintext_len);
  uint8_t full_calculated_tag_hash[32];
  crypto_engine_hash256(calculated_tag_input_buffer, aad_len + *plaintext_len, full_calculated_tag_hash);
  uint8_t expected_tag_from_calc[16];
  memcpy(expected_tag_from_calc, full_calculated_tag_hash, 16); // Truncate to 16 bytes for tag

  // Verify the tag in constant time
  if (!sec_consttime_memeq(expected_tag_from_calc, tag, 16u)) {
      security_secure_zero(plaintext, plaintext_capacity); // Zeroize plaintext on authentication failure
      *plaintext_len = 0; // Indicate no plaintext was successfully decrypted
      success = false;
  } else {
      success = true;
  }
  security_secure_zero(dev_key_stream, sizeof(dev_key_stream));
  security_secure_zero(calculated_tag_input_buffer, sizeof(calculated_tag_input_buffer));
  security_secure_zero(full_calculated_tag_hash, sizeof(full_calculated_tag_hash));
  security_secure_zero(expected_tag_from_calc, sizeof(expected_tag_from_calc));
#endif

  if (!success) {
      security_secure_zero(plaintext, plaintext_capacity); // Ensure plaintext is zeroized on any failure path
      *plaintext_len = 0;
  }
  return success;
}

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
  uint8_t raw_ciphertext_bytes[PASSWORD_MAX_LENGTH];
  size_t raw_ciphertext_bytes_len = 0u;
  size_t decrypted_plaintext_len;

  if (ciphertext_formatted == NULL || plaintext_out == NULL || out_len < 2u) {
    return false;
  }
  if (!crypto_engine_ready_for_sensitive_ops()) {
    return false;
  }
  plaintext_out[0] = '\0'; // Ensure null termination from start

  // Expected format: "v1:aad_hex:tag_hex:ciphertext_hex"
  if (strncmp(ciphertext_formatted, "v1:", 3u) != 0) {
    return false; // Wrong version or format
  }

  aad_hex_str = ciphertext_formatted + 3u;
  sep1 = strchr(aad_hex_str, ':');
  if (sep1 == NULL) {
    return false; // Malformed
  }
  tag_hex_str = sep1 + 1u;
  sep2 = strchr(tag_hex_str, ':');
  if (sep2 == NULL) {
    return false; // Malformed
  }
  raw_ciphertext_hex_str = sep2 + 1u;

  aad_hex_len = (size_t)(sep1 - aad_hex_str);
  tag_hex_len = (size_t)(sep2 - tag_hex_str);
  raw_ciphertext_hex_len = strlen(raw_ciphertext_hex_str);

  // Validate hex string lengths
  if (aad_hex_len != 24u || tag_hex_len != 32u || raw_ciphertext_hex_len == 0u) {
    return false;
  }

  // Decode hex strings to bytes
  if (!hex_decode(aad_hex_str, aad_hex_len, aad_bytes, sizeof(aad_bytes), NULL) ||
      !hex_decode(tag_hex_str, tag_hex_len, tag_bytes, sizeof(tag_bytes), NULL) ||
      !hex_decode(raw_ciphertext_hex_str, raw_ciphertext_hex_len, raw_ciphertext_bytes, sizeof(raw_ciphertext_bytes), &raw_ciphertext_bytes_len)) {
    return false;
  }

  decrypted_plaintext_len = out_len - 1u; // Max length for plaintext_out, reserving space for null terminator

  bool success = crypto_engine_decrypt_aead(raw_ciphertext_bytes, raw_ciphertext_bytes_len,
                                            aad_bytes, sizeof(aad_bytes),
                                            tag_bytes,
                                            (uint8_t *)plaintext_out, decrypted_plaintext_len, &decrypted_plaintext_len);
  
  if (success) {
      plaintext_out[decrypted_plaintext_len] = '\0'; // Null-terminate the output.
  } else {
      security_secure_zero(plaintext_out, out_len); // Zeroize on failure.
      plaintext_out[0] = '\0';
  }

  // Zeroize intermediate sensitive data
  security_secure_zero(raw_ciphertext_bytes, sizeof(raw_ciphertext_bytes));
  security_secure_zero(tag_bytes, sizeof(tag_bytes));
  security_secure_zero(aad_bytes, sizeof(aad_bytes));
  
  return success;
}
