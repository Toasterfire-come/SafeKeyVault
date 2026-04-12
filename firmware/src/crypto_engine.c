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
                                 nonce, sizeof(nonce), // Nonce as AAD for now; ATECC should generate internal unique nonce
                                 ciphertext, sizeof(ciphertext), &ciphertext_len, tag);
#else
  if (!g_crypto_state.secure_element_bound) {
      // Fallback to stub for development builds if ATECC is not bound or fails
      // Fallback to stub for development builds if ATECC is not bound or fails
      // THIS IS NOT A SECURE IMPLEMENTATION FOR PRODUCTION.
      success = crypto_stub_encrypt_password(plaintext, (char*)ciphertext, sizeof(ciphertext));
      if (success) {
          crypto_stub_hash16(ciphertext, ciphertext_len, tag); // Simulate tag
          ciphertext_len = strlen((char*)ciphertext); // Stub returns null-terminated string
      } else {
          Error_Handler(); // Placeholder: In production, this should not occur if stub is not used.
      }
  } else {
      // If ATECC is available in development, use it.
      success = atecc608a_encrypt_aead(ATECC608A_SLOT_MASTER_KEY,
                                     (const uint8_t *)plaintext, plaintext_len,
                                     nonce, sizeof(nonce),
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

bool crypto_engine_decrypt_password(const char *ciphertext,
                                    char *plaintext_out,
                                    size_t out_len) {
  const char *nonce_hex;
  const char *tag_hex;
  const char *ciphertext_hex;
  const char *sep1;
  const char *sep2;
  size_t nonce_hex_len;
  size_t tag_hex_len;
  size_t ciphertext_hex_len;
  uint8_t nonce[12];
  uint8_t tag[16];
  uint8_t ciphertext_bytes[PASSWORD_MAX_LENGTH];
  size_t ciphertext_len = 0u;
  size_t plaintext_len;

  if (ciphertext == NULL || plaintext_out == NULL || out_len < 2u) {
    return false;
  }
  if (!crypto_engine_ready_for_sensitive_ops()) {
    return false;
  }
  plaintext_out[0] = '\0';
  if (strncmp(ciphertext, "v1:", 3u) != 0) {
    return false;
  }

  nonce_hex = ciphertext + 3u;
  sep1 = strchr(nonce_hex, ':');
  if (sep1 == NULL) {
    return false;
  }
  tag_hex = sep1 + 1u;
  sep2 = strchr(tag_hex, ':');
  if (sep2 == NULL) {
    return false;
  }
  ciphertext_hex = sep2 + 1u;

  nonce_hex_len = (size_t)(sep1 - nonce_hex);
  tag_hex_len = (size_t)(sep2 - tag_hex);
  ciphertext_hex_len = strlen(ciphertext_hex);

  if (nonce_hex_len != 24u || tag_hex_len != 32u || ciphertext_hex_len == 0u) {
    return false;
  }
  if (!hex_decode(nonce_hex, nonce_hex_len, nonce, sizeof(nonce), NULL) ||
      !hex_decode(tag_hex, tag_hex_len, tag, sizeof(tag), NULL) ||
      !hex_decode(ciphertext_hex, ciphertext_hex_len, ciphertext_bytes, sizeof(ciphertext_bytes), &ciphertext_len)) {
    return false;
  }

  plaintext_len = out_len - 1u; // Max length for plaintext_out, reserving space for null terminator
  bool success;

#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_bound) {
      return false; // In production, ATECC must always be used
  }
  // Use ATECC608A for AEAD decryption
  // ATECC608A_SLOT_MASTER_KEY holds the key for decryption
  success = atecc608a_decrypt_aead(ATECC608A_SLOT_MASTER_KEY,
                                 ciphertext_bytes, ciphertext_len,
                                 nonce, sizeof(nonce), // Nonce as AAD
                                 tag,
                                 (uint8_t *)plaintext_out, plaintext_len, &plaintext_len);
#else
  if (!g_crypto_state.secure_element_bound) {
      // Fallback to stub for development builds if ATECC is not bound or fails
      success = crypto_stub_decrypt_password((const char*)ciphertext_bytes, plaintext_out, out_len);
      if (success) {
          plaintext_len = strlen(plaintext_out); // Stub returns null-terminated string
      } else {
           Error_Handler(); // Placeholder: In production, this should not occur if stub is not used.
      }
  } else {
      // Use ATECC608A for AEAD decryption even in dev mode if bound
      success = atecc608a_decrypt_aead(ATECC608A_SLOT_MASTER_KEY,
                                     ciphertext_bytes, ciphertext_len,
                                     nonce, sizeof(nonce),
                                     tag,
                                     (uint8_t *)plaintext_out, plaintext_len, &plaintext_len);
  }
#endif

  if (!success) {
    security_secure_zero(ciphertext_bytes, sizeof(ciphertext_bytes));
    security_secure_zero(tag, sizeof(tag));
    security_secure_zero(nonce, sizeof(nonce));
    return false; // Decryption or tag verification failed
  }

  // Ensure null termination if the plaintext_len is less than out_len
  if (plaintext_len < out_len) {
      plaintext_out[plaintext_len] = '\0';
  } else {
      // If decrypted plaintext is too long for buffer, treat as error and zeroize
      security_secure_zero(plaintext_out, out_len);
      return false;
  }

  security_secure_zero(ciphertext_bytes, sizeof(ciphertext_bytes));
  security_secure_zero(tag, sizeof(tag));
  security_secure_zero(nonce, sizeof(nonce));
  return true;
}

void crypto_engine_password_fingerprint(const char *password,
                                        uint8_t out_fp[16],
                                        size_t out_len) {
#if FIRMWARE_PRODUCTION
  if (g_crypto_state.secure_element_bound) {
    // In production, password fingerprinting should use a secure derivation from the ATECC.
    // This implementation uses SHA256 of the password truncated to 16 bytes. This is not
    // a true "fingerprint" leveraging the secure element directly but a software hash.
    uint8_t hash_full[32];
    crypto_engine_hash256((const uint8_t*)password, strlen(password), hash_full);
    memcpy(out_fp, hash_full, (out_len < 16) ? out_len : 16); // Truncate or copy fully
    security_secure_zero(hash_full, sizeof(hash_full));
  } else {
    // In production, if the secure element is not bound, then sensitive operations halt.
    Error_Handler();
    security_secure_zero(out_fp, out_len); // Ensure output is zeroized on failure path.
  }
#else
  // Use stub for fingerprinting in dev builds if not in production.
  crypto_stub_password_fingerprint(password, out_fp, out_len);
#endif
}

void crypto_engine_hash16(const uint8_t *data, size_t data_len, uint8_t out_fp[16]) {
#if FIRMWARE_PRODUCTION
  if (g_crypto_state.secure_element_bound) {
      // In production, use ATECC for hashing if available. This example assumes SHA256 truncated.
      uint8_t hash_full[32];
      crypto_engine_hash256(data, data_len, hash_full); // Call SHA256 and truncate
      memcpy(out_fp, hash_full, 16);
      security_secure_zero(hash_full, sizeof(hash_full));
  } else {
      Error_Handler(); // In production, if SE is not bound, critical error.
      security_secure_zero(out_fp, 16); // Zeroize output on failure.
  }
#else
  // Fallback to stub for hashing in dev builds.
  crypto_stub_hash16(data, data_len, out_fp);
#endif
}

bool crypto_engine_ecdsa_verify(const uint8_t *public_key,
                                size_t public_key_len,
                                const uint8_t *message_hash,
                                size_t message_hash_len,
                                const uint8_t *signature,
                                size_t signature_len) {
#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_bound) {
      return false; // In production, ATECC is mandatory for verification
  }
  // Use ATECC608A for ECDSA verification exclusively.
  // ATECC608A_SLOT_PUBKEY (slot 2) is designated for this in the request.
  return atecc608a_ecdsa_verify(ATECC608A_SLOT_PUBKEY,
                                public_key, public_key_len, // These should likely be the public key associated with SLOT_PUBKEY
                                message_hash, message_hash_len,
                                signature, signature_len) == ATECC608A_SUCCESS;
#else
  // Fallback to stub for testing/development
  return crypto_stub_ecdsa_verify(public_key, public_key_len, message_hash, message_hash_len, signature, signature_len);
#endif
}

bool crypto_engine_generate_ec_keypair(uint8_t *public_key, size_t public_key_len, uint8_t *private_key, size_t private_key_len) {
#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_bound) {
      Error_Handler(); // In production, ATECC is mandatory for key generation.
      return false;
  }
  // Delegate to ATECC608A to generate a key pair and store the private part securely internally.
  // The ATECC function should return the public key.
  // The 'private_key' parameter is unused here as the private key stays in ATECC.
  (void)private_key;
  (void)private_key_len;
  return atecc608a_generate_ec_keypair(public_key, public_key_len) == ATECC608A_SUCCESS;
#else
  // Fallback to stub for testing/development
  return crypto_stub_generate_ec_keypair(public_key, public_key_len, private_key, private_key_len);
#endif
}

bool crypto_engine_ecdsa_sign(const uint8_t *key_slot_id_ptr, size_t key_slot_id_len, // Changed private_key to key_slot_id_ptr for ATECC slot reference
                              const uint8_t *message, size_t message_len,
                              uint8_t *signature, size_t signature_len) {
#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_bound) {
      Error_Handler(); // In production, ATECC is mandatory for signing.
      return false;
  }
  // Delegate to ATECC608A for actual signing.
  // The 'key_slot_id_ptr' parameter points to the ID of the ATECC slot containing the private key.
  // 'key_slot_id_len' must be 1 (sizeof(uint8_t)) for a single slot ID.
  // The message hash should be computed before calling this function.
  if (key_slot_id_ptr == NULL || key_slot_id_len != 1) {
      return false;
  }
  return atecc608a_ecdsa_sign(*key_slot_id_ptr, message, message_len, signature, signature_len) == ATECC608A_SUCCESS;
#else
  // Fallback to stub for testing/development.
  // The 'key_slot_id_ptr' here is passed to the stub as a conceptual identifier, not a real key.
  return crypto_stub_ecdsa_sign(key_slot_id_ptr, key_slot_id_len, message, message_len, signature, signature_len);
#endif
}

void crypto_engine_hash256(const uint8_t *data, size_t data_len, uint8_t out_hash[32]) {
#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_bound) {
    // In production, if ATECC is not bound, hashing cannot be performed securely.
    // Zeroize output and return.
    security_secure_zero(out_hash, 32);
    return;
  }
  // In production, use ATECC608A for SHA-256 hashing if available via the driver.
  // Assuming a function like atecc608a_sha256 exists or can be implemented.
  // For simplicity using software library if ATECC does not provide generic SHA256 directly.
  // The most secure method would be to use ATECC's internal SHA.
  atecc608a_sha256(data, data_len, out_hash); // Assuming this function is implemented in atecc driver
#else
  crypto_stub_hash256(data, data_len, out_hash);
#endif
}

bool crypto_engine_read_atecc_slot(uint8_t slot_id, uint8_t *data, size_t data_len) {
    if (g_crypto_state.secure_element_bound) {
        return atecc608a_read_slot(slot_id, data, data_len) == ATECC608A_SUCCESS;
    }
    return false;
}

bool crypto_engine_write_atecc_slot(uint8_t slot_id, const uint8_t *data, size_t data_len) {
    if (g_crypto_state.secure_element_bound) {
        return atecc608a_write_slot(slot_id, data, data_len) == ATECC608A_SUCCESS;
    }
    return false;
}


bool crypto_engine_derive_pin_key(const char *pin,
                                  const uint8_t *salt,
                                  size_t salt_len,
                                  uint8_t out_key[32]) {
  uint8_t hash_a[16];
  uint8_t hash_b[16];
  uint8_t mix[64];
  size_t secret_copy_len = 0u;
  size_t pin_len = 0u;
  size_t i;

  if (pin == NULL || out_key == NULL) {
    return false;
  }
  pin_len = strlen(pin);
  if (pin_len == 0u) {
    return false;
  }
  memset(mix, 0, sizeof(mix));
  if (pin_len > sizeof(mix)) {
    pin_len = sizeof(mix);
  }
  memcpy(mix, pin, pin_len);
  if (g_crypto_state.device_secret_set_in_atecc) {
    // Attempt to read the device secret from ATECC to mix into KDF input.
    // This is a more secure approach than storing it in RAM.
    uint8_t device_secret_component[16]; // Use a portion for mixing
    if (crypto_engine_read_atecc_slot(ATECC608A_SLOT_DEVICE_SECRET, device_secret_component, sizeof(device_secret_component))) {
        secret_copy_len = sizeof(device_secret_component);
        if (secret_copy_len > (sizeof(mix) - pin_len)) {
            secret_copy_len = sizeof(mix) - pin_len;
        }
        memcpy(mix + pin_len, device_secret_component, secret_copy_len);
        security_secure_zero(device_secret_component, sizeof(device_secret_component));
    } else {
      // In production, if device secret cannot be read from ATECC, KDF should fail.
#if FIRMWARE_PRODUCTION
      Error_Handler(); // Critical error: cannot derive key without device secret.
#endif
      security_secure_zero(mix, sizeof(mix));
      return false;
    }
  } else {
    // In production, device secret is mandatory for KDF operations
#if FIRMWARE_PRODUCTION
    Error_Handler(); // Critical error: device secret not set.
#endif
    security_secure_zero(mix, sizeof(mix));
    return false;
  }
  if (salt != NULL && salt_len > 0u) {
    size_t copy_len = salt_len;
    size_t salt_offset = pin_len + secret_copy_len;
    if (salt_offset >= sizeof(mix)) {
      copy_len = 0u;
    }
    if (copy_len > (sizeof(mix) - salt_offset)) {
      copy_len = sizeof(mix) - salt_offset;
    }
    if (copy_len > 0u) {
      memcpy(mix + salt_offset, salt, copy_len);
    }
  }

  bool success;
#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_bound) {
      Error_Handler(); // In production, ATECC is mandatory for KDF
      security_secure_zero(mix, sizeof(mix));
      return false;
  }
  // Use ATECC608A for key derivation (PBKDF2 equivalent).
  // ATECC608A_SLOT_DEVICE_SECRET is the key controlling the derivation.
  // The 'mix' data acts as the password/salt for the KDF.
  // The ATECC is expected to provide 32-byte output and handle iterations securely.
  success = atecc608a_derive_key_slot(ATECC608A_SLOT_DEVICE_SECRET, // Slot that holds the device secret as base key
                                      mix, sizeof(mix), // Password & Salt input
                                      out_key, 32) == ATECC608A_SUCCESS; // Output 32 bytes
#else
  // Fallback to stub for development builds if ATECC is not bound or fails.
  crypto_stub_hash16(mix, sizeof(mix), hash_a);
  crypto_stub_hash16(hash_a, sizeof(hash_a), hash_b);
  for (i = 0u; i < 16u; ++i) {
    out_key[i] = hash_a[i];
    out_key[i + 16u] = hash_b[i];
  }
  security_secure_zero(hash_a, sizeof(hash_a));
  security_secure_zero(hash_b, sizeof(hash_b));
  success = true;
#endif

  if (!success) {
      security_secure_zero(mix, sizeof(mix));
      return false;
  }
  security_secure_zero(mix, sizeof(mix));
  return true;
}

bool crypto_engine_encrypt_aead(const uint8_t *plaintext,
                                size_t plaintext_len,
                                const uint8_t *aad,
                                size_t aad_len,
                                uint8_t *ciphertext,
                                size_t ciphertext_capacity,
                                size_t *ciphertext_len,
                                uint8_t out_tag[16]) {
  size_t i;
  uint8_t mac_input[64];
  if (plaintext == NULL || ciphertext == NULL || ciphertext_len == NULL || out_tag == NULL) {
    return false;
  }
  if (!crypto_engine_ready_for_sensitive_ops()) {
    return false;
  }
  if (ciphertext_capacity < plaintext_len) {
    return false;
  }

#if FIRMWARE_PRODUCTION
#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_bound) {
      Error_Handler(); // ATECC must be bound in production
      return false;
  }
  // Use ATECC608A for AEAD encryption. It handles nonce internally for each call as per API or expects it as AAD.
  // AAD ensures integrity of associated data (like version/CRC)
  success = atecc608a_encrypt_aead(ATECC608A_SLOT_MASTER_KEY,
                                   plaintext, plaintext_len,
                                   aad, aad_len,
                                   ciphertext, ciphertext_capacity, ciphertext_len, out_tag);

#else // Development/non-production build
  if (!g_crypto_state.secure_element_bound) {
      // Fallback to stub for development builds if ATECC is not bound.
      // THIS IS NOT A SECURE IMPLEMENTATION FOR PRODUCTION.
      for (i = 0u; i < plaintext_len && i < ciphertext_capacity; ++i) {
          ciphertext[i] = plaintext[i] ^ (uint8_t)(i % 256); // Simple stream cipher for stub
      }
      *ciphertext_len = plaintext_len;
      crypto_stub_hash16(ciphertext, *ciphertext_len, out_tag); // Simulate tag.
      success = true;
  } else {
      // If ATECC is available in development, use it.
      success = atecc608a_encrypt_aead(ATECC608A_SLOT_MASTER_KEY,
                                       plaintext, plaintext_len,
                                       aad, aad_len,
                                       ciphertext, ciphertext_capacity, ciphertext_len, out_tag);
  }
#endif

  if (!success) {
      return false;
  }
  return true;
}

bool crypto_engine_decrypt_aead(const uint8_t *ciphertext,
                                size_t ciphertext_len,
                                const uint8_t *aad,
                                size_t aad_len,
                                const uint8_t tag[16],
                                uint8_t *plaintext,
                                size_t plaintext_capacity,
                                size_t *plaintext_len) {
  size_t i;
  uint8_t expected_tag[16];
  uint8_t mac_input[64];

  if (ciphertext == NULL || plaintext == NULL || plaintext_len == NULL || tag == NULL) {
    return false;
  }
  if (!crypto_engine_ready_for_sensitive_ops()) {
    return false;
  }
  if (plaintext_capacity < ciphertext_len) {
    return false;
  }

#if FIRMWARE_PRODUCTION
  if (!g_crypto_state.secure_element_bound) {
      return false; // ATECC must be bound in production
  }
  // Use ATECC608A for AEAD decryption.
  success = atecc608a_decrypt_aead(ATECC608A_SLOT_MASTER_KEY,
                                   ciphertext, ciphertext_len,
                                   aad, aad_len,
                                   tag, // ATECC driver must verify this tag internally
                                   plaintext, plaintext_capacity, plaintext_len);
#else // Development/non-production build
  uint8_t expected_tag[16]; // Only used in stub/software fallback
  if (!g_crypto_state.secure_element_bound) {
      // Fallback to stub for development builds if ATECC is not bound.
      // THIS IS NOT A SECURE IMPLEMENTATION FOR PRODUCTION.
      uint8_t mac_input[64]; // For stub's MAC calculation (if enabled)
      for (i = 0u; i < ciphertext_len && i < plaintext_capacity; ++i) {
          plaintext[i] = ciphertext[i] ^ (uint8_t)(i % 256); // Simple stream cipher for stub
      }
      *plaintext_len = ciphertext_len;
      // For the stub implementation, we re-hash to get the expected tag.
      // This is a simplified MAC calculation.
      memset(mac_input, 0, sizeof(mac_input));
      size_t current_mac_input_len = 0;
      if (aad != NULL && aad_len > 0) {
          memcpy(mac_input, aad, (aad_len > sizeof(mac_input)) ? sizeof(mac_input) : aad_len);
          current_mac_input_len = (aad_len > sizeof(mac_input)) ? sizeof(mac_input) : aad_len;
      }
      if (*plaintext_len > 0) {
          size_t copy_len = (*plaintext_len > (sizeof(mac_input) - current_mac_input_len)) ? (sizeof(mac_input) - current_mac_input_len) : *plaintext_len;
          memcpy(mac_input + current_mac_input_len, plaintext, copy_len);
          current_mac_input_len += copy_len;
      }
      crypto_stub_hash16(mac_input, current_mac_input_len, expected_tag);

      // Verify stub tag
      if (!sec_consttime_memeq(expected_tag, tag, 16u)) {
          security_secure_zero(expected_tag, sizeof(expected_tag));
          security_secure_zero(mac_input, sizeof(mac_input));
          security_secure_zero(plaintext, *plaintext_len); // Zeroize plaintext on auth failure
          *plaintext_len = 0; // Indicate no plaintext output
          return false;
      }
      security_secure_zero(expected_tag, sizeof(expected_tag));
      security_secure_zero(mac_input, sizeof(mac_input));
      success = true; // Decryption succeeded for stub path
  } else {
      // If ATECC is available in development, use it.
      success = atecc608a_decrypt_aead(ATECC608A_SLOT_MASTER_KEY,
                                       ciphertext, ciphertext_len,
                                       aad, aad_len,
                                       tag,
                                       plaintext, plaintext_capacity, plaintext_len);
  }
#endif

  if (!success) {
      security_secure_zero(plaintext, ciphertext_len); // Zeroize plaintext on failure
      return false;
  }
  return true;
}
