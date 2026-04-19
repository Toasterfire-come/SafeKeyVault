#include "crypto_stub.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h" // Include the real crypto engine APIs
#include "security_utils.h" // For security_secure_zero

/**
 * @brief This module provides stub implementations for cryptographic functions.
 *        These stubs are used primarily for host tests and development builds
 *        where a hardware secure element (like ATECC608A) is not available.
 *        In production firmware, these calls are replaced by direct interactions
 *        with the secure element via the `crypto_engine` functions.
 *
 *        The functions here now largely delegate to the `crypto_engine` APIs,
 *        assuming the `crypto_engine` itself will provide the necessary
 *        software fallbacks or be mocked for testing purposes.
 */


void crypto_stub_set_master_key(const uint8_t *key, size_t key_len) {
  // In a production system utilizing ATECC, the master key is provisioned
  // directly into the ATECC and not handled explicitly by software this way.
  // This stub function is primarily for older test patterns or scenarios
  // where a software-managed master key might still be used in dev builds.
  // For the updated design, this would essentially be a no-op or would
  // simulate setting up a software key for fallback operations within crypto_engine.
  (void)key; // Suppress unused parameter warning
  (void)key_len; // Suppress unused parameter warning
}

bool crypto_stub_encrypt_password(const char *plaintext, char *ciphertext_out, size_t out_len) {
  // Delegate to the main crypto engine's password encryption function.
  // The crypto engine internally handles selecting hardware or software implementation.
  return crypto_engine_encrypt_password(plaintext, ciphertext_out, out_len);
}

bool crypto_stub_decrypt_password(const char *ciphertext, char *plaintext_out, size_t out_len) {
  // Delegate to the main crypto engine's password decryption function.
  return crypto_engine_decrypt_password(ciphertext, plaintext_out, out_len);
}

void crypto_stub_password_fingerprint(const char *password, uint8_t out_fp[16], size_t out_len) {
  // Delegate to the main crypto engine's password fingerprint function.
  crypto_engine_password_fingerprint(password, out_fp, out_len);
}

void crypto_stub_hash16(const uint8_t *data, size_t data_len, uint8_t out_fp[16]) {
  // Delegate to the main crypto engine's hash16 function.
  crypto_engine_hash16(data, data_len, out_fp);
}

void crypto_stub_hash256(const uint8_t *data, size_t data_len, uint8_t out_hash[32]) {
  // Delegate to the main crypto engine's hash256 function.
  crypto_engine_hash256(data, data_len, out_hash);
}

bool crypto_stub_generate_ec_keypair(uint8_t *public_key, size_t public_key_len, uint8_t *private_key, size_t private_key_len) {
  // Delegate to the main crypto engine's keypair generation function.
  // The `crypto_engine_generate_ec_keypair` no longer accepts `private_key` directly,
  // as the private key is held securely within the ATECC.
  // For the stub, we still provide a dummy `private_key` if a caller expects it,
  // but it's not used by the underlying `crypto_engine` call in its current definition.
  bool result = crypto_engine_generate_ec_keypair(public_key, public_key_len);
  if (result && private_key != NULL && private_key_len >= 32) {
    // Fill `private_key` with dummy data if the stub caller expects it.
    // In a real secure element context, this would not happen.
    for (size_t i = 0; i < 32; ++i) {
      private_key[i] = (uint8_t)(0xDE + i); // Dummy private key material
    }
  } else if (private_key != NULL && private_key_len > 0) {
    security_secure_zero(private_key, private_key_len);
  }
  return result;
}

bool crypto_stub_ecdsa_sign(const uint8_t *private_key_bytes, size_t private_key_len, const uint8_t *message, size_t message_len, uint8_t *signature, size_t signature_len) {
  // Delegate to the main crypto engine's signing function.
  // The `crypto_engine_ecdsa_sign` now expects a `key_slot_id` not raw private key bytes.
  // For the stub, we will use a specific ATECC slot ID for signing.
  (void)private_key_bytes; // Unused in this new delegation model
  (void)private_key_len;   // Unused

  // Using a predefined slot ID for signing in stub/test environments.
  // ATECC608A_SLOT_SIGNING_PRIVKEY should be defined in `atecc608a_driver.h` or similar.
  return crypto_engine_ecdsa_sign(ATECC608A_SLOT_SIGNING_PRIVKEY, message, message_len, signature, signature_len);
}
