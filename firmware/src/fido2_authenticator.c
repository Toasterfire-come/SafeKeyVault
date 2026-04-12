#include "fido2_authenticator.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h"
#include "security_utils.h"

typedef struct {
  bool initialized;
  bool has_credential;
  uint8_t cred_id[64]; // Credential ID (might be raw public key hash, or other identifier)
  size_t cred_id_len;
  uint8_t rp_hash[32]; // Hash of Relying Party ID (SHA-256)
  uint8_t user_hash[32]; // Hash of User ID (SHA-256)
  uint32_t sign_counter;
} fido2_state_t;

static fido2_state_t g_fido2;

void fido2_authenticator_init(void) {
  // Use secure_zero to ensure sensitive data is not left in memory
  security_secure_zero(&g_fido2, sizeof(g_fido2));
  g_fido2.initialized = true;
}

bool fido2_create_credential(const char *rp_id,
                             const char *user_name,
                             const uint8_t *client_data_hash,
                             size_t hash_len,
                             fido2_credential_t *out_cred) {
  uint8_t seed[64];
  if (!g_fido2.initialized) {
    fido2_authenticator_init();
  }
  if (rp_id == NULL || user_name == NULL || client_data_hash == NULL || out_cred == NULL) {
    return false;
  }
  memset(seed, 0, sizeof(seed));
  memset(out_cred, 0, sizeof(*out_cred));

  crypto_engine_hash16((const uint8_t *)rp_id, strlen(rp_id), g_fido2.rp_hash);
  crypto_engine_hash16((const uint8_t *)user_name, strlen(user_name), g_fido2.user_hash);
  memcpy(seed, g_fido2.rp_hash, sizeof(g_fido2.rp_hash));
  memcpy(seed + 16u, g_fido2.user_hash, sizeof(g_fido2.user_hash));
  if (hash_len > 16u) {
    hash_len = 16u;
  }
  memcpy(seed + 32u, client_data_hash, hash_len);
  crypto_engine_hash16(seed, sizeof(seed), out_cred->id);
  out_cred->id_len = 16u;
  crypto_engine_hash16(out_cred->id, out_cred->id_len, out_cred->public_key);
  out_cred->public_key_len = 16u;

  memcpy(g_fido2.cred_id, out_cred->id, out_cred->id_len);
  g_fido2.cred_id_len = out_cred->id_len;
  g_fido2.has_credential = true;
  g_fido2.sign_counter = 0u;
  return true;
}

bool fido2_get_assertion(const char *rp_id,
                         const uint8_t *client_data_hash,
                         size_t hash_len,
                         fido2_assertion_t *out_assertion) {
  uint8_t auth_data_buf[256]; // Authenticator Data structure (placeholder size)
  size_t auth_data_len = 0;
  uint8_t rp_id_hash[32] = {0}; // RP ID hash (SHA-256)
  uint8_t signature_input_buffer[128] = {0}; // Buffer to hold data to be signed
  size_t signature_input_len = 0;
  uint8_t signature[64] = {0}; // ECDSA P-256 signature output
  uint8_t credential_private_key_handle[32] = {0}; // Placeholder for loading private key handle
  bool success = false;

  if (!g_fido2.initialized || !g_fido2.has_credential) {
    return false;
  }
  if (rp_id == NULL || client_data_hash == NULL || out_assertion == NULL || hash_len == 0 || hash_len > 32) {
    goto end;
  }
  memset(out_assertion, 0, sizeof(*out_assertion));

  // 1. Verify Relying Party ID hash
  crypto_engine_hash256((const uint8_t *)rp_id, strnlen(rp_id, 256), rp_id_hash);
  if (!sec_consttime_memeq(rp_id_hash, g_fido2.rp_hash, sizeof(rp_id_hash))) {
    goto end; // RP ID mismatch
  }

  // 2. Construct Authenticator Data (simplified)
  // rpIdHash (32 bytes)
  memcpy(auth_data_buf, g_fido2.rp_hash, sizeof(g_fido2.rp_hash));
  auth_data_len += sizeof(g_fido2.rp_hash);

  // flags (1 byte: UP, UV, AT, ED) - example: User Present (UP) flag only
  auth_data_buf[auth_data_len++] = 0x01; // Assuming only User Present (UP) flag is set

  // signCount (4 bytes)
  g_fido2.sign_counter++; // Increment counter
  memcpy(auth_data_buf + auth_data_len, &g_fido2.sign_counter, sizeof(g_fido2.sign_counter));
  auth_data_len += sizeof(g_fido2.sign_counter);

  // 3. Prepare data to be signed: hash(authenticatorData) || hash(clientDataJSON)
  signature_input_len = 0;
  // SHA-256 hash of Authenticator Data
  crypto_engine_hash256(auth_data_buf, auth_data_len, signature_input_buffer);
  signature_input_len += 32;

  // SHA-256 hash of Client Data Hash
  memcpy(signature_input_buffer + signature_input_len, client_data_hash, 32); // client_data_hash is already a hash
  signature_input_len += 32;

  // 4. Sign the data using the credential's private key
  // For production, this involves using the secure element to sign using the stored private key
  // For this stub, we'll simulate private key loading from a handle
  // (In real ATECC, you'd use a command to sign directly from slot)
  if (!crypto_engine_read_atecc_slot(ATECC608A_SLOT_CRED_PRIVKEY, credential_private_key_handle, sizeof(credential_private_key_handle))) {
      goto end; // Failed to get private key handle
  }

  if (!crypto_engine_ecdsa_sign(credential_private_key_handle, sizeof(credential_private_key_handle),
                                signature_input_buffer, signature_input_len,
                                signature, sizeof(signature))) {
    goto end;
  }

  // 5. Populate out_assertion
  memcpy(out_assertion->user_handle, g_fido2.user_hash, sizeof(g_fido2.user_hash));
  out_assertion->user_handle_len = sizeof(g_fido2.user_hash);
  memcpy(out_assertion->signature, signature, sizeof(signature));
  out_assertion->signature_len = sizeof(signature);
  out_assertion->sign_count = g_fido2.sign_counter;
  success = true;

end:
  // Securely zeroize sensitive intermediate buffers
  security_secure_zero(auth_data_buf, sizeof(auth_data_buf));
  security_secure_zero(rp_id_hash, sizeof(rp_id_hash));
  security_secure_zero(signature_input_buffer, sizeof(signature_input_buffer));
  security_secure_zero(signature, sizeof(signature));
  security_secure_zero(credential_private_key_handle, sizeof(credential_private_key_handle));
  return success;
}

