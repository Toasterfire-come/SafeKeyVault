#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Forward declarations for hardware driver enums/structs if needed
typedef enum {
    ATECC608A_SUCCESS = 0,
    ATECC608A_ERROR = -1,
    // Add other specific error codes as needed
} atecc608a_status_t;

typedef enum {
    ATECC608A_AEAD_INTERFACE,
    ATECC608A_KDF_INTERFACE,
    // Add other interface types
} atecc608a_interface_t;

typedef enum {
  CRYPTO_BACKEND_SOFTWARE_FALLBACK = 0,
  CRYPTO_BACKEND_ATECC608A
} crypto_backend_t;

typedef struct {
  crypto_backend_t backend;
  bool aead_interface_ready;
  bool kdf_interface_ready;
  bool secure_element_bound;
  bool production_mode;
} crypto_engine_status_t;

void crypto_engine_init(void);
void crypto_engine_set_master_key_slot_ready(void); // Indicates master key is ready in ATECC slot
bool crypto_engine_set_device_secret(const uint8_t *secret, size_t secret_len);
bool crypto_engine_bind_atecc_slot(uint8_t slot_id,
                                   const uint8_t *public_key,
                                   size_t public_key_len);
crypto_engine_status_t crypto_engine_get_status(void);

/* High-level password helpers used by firmware modules. */
bool crypto_engine_encrypt_password(const char *plaintext,
                                    char *ciphertext_out,
                                    size_t out_len);
bool crypto_engine_decrypt_password(const char *ciphertext,
                                    char *plaintext_out,
                                    size_t out_len);
void crypto_engine_password_fingerprint(const char *password,
                                        uint8_t out_fp[16],
                                        size_t out_len);
void crypto_engine_hash16(const uint8_t *data, size_t data_len, uint8_t out_fp[16]);

/* Primitives for AEAD and KDF integration using ATECC608A. */
bool crypto_engine_derive_pin_key(const char *pin,
                                  const uint8_t *salt,
                                  size_t salt_len,
                                  uint8_t out_key[32]);
bool crypto_engine_encrypt_aead(const uint8_t *plaintext,
                                size_t plaintext_len,
                                const uint8_t *aad,
                                size_t aad_len,
                                uint8_t *ciphertext,
                                size_t ciphertext_capacity,
                                size_t *ciphertext_len,
                                uint8_t out_tag[16]);
bool crypto_engine_decrypt_aead(const uint8_t *ciphertext,
                                size_t ciphertext_len,
                                const uint8_t *aad,
                                size_t aad_len,
                                const uint8_t tag[16],
                                uint8_t *plaintext,
                                size_t plaintext_capacity,
                                size_t *plaintext_len);

/* Secure Boot related crypto functions */
bool crypto_engine_ecdsa_verify(const uint8_t *public_key,
                                size_t public_key_len,
                                const uint8_t *message_hash,
                                size_t message_hash_len,
                                const uint8_t *signature,
                                size_t signature_len);

/* ATECC608A specific read/write slot functions */
bool crypto_engine_read_atecc_slot(uint8_t slot_id, uint8_t *data, size_t data_len);
bool crypto_engine_write_atecc_slot(uint8_t slot_id, const uint8_t *data, size_t data_len);

/* New declarations for FIDO2/CTAP2 implementation */
/**
 * @brief Generates an ECDSA P-256 key pair.
 *
 * @param public_key Buffer to store the public key (64 bytes for P-256).
 * @param public_key_len Size of the public_key buffer.
 * @param private_key Buffer to store the private key (32 bytes for P-256).
 * @param private_key_len Size of the private_key buffer.
 * @return true if key pair generation was successful, false otherwise.
 */
bool crypto_engine_generate_ec_keypair(uint8_t *public_key, size_t public_key_len); // Private key argument removed

/**
 * @brief Signs a message using an ECDSA private key.
 *
 * @param private_key The private key to use for signing.
 * @param private_key_len Length of the private key.
 * @param message The message to sign.
 * @param message_len Length of the message.
 * @param signature Buffer to store the resulting signature.
 * @param signature_len Size of the signature buffer.
 * @return true if signing was successful, false otherwise.
 */
bool crypto_engine_ecdsa_sign(const uint8_t key_slot_id, // Changed to key_slot_id
                              const uint8_t *message, size_t message_len,
                              uint8_t *signature, size_t signature_len);

/**
 * @brief Computes the SHA-256 hash of the given data.
 *
 * @param data The input data.
 * @param data_len Length of the input data.
 * @param out_hash Buffer to store the 32-byte SHA-256 hash.
 */
void crypto_engine_hash256(const uint8_t *data, size_t data_len, uint8_t out_hash[32]);

#endif /* CRYPTO_ENGINE_H */
