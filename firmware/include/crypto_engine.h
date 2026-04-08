#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  CRYPTO_BACKEND_SOFTWARE_FALLBACK = 0,
  CRYPTO_BACKEND_ATECC608A
} crypto_backend_t;

typedef struct {
  crypto_backend_t backend;
  bool aead_interface_ready;
  bool kdf_interface_ready;
  bool secure_element_bound;
} crypto_engine_status_t;

void crypto_engine_init(void);
void crypto_engine_set_master_key(const uint8_t *key, size_t key_len);
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

/* Future-ready primitives for AEAD and KDF integration. */
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

#endif /* CRYPTO_ENGINE_H */
