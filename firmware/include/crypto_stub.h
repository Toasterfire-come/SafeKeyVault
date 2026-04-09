#ifndef CRYPTO_STUB_H
#define CRYPTO_STUB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Stub APIs for host tests; replace with AEAD + secure element key derivation on device. */
void crypto_stub_set_master_key(const uint8_t *key, size_t key_len);
bool crypto_stub_encrypt_password(const char *plaintext, char *ciphertext_out, size_t out_len);
bool crypto_stub_decrypt_password(const char *ciphertext, char *plaintext_out, size_t out_len);
void crypto_stub_password_fingerprint(const char *password, uint8_t out_fp[16], size_t out_len);
void crypto_stub_hash16(const uint8_t *data, size_t data_len, uint8_t out_fp[16]);

#endif /* CRYPTO_STUB_H */
