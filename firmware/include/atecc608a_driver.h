#ifndef ATECC608A_DRIVER_H
#define ATECC608A_DRIVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    CRYPTO_FUNCTION_ANY = 0,
    CRYPTO_FUNCTION_AEAD,
    CRYPTO_FUNCTION_KDF,
    CRYPTO_FUNCTION_ECDSA_SIGN,
    CRYPTO_FUNCTION_ECDSA_VERIFY,
    CRYPTO_FUNCTION_ECC_GENERATE,
    CRYPTO_FUNCTION_MAX
} CryptoFunctionType;

// Initialize the ATECC608A driver. This should be called once at startup.
// Returns true on success, false otherwise.
bool atecc608a_init(void);

// Perform a self-test of the ATECC608A.
// Returns true if the self-test passes, false otherwise.
bool atecc608a_self_test(void);

// Check if a specific slot in the ATECC608A is provisioned (i.e., contains data or a key).
// slot_idx: The index of the slot to check (0-15).
// Returns true if the slot is provisioned, false otherwise or on error.
bool atecc608a_is_slot_provisioned(uint8_t slot_idx);

// Write data to a specific slot in the ATECC608A.
// slot_idx: The index of the slot to write (0-15).
// data: The data to write.
// len: Length of data (<=32 bytes typically).
// Returns true on success, false otherwise.
bool atecc608a_write_slot(uint8_t slot_idx, const uint8_t *data, size_t len);

// Read data from a specific slot in the ATECC608A.
// slot_idx: The index of the slot to read (0-15).
// data: Buffer to receive the data.
// len: Expected length of data (must match slot contents).
// Returns true on success, false otherwise.
bool atecc608a_read_slot(uint8_t slot_idx, uint8_t *data, size_t len);

// Bind/lock a specific slot in the ATECC608A (finalizes configuration).
// slot_idx: The index of the slot to bind (0-15).
// Returns true on success, false otherwise.
bool atecc608a_bind_slot(uint8_t slot_idx);

// Compute SHA256 hash using ATECC608A hardware.
// data: Input data.
// len: Length of input data.
// digest: 32-byte output buffer for SHA256 digest.
// Returns true on success, false otherwise.
bool atecc608a_sha256(const uint8_t *data, size_t len, uint8_t *digest);

// AEAD Encryption (e.g., AES-GCM) using ATECC608A.
// key_slot: Slot containing the key (0-15).
// plaintext: Input plaintext.
// plaintext_len: Length of plaintext.
// aad: Additional authenticated data.
// aad_len: Length of AAD.
// nonce: Nonce/IV (may be NULL if handled internally).
// nonce_len: Length of nonce.
// ciphertext: Output buffer.
// ciphertext_capacity: Capacity of ciphertext buffer.
// ciphertext_len: Output length (set on success).
// tag: Authentication tag output (typically 16 bytes).
// Returns true on success, false otherwise.
bool atecc608a_encrypt_aead(uint8_t key_slot,
                            const uint8_t *plaintext, size_t plaintext_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *nonce, size_t nonce_len,
                            uint8_t *ciphertext, size_t ciphertext_capacity,
                            size_t *ciphertext_len,
                            uint8_t *tag);

// AEAD Decryption (e.g., AES-GCM) using ATECC608A.
// key_slot: Slot containing the key (0-15).
// ciphertext: Input ciphertext.
// ciphertext_len: Length of ciphertext.
// aad: Additional authenticated data.
// aad_len: Length of AAD.
// nonce: Nonce/IV (may be NULL if handled internally).
// nonce_len: Length of nonce.
// tag: Authentication tag input.
// plaintext: Output buffer.
// plaintext_capacity: Capacity of plaintext buffer.
// plaintext_len: Output length (set on success).
// Returns true on success (tag verified), false otherwise (incl. tag mismatch).
bool atecc608a_decrypt_aead(uint8_t key_slot,
                            const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *tag,
                            uint8_t *plaintext, size_t plaintext_capacity,
                            size_t *plaintext_len);

// Derive key material from parent key slot and output to buffer.
// parent_key_slot: Slot containing parent key.
// data: Input data for derivation.
// data_len: Length of input data.
// out_key: Output buffer for derived key.
// out_key_len: Length of output key material.
// Returns true on success, false otherwise.
bool atecc608a_derive_key_slot_and_output(uint8_t parent_key_slot,
                                          const uint8_t *data, size_t data_len,
                                          uint8_t *out_key, size_t out_key_len);

// Derive key from parent key slot and write to derived slot.
// parent_key_slot: Slot containing parent key.
// data: Input data for derivation.
// data_len: Length of input data.
// derived_key_slot: Target slot for derived key.
// Returns true on success, false otherwise.
bool atecc608a_derive_key_slot(uint8_t parent_key_slot,
                               const uint8_t *data, size_t data_len,
                               uint8_t derived_key_slot);

// Generate ECC P-256 keypair in slot, return public key.
// key_slot: Slot for private key (0-15).
// public_key: Output buffer (64 bytes uncompressed).
// Returns true on success, false otherwise.
bool atecc608a_generate_ec_keypair(uint8_t key_slot, uint8_t *public_key);

// ECDSA sign using private key in slot.
// key_slot: Slot containing private key.
// digest: 32-byte message digest (SHA256).
// signature: Output buffer (64 bytes R+S).
// Returns true on success, false otherwise.
bool atecc608a_ecdsa_sign(uint8_t key_slot, const uint8_t *digest, uint8_t *signature);

// ECDSA verify using external public key.
// public_key: Uncompressed P-256 public key (64 bytes).
// digest: 32-byte message digest.
// signature: 64-byte signature (R+S).
// Returns true if valid, false otherwise.
bool atecc608a_ecdsa_verify(const uint8_t *public_key, const uint8_t *digest, const uint8_t *signature);

// Check if ATECC608A is available (init + selftest passed).
bool atecc608a_is_available(void);

// Check if ATECC608A is ready for specific crypto function.
// func_type: Type of function to check.
// Returns true if ready, false otherwise.
bool atecc608a_is_ready(CryptoFunctionType func_type);

#endif /* ATECC608A_DRIVER_H */
