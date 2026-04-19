#ifndef ATECC608A_DRIVER_H
#define ATECC608A_DRIVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
// This function assumes the slot is configured for writing.
// slot_idx: The index of the slot to write to (0-15).
// data: Pointer to the data to write.
// len: The length of the data to write. This must match the slot's configuration.
// Returns true on success, false otherwise.
bool atecc608a_write_slot(uint8_t slot_idx, const uint8_t *data, size_t len);

// Read data from a specific slot in the ATECC608A.
// slot_idx: The index of the slot to read from (0-15).
// data: Pointer to the buffer where the read data will be stored.
// len: The expected length of the data to read. This must match the slot's configuration.
// Returns true on success, false otherwise.
bool atecc608a_read_slot(uint8_t slot_idx, uint8_t *data, size_t len);

// "Bind" a slot. This might involve locking a slot or performing a secure operation
// that permanently links its content or configuration. The exact behavior
// is highly dependent on the ATECC configuration and intended use case.
// For now, this can be a placeholder or a simplified operation.
// slot_idx: The index of the slot to bind.
// Returns true on success, false otherwise.
bool atecc608a_bind_slot(uint8_t slot_idx);

// Perform a hardware-accelerated SHA256 hash.
// data: Pointer to the input data.
// len: Length of the input data.
// digest: Pointer to the buffer where the 32-byte SHA256 digest will be stored.
// Returns true on success, false otherwise.
bool atecc608a_sha256(const uint8_t *data, size_t len, uint8_t *digest);

// Perform hardware-backed authenticated encryption (AEAD).
// This function needs further specification for actual AEAD modes and key usage.
// For now, it's a placeholder.
// key_slot: The ATECC slot containing the encryption key.
// plaintext: Input data to encrypt.
// plaintext_len: Length of the plaintext.
// aad: Additional authenticated data (can be NULL).
// aad_len: Length of AAD.
// nonce: Nonce for the encryption operation.
// nonce_len: Length of the nonce.
// ciphertext: Output buffer for ciphertext.
// tag: Output buffer for authentication tag.
// Returns true on success, false otherwise.
bool atecc608a_encrypt_aead(uint8_t key_slot,
                            const uint8_t *plaintext, size_t plaintext_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *nonce, size_t nonce_len,
                            uint8_t *ciphertext, uint8_t *tag);

// Perform hardware-backed authenticated decryption (AEAD).
// This function needs further specification for actual AEAD modes and key usage.
// For now, it's a placeholder.
// key_slot: The ATECC slot containing the decryption key.
// ciphertext: Input ciphertext to decrypt.
// ciphertext_len: Length of the ciphertext.
// aad: Additional authenticated data (can be NULL).
// aad_len: Length of AAD.
// nonce: Nonce used for encryption.
// nonce_len: Length of the nonce.
// tag: Authentication tag.
// plaintext: Output buffer for decrypted plaintext.
// Returns true on success, false otherwise.
bool atecc608a_decrypt_aead(uint8_t key_slot,
                            const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *tag,
                            uint8_t *plaintext);

// Perform hardware-backed key derivation function (KDF) using a key in a specified slot.
// parent_key_slot: The ATECC slot containing the parent key for derivation.
// data: Input data for KDF (e.g., salt, context).
// data_len: Length of input data.
// derived_key_slot: The ATECC slot where the derived key will be stored/used.
// Returns true on success, false otherwise.
bool atecc608a_derive_key_slot(uint8_t parent_key_slot,
                               const uint8_t *data, size_t data_len,
                               uint8_t derived_key_slot);

// Generate an ECC key pair within the ATECC608A.
// key_slot: The ATECC slot where the private key will be generated and stored.
// public_key: Output buffer for the 64-byte uncompressed public key (X and Y coordinates).
// Returns true on success, false otherwise.
bool atecc608a_generate_ec_keypair(uint8_t key_slot, uint8_t *public_key);

// Perform hardware-backed ECDSA signing using a private key in a specified slot.
// key_slot: The ATECC slot containing the private key for signing.
// digest: The 32-byte hash (digest) to be signed.
// signature: Output buffer for the ECDSA signature (64 bytes: R and S components).
// Returns true on success, false otherwise.
bool atecc608a_ecdsa_sign(uint8_t key_slot, const uint8_t *digest, uint8_t *signature);

// Perform hardware-backed ECDSA signature verification.
// public_key: The 64-byte uncompressed public key (X and Y coordinates).
// digest: The 32-byte hash (digest) that was signed.
// signature: The 64-byte ECDSA signature to verify.
// Returns true if the signature is valid, false otherwise.
bool atecc608a_ecdsa_verify(const uint8_t *public_key, const uint8_t *digest, const uint8_t *signature);

#endif // ATECC608A_DRIVER_H
