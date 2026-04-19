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
// Perform hardware-backed ECDSA signature verification.
// public_key: The 64-byte uncompressed public key (X and Y coordinates).
// digest: The 32-byte hash (digest) that was signed.
// signature: The 64-byte ECDSA signature to verify.
// Returns true if the signature is valid, false otherwise.
// Note: `public_key_len`, `digest_len`, `signature_len` are omitted assuming P-256 (64-byte pubkey, 32-byte digest, 64-byte sig).
bool atecc608a_ecdsa_verify(const uint8_t *public_key, const uint8_t *digest, const uint8_t *signature);

// Check if the ATECC608A is generally available (initialized and self-test passed).
// Returns true if available, false otherwise.
bool atecc608a_is_available(void);

// Enum for specific cryptographic functions the crypto_engine might query from ATECC.
typedef enum {
    CRYPTO_FUNCTION_ANY = 0,             // General availability or any function
    CRYPTO_FUNCTION_AEAD,                // Authenticated Encryption with Associated Data
    CRYPTO_FUNCTION_KDF,                 // Key Derivation Function
    CRYPTO_FUNCTION_ECDSA_SIGN,          // ECDSA Signing
    CRYPTO_FUNCTION_ECDSA_VERIFY,        // ECDSA Verification
    CRYPTO_FUNCTION_ECC_GENERATE         // ECC Key Pair Generation
} CryptoFunctionType;

// Check if the ATECC608A is ready for a specific cryptographic function.
// This allows checking for availability of specific features/slots.
// func_type: The type of cryptographic function to check readiness for.
// Returns true if ready, false otherwise.
bool atecc608a_is_ready(CryptoFunctionType func_type);

// This function directly outputs derived key material.
// In a real ATECC, derived keys are often placed in other slots or require specific commands to read.
// This adjusts the mock implementation to match the crypto_engine's expectation for fingerprinting and KDFs that output direct material.
// parent_key_slot: The ATECC slot containing the parent key for derivation.
// data: Input data for KDF (e.g., salt, context).
// data_len: Length of input data.
// out_key: Output buffer for the derived key material.
// out_key_len: Expected length of the derived key. Must be <= 32 bytes for current simulation.
// Returns true on success, false otherwise.
bool atecc608a_derive_key_slot_and_output(uint8_t parent_key_slot,
                                          const uint8_t *data, size_t data_len,
                                          uint8_t *out_key, size_t out_key_len);

// Updated AEAD encryption signature to include capacity and return length for more flexible use.
bool atecc608a_encrypt_aead(uint8_t key_slot,
                            const uint8_t *plaintext, size_t plaintext_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *nonce, size_t nonce_len,         // Nonce can be NULL if managed internally
                            uint8_t *ciphertext, size_t ciphertext_capacity, // Capacity of ciphertext buffer
                            size_t *ciphertext_len,                          // Actual length of ciphertext written
                            uint8_t *tag);                                   // 16-byte authentication tag

// Updated AEAD decryption signature to include capacity and return length.
bool atecc608a_decrypt_aead(uint8_t key_slot,
                            const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *nonce, size_t nonce_len,         // Nonce can be NULL if managed internally
                            const uint8_t *tag,
                            uint8_t *plaintext, size_t plaintext_capacity,   // Capacity of plaintext buffer
                            size_t *plaintext_len);                          // Actual length of plaintext written

// Simplified signatures for generate_ec_keypair and ecdsa_sign assuming P-256 curve details.
bool atecc608a_generate_ec_keypair(uint8_t key_slot, uint8_t *public_key); // Public key is 64 bytes
bool atecc608a_ecdsa_sign(uint8_t key_slot, const uint8_t *digest, uint8_t *signature); // Digest is 32 bytes, signature 64 bytes

#endif // ATECC608A_DRIVER_H
