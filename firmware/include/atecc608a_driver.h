#ifndef ATECC608A_DRIVER_H
#define ATECC608A_DRIVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// --- IMPORTANT ---
// This header file defines the interface for the ATECC608A driver.
// The implementation in `atecc608a_driver.c` currently uses STUBS and SIMULATIONS.
// In a real implementation, these functions would interface with the ATECC608A hardware
// via the Microchip CryptoAuthLib and an appropriate HAL (e.g., I2C/SWI drivers).
// --- IMPORTANT ---

// Define common slot indices for clarity. These are typical for ATECC608A.
// Actual usage may vary based on device configuration and provisioning.
#define ATECC608A_SLOT_RESERVED_0           0
#define ATECC608A_SLOT_RESERVED_1           1
#define ATECC608A_SLOT_RESERVED_2           2
#define ATECC608A_SLOT_RESERVED_3           3
#define ATECC608A_SLOT_DEVICE_SECRET        4  // Often used for device unique secret
#define ATECC608A_SLOT_SIGNING_PRIVKEY      5  // Private key for signing
#define ATECC608A_SLOT_ENCRYPTION_PRIVKEY   6  // Private key for encryption
#define ATECC608A_SLOT_MASTER_KEY           7  // Master key for various operations
#define ATECC608A_SLOT_PUBLIC_KEY_SIGN      8  // Public key corresponding to SIGNING_PRIVKEY
#define ATECC608A_SLOT_PUBLIC_KEY_ENCRYPT  9  // Public key corresponding to ENCRYPTION_PRIVKEY
#define ATECC608A_SLOT_CERT_DEVICE       10  // Device certificate
#define ATECC608A_SLOT_CERT_CA           11  // CA certificate
#define ATECC608A_SLOT_PRIVATE_DATA_0    12  // User-defined private data slot
#define ATECC608A_SLOT_PRIVATE_DATA_1    13  // User-defined private data slot
#define ATECC608A_SLOT_PRIVATE_DATA_2    14  // User-defined private data slot
#define ATECC608A_SLOT_PRIVATE_DATA_3    15  // User-defined private data slot

// Enum to categorize cryptographic functions for readiness checks.
typedef enum {
    CRYPTO_FUNCTION_ANY = 0,
    CRYPTO_FUNCTION_AEAD,             // Authenticated Encryption with Associated Data
    CRYPTO_FUNCTION_KDF,              // Key Derivation Function
    CRYPTO_FUNCTION_ECDSA_SIGN,       // ECDSA Signing
    CRYPTO_FUNCTION_ECDSA_VERIFY,     // ECDSA Verification
    CRYPTO_FUNCTION_ECC_GENERATE,     // ECC Key Pair Generation
    CRYPTO_FUNCTION_MAX
} CryptoFunctionType;

/**
 * @brief Initializes the ATECC608A device driver.
 * This function should be called once during system startup.
 * @retval true if initialization is successful, false otherwise.
 */
bool atecc608a_init(void);

/**
 * @brief Performs a self-test on the ATECC608A device.
 * This verifies the basic functionality and integrity of the chip.
 * @retval true if the self-test passes, false otherwise.
 */
bool atecc608a_self_test(void);

/**
 * @brief Checks if a specific slot on the ATECC608A is provisioned.
 * Provisioned slots typically contain data, keys, or certificates and may be locked.
 * @param slot_idx The index of the slot to check (0-15).
 * @retval true if the slot is provisioned, false otherwise or on error.
 */
bool atecc608a_is_slot_provisioned(uint8_t slot_idx);

/**
 * @brief Writes data to a specific slot on the ATECC608A.
 * Note: The actual ATECC608A has specific zones and write permissions.
 * This function abstracts those details.
 * @param slot_idx The index of the slot to write to (0-15).
 * @param data Pointer to the data to write.
 * @param len Length of the data to write (typically up to 32 bytes for data slots).
 * @retval true if the write is successful, false otherwise.
 */
bool atecc608a_write_slot(uint8_t slot_idx, const uint8_t *data, size_t len);

/**
 * @brief Reads data from a specific slot on the ATECC608A.
 * @param slot_idx The index of the slot to read from (0-15).
 * @param data Pointer to the buffer to store the read data.
 * @param len Expected length of the data to read.
 * @retval true if the read is successful, false otherwise.
 */
bool atecc608a_read_slot(uint8_t slot_idx, uint8_t *data, size_t len);

/**
 * @brief Binds or locks a slot on the ATECC608A.
 * This operation typically makes the slot's contents immutable or finalizes its configuration.
 * @param slot_idx The index of the slot to bind (0-15).
 * @retval true if the bind operation is successful, false otherwise.
 */
bool atecc608a_bind_slot(uint8_t slot_idx);

/**
 * @brief Computes the SHA256 hash of input data using the ATECC608A hardware.
 * @param data Pointer to the input data.
 * @param len Length of the input data.
 * @param digest Pointer to the buffer where the 32-byte digest will be stored.
 * @retval true if the hash computation is successful, false otherwise.
 */
bool atecc608a_sha256(const uint8_t *data, size_t len, uint8_t *digest);

/**
 * @brief Performs AEAD (Authenticated Encryption with Associated Data) encryption.
 * This function is a placeholder for operations like AES-GCM.
 * @param key_slot The slot index containing the encryption key.
 * @param plaintext Pointer to the data to encrypt.
 * @param plaintext_len Length of the plaintext.
 * @param aad Pointer to the associated data.
 * @param aad_len Length of the associated data.
 * @param nonce Pointer to the nonce (Initialization Vector).
 * @param nonce_len Length of the nonce.
 * @param ciphertext Pointer to the buffer for the encrypted data.
 * @param ciphertext_capacity Maximum capacity of the ciphertext buffer.
 * @param ciphertext_len Pointer to store the actual length of the ciphertext.
 * @param tag Pointer to the buffer for the authentication tag.
 * @retval true if encryption is successful, false otherwise.
 */
bool atecc608a_encrypt_aead(uint8_t key_slot,
                            const uint8_t *plaintext, size_t plaintext_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *nonce, size_t nonce_len,
                            uint8_t *ciphertext, size_t ciphertext_capacity,
                            size_t *ciphertext_len,
                            uint8_t *tag);

/**
 * @brief Performs AEAD (Authenticated Encryption with Associated Data) decryption.
 * This function is a placeholder for operations like AES-GCM. It includes tag verification.
 * @param key_slot The slot index containing the decryption key.
 * @param ciphertext Pointer to the encrypted data.
 * @param ciphertext_len Length of the ciphertext.
 * @param aad Pointer to the associated data.
 * @param aad_len Length of the associated data.
 * @param nonce Pointer to the nonce (Initialization Vector).
 * @param nonce_len Length of the nonce.
 * @param tag Pointer to the authentication tag.
 * @param plaintext Pointer to the buffer for the decrypted data.
 * @param plaintext_capacity Maximum capacity of the plaintext buffer.
 * @param plaintext_len Pointer to store the actual length of the plaintext.
 * @retval true if decryption and verification are successful, false otherwise (including tag mismatch).
 */
bool atecc608a_decrypt_aead(uint8_t key_slot,
                            const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *tag,
                            uint8_t *plaintext, size_t plaintext_capacity,
                            size_t *plaintext_len);

/**
 * @brief Derives key material from a parent key and additional data, outputting to a buffer.
 * This function is a placeholder for Key Derivation Functions (KDFs).
 * @param parent_key_slot The slot index of the parent key.
 * @param data Pointer to additional data for derivation.
 * @param data_len Length of the additional data.
 * @param out_key Pointer to the buffer for the derived key material.
 * @param out_key_len Length of the derived key material to generate.
 * @retval true if key derivation is successful, false otherwise.
 */
bool atecc608a_derive_key_slot_and_output(uint8_t parent_key_slot,
                                          const uint8_t *data, size_t data_len,
                                          uint8_t *out_key, size_t out_key_len);

/**
 * @brief Derives key material from a parent key and additional data, storing it in a target slot.
 * @param parent_key_slot The slot index of the parent key.
 * @param data Pointer to additional data for derivation.
 * @param data_len Length of the additional data.
 * @param derived_key_slot The slot index where the derived key will be stored.
 * @retval true if key derivation and storage are successful, false otherwise.
 */
bool atecc608a_derive_key_slot(uint8_t parent_key_slot,
                               const uint8_t *data, size_t data_len,
                               uint8_t derived_key_slot);

/**
 * @brief Generates an ECC P-256 key pair. The private key is stored in a specified slot,
 * and the corresponding public key is returned.
 * @param key_slot The slot index where the private key will be stored (0-15).
 * @param public_key Pointer to the buffer where the public key will be stored (typically 64 bytes for uncompressed P256).
 * @retval true if key pair generation is successful, false otherwise.
 */
bool atecc608a_generate_ec_keypair(uint8_t key_slot, uint8_t *public_key);

/**
 * @brief Signs a digest using the private key stored in a specific slot via ECDSA.
 * @param key_slot The slot index containing the private key.
 * @param digest Pointer to the 32-byte message digest (e.g., SHA256 output).
 * @param signature Pointer to the buffer where the signature will be stored (typically 64 bytes for P256).
 * @retval true if signing is successful, false otherwise.
 */
bool atecc608a_ecdsa_sign(uint8_t key_slot, const uint8_t *digest, uint8_t *signature);

/**
 * @brief Verifies an ECDSA signature against a public key and digest.
 * This function can be used with externally provided public keys.
 * @param public_key Pointer to the public key (e.g., 64 bytes uncompressed P256).
 * @param digest Pointer to the 32-byte message digest.
 * @param signature Pointer to the signature to verify.
 * @retval true if the signature is valid, false otherwise.
 */
bool atecc608a_ecdsa_verify(const uint8_t *public_key, const uint8_t *digest, const uint8_t *signature);

/**
 * @brief Checks if the ATECC608A device is available and operational.
 * Availability is typically determined by successful initialization and self-test.
 * @retval true if the device is available, false otherwise.
 */
bool atecc608a_is_available(void);

/**
 * @brief Checks if the ATECC608A is ready to perform a specific cryptographic function.
 * Readiness may depend on the device's state, configuration, and presence of necessary keys/data.
 * @param func_type The type of cryptographic function to check readiness for.
 * @retval true if the device is ready for the specified function, false otherwise.
 */
bool atecc608a_is_ready(CryptoFunctionType func_type);

#endif /* ATECC608A_DRIVER_H */
