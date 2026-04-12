#ifndef FLASH_STORAGE_H
#define FLASH_STORAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Writes an encrypted private key to flash.
 *
 * This function is responsible for securely storing the encrypted private key.
 * The encryption mechanism is assumed to be handled by the crypto engine
 * using the master key.
 *
 * @param key Pointer to the encrypted private key data.
 * @param len Length of the private key data.
 * @return true if the key was written successfully, false otherwise.
 */
bool flash_write_encrypted_private_key(const uint8_t *key, size_t len);

/**
 * @brief Reads an encrypted private key from flash.
 *
 * This function retrieves the encrypted private key from flash storage.
 * The decryption mechanism is assumed to be handled by the crypto engine
 * using the master key.
 *
 * @param key Buffer to store the decrypted private key data.
 * @param len Maximum length of the buffer.
 * @return true if the key was read successfully, false otherwise.
 */
bool flash_read_encrypted_private_key(uint8_t *key, size_t len);

// Add other flash storage related function declarations here if needed.

#endif /* FLASH_STORAGE_H */
