#ifndef TOTP_H
#define TOTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TOTP_MAX_ACCOUNTS 10
#define TOTP_SECRET_MAX_LEN 32
#define TOTP_LABEL_MAX_LEN 64
#define TOTP_CODE_MAX_LEN 9 // Max 8 digits + null terminator

typedef struct {
  uint8_t secret[TOTP_SECRET_MAX_LEN];
  size_t secret_len;
  char label[TOTP_LABEL_MAX_LEN];
  uint8_t digits; // Typically 6 or 8
  bool initialized; // Added to track if the store has been initialized
} totp_account_t;

typedef struct {
  totp_account_t accounts[TOTP_MAX_ACCOUNTS];
  size_t count;
  bool initialized; // Added to track if the store has been initialized
} totp_store_t;

/**
 * @brief Adds a new TOTP account to the store.
 *
 * @param store The TOTP store to add the account to.
 * @param label The label for the account (e.g., "example.com").
 * @param base32_secret The Base32 encoded secret key.
 * @param digits The number of digits for the TOTP code (6 or 8).
 * @return true if the account was added successfully, false otherwise.
 */
bool totp_add_account(totp_store_t *store, const char *label, const char *base32_secret, uint8_t digits);

/**
 * @brief Deletes a TOTP account from the store at the given index.
 *
 * @param store The TOTP store to delete the account from.
 * @param index The index of the account to delete.
 * @return true if the account was deleted successfully, false otherwise.
 */
bool totp_delete_account(totp_store_t *store, size_t index);

/**
 * @brief Generates the current TOTP code for a given account.
 *
 * @param account The TOTP account to generate the code for.
 * @param unix_time The current Unix timestamp.
 * @param out_code Buffer to store the generated code.
 * @param out_len The maximum length of the output buffer.
 * @return true if the code was generated successfully, false otherwise.
 */
bool totp_get_code(const totp_account_t *account, uint64_t unix_time, char *out_code, size_t out_len);

/**
 * @brief Types the current TOTP code via USB HID.
 *
 * @param account The TOTP account to generate the code for.
 * @param unix_time The current Unix timestamp.
 * @return true if the code was typed successfully, false otherwise.
 */
bool totp_type_code(const totp_account_t *account, uint64_t unix_time);

/**
 * @brief Looks up an account by index, generates its TOTP code, and types it via USB HID.
 *
 * @param store The TOTP store containing the accounts.
 * @param index The index of the account to copy the code from.
 * @param unix_time The current Unix timestamp.
 * @return true if the code was copied successfully, false otherwise.
 */
bool totp_copy_code(const totp_store_t *store, size_t index, uint64_t unix_time);

/**
 * @brief Saves the current TOTP store to persistent storage.
 *
 * @param store The TOTP store to save.
 * @return true if the store was saved successfully, false otherwise.
 */
bool totp_save(const totp_store_t *store);

/**
 * @brief Loads the TOTP store from persistent storage.
 *
 * @param store The TOTP store to load into.
 * @return true if the store was loaded successfully, false otherwise.
 */
bool totp_load(totp_store_t *store);

#endif /* TOTP_H */
