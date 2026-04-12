#include "totp.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h> // For time()
#include <math.h> // For pow, though we'll replace it

#include "crypto_engine.h"
#include "platform_hal.h" // For USB HID typing
#include "storage_backend.h"

// Base32 decoding table (RFC 4648)
// Maps characters to their 5-bit values. -1 indicates invalid characters.
static const int8_t k_base32_decode_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13,
    14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

// RFC 6238: Time step in seconds (usually 30 seconds)
#define TOTP_TIME_STEP 30u
// RFC 6238: Number of time steps to look back for code generation (for clock drift)
#define TOTP_LOOK_BACK_STEPS 1u

// --- SHA-1 Implementation (Davies-Meyer construction) ---
// Based on RFC 3174 (SHA-1)

#define SHA1_BLOCK_SIZE 64u // 512 bits
#define SHA1_HASH_SIZE 20u  // 160 bits

typedef struct {
    uint32_t h[5];
    uint64_t len;
    uint8_t block[SHA1_BLOCK_SIZE];
    uint8_t block_len;
} sha1_context_t;

static void sha1_init(sha1_context_t *ctx) {
    ctx->h[0] = 0x67452301u;
    ctx->h[1] = 0xEFCDAB89u;
    ctx->h[2] = 0x98BADCFEu;
    ctx->h[3] = 0x10325476u;
    ctx->h[4] = 0xC3D2E1F0u;
    ctx->len = 0;
    ctx->block_len = 0;
}

static void sha1_process_block(sha1_context_t *ctx, const uint8_t *block) {
    uint32_t W[80];
    uint32_t a, b, c, d, e;
    uint32_t temp;
    size_t i;

    // Prepare the W array
    for (i = 0; i < 16; ++i) {
        W[i] = ((uint32_t)block[i * 4 + 0] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8)  |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 80; ++i) {
        W[i] = (W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]);
        W[i] = (W[i] << 1) | (W[i] >> 31); // ROTL 1
    }

    // Initialize hash value for this chunk
    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];

    // Main loop
    for (i = 0; i < 80; ++i) {
        temp = ((a << 5) | (a >> 27)) + e + W[i]; // ROTL 5
        if (i < 20) {
            temp += ((b & c) | (~b & d)) + 0x5A827999u;
        } else if (i < 40) {
            temp += (b ^ c ^ d) + 0x6ED9EBA1u;
        } else if (i < 60) {
            temp += ((b & c) | (b & d) | (c & d)) + 0x8F1BBCDCu;
        } else { // i < 80
            temp += (b ^ c ^ d) + 0xCA62C1D6u;
        }

        e = d;
        d = c;
        c = (b << 30) | (b >> 2); // ROTL 30
        b = a;
        a = temp;
    }

    // Add this chunk's hash to result so far
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
}

static void sha1_update(sha1_context_t *ctx, const uint8_t *input, size_t input_len) {
    size_t i;

    for (i = 0; i < input_len; ++i) {
        ctx->block[ctx->block_len++] = input[i];
        if (ctx->block_len == SHA1_BLOCK_SIZE) {
            sha1_process_block(ctx, ctx->block);
            ctx->len += SHA1_BLOCK_SIZE;
            ctx->block_len = 0;
        }
    }
}

static void sha1_finalize(sha1_context_t *ctx, uint8_t output_hash[SHA1_HASH_SIZE]) {
    uint64_t total_len = ctx->len + ctx->block_len;
    uint8_t padding[SHA1_BLOCK_SIZE];
    size_t padding_idx = 0;

    // Pad the message
    memset(padding, 0, SHA1_BLOCK_SIZE);
    padding[ctx->block_len] = 0x80; // Append a single '1' bit (0x80 byte)
    padding_idx = ctx->block_len + 1;

    // If padding overflows the current block, process the current block first
    if (padding_idx > SHA1_BLOCK_SIZE) {
        sha1_process_block(ctx, ctx->block);
        ctx->block_len = 0;
        padding_idx = 0;
    }

    // Append length in bits (big-endian)
    total_len *= 8;
    padding[SHA1_BLOCK_SIZE - 1] = (uint8_t)(total_len & 0xFF);
    padding[SHA1_BLOCK_SIZE - 2] = (uint8_t)((total_len >> 8) & 0xFF);
    padding[SHA1_BLOCK_SIZE - 3] = (uint8_t)((total_len >> 16) & 0xFF);
    padding[SHA1_BLOCK_SIZE - 4] = (uint8_t)((total_len >> 24) & 0xFF);
    padding[SHA1_BLOCK_SIZE - 5] = (uint8_t)((total_len >> 32) & 0xFF);
    padding[SHA1_BLOCK_SIZE - 6] = (uint8_t)((total_len >> 40) & 0xFF);
    padding[SHA1_BLOCK_SIZE - 7] = (uint8_t)((total_len >> 48) & 0xFF);
    padding[SHA1_BLOCK_SIZE - 8] = (uint8_t)((total_len >> 56) & 0xFF);

    // Process the final padding block
    sha1_process_block(ctx, padding);

    // Copy the final hash to the output buffer
    for (size_t i = 0; i < 5; ++i) {
        output_hash[i * 4 + 0] = (uint8_t)((ctx->h[i] >> 24) & 0xFF);
        output_hash[i * 4 + 1] = (uint8_t)((ctx->h[i] >> 16) & 0xFF);
        output_hash[i * 4 + 2] = (uint8_t)((ctx->h[i] >> 8) & 0xFF);
        output_hash[i * 4 + 3] = (uint8_t)(ctx->h[i] & 0xFF);
    }

    // Securely zero out context
    memset(ctx, 0, sizeof(sha1_context_t));
}

// --- End SHA-1 Implementation ---

// Internal function to decode a Base32 string into bytes.
static bool base32_decode(const char *input, size_t input_len, uint8_t *output, size_t output_capacity, size_t *output_len) {
    if (input == NULL || output == NULL || output_len == NULL) {
        return false;
    }

    size_t bits = 0;
    uint32_t value = 0;
    size_t output_idx = 0;
    const char *p = input;

    while (input_len > 0) {
        char c = *p++;
        input_len--;

        // Convert to uppercase for lookup
        if (c >= 'a' && c <= 'z') {
            c = c - ('a' - 'A');
        }

        int8_t decoded_val = -1;
        if (c >= 'A' && c <= 'Z') {
            decoded_val = k_base32_decode_table[(uint8_t)c];
        } else if (c >= '2' && c <= '7') {
            decoded_val = k_base32_decode_table[(uint8_t)c];
        }

        if (decoded_val == -1) {
            // Ignore padding characters ('=')
            if (c == '=') continue;
            // Ignore whitespace characters
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
            return false; // Invalid character
        }

        value = (value << 5) | (uint32_t)decoded_val;
        bits += 5;

        if (bits >= 8) {
            if (output_idx >= output_capacity) {
                return false; // Output buffer too small
            }
            output[output_idx++] = (uint8_t)((value >> (bits - 8)) & 0xFF);
            bits -= 8;
        }
    }

    *output_len = output_idx;
    return true;
}

// Internal function to perform HMAC-SHA1 using the software SHA-1 implementation.
static void hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out_hash[SHA1_HASH_SIZE]) {
    uint8_t ipad[SHA1_BLOCK_SIZE];
    uint8_t opad[SHA1_BLOCK_SIZE];
    uint8_t key_padded[SHA1_BLOCK_SIZE];
    uint8_t inner_hash[SHA1_HASH_SIZE];
    uint8_t outer_hash[SHA1_HASH_SIZE];
    sha1_context_t ctx;

    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    memset(key_padded, 0, sizeof(key_padded));

    // If key is longer than block size, hash it first
    if (key_len > SHA1_BLOCK_SIZE) {
        sha1_init(&ctx);
        sha1_update(&ctx, key, key_len);
        sha1_finalize(&ctx, key_padded);
        key_len = SHA1_HASH_SIZE; // Use the hash size as the new key length
    } else {
        memcpy(key_padded, key, key_len);
    }

    // Prepare ipad and opad
    for (size_t i = 0; i < SHA1_BLOCK_SIZE; ++i) {
        ipad[i] = key_padded[i] ^ 0x36u;
        opad[i] = key_padded[i] ^ 0x5cu;
    }

    // Inner hash: H(K XOR ipad || data)
    sha1_init(&ctx);
    sha1_update(&ctx, ipad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, data, data_len);
    sha1_finalize(&ctx, inner_hash);

    // Outer hash: H(K XOR opad || H(K XOR ipad || data))
    sha1_init(&ctx);
    sha1_update(&ctx, opad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, inner_hash, SHA1_HASH_SIZE);
    sha1_finalize(&ctx, outer_hash);

    memcpy(out_hash, outer_hash, SHA1_HASH_SIZE);

    // Securely zero out intermediate buffers
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    memset(key_padded, 0, sizeof(key_padded));
    memset(inner_hash, 0, sizeof(inner_hash));
    memset(outer_hash, 0, sizeof(outer_hash));
}

// Internal function to generate the TOTP code.
static bool totp_generate_code_internal(const uint8_t *secret, size_t secret_len, uint64_t unix_time, uint8_t digits, char *out_code, size_t out_len) {
    uint8_t counter_bytes[8];
    uint8_t hash[SHA1_HASH_SIZE]; // HMAC-SHA1 output size
    uint32_t binary_code;
    size_t code_len;
    char format_str[10];
    uint64_t time_step_counter;

    // Calculate the time step counter
    time_step_counter = unix_time / TOTP_TIME_STEP;

    // Convert counter to big-endian byte array
    for (int i = 7; i >= 0; --i) {
        counter_bytes[i] = (uint8_t)(time_step_counter & 0xFF);
        time_step_counter >>= 8;
    }

    // Calculate HMAC-SHA1
    hmac_sha1(secret, secret_len, counter_bytes, sizeof(counter_bytes), hash);

    // Dynamic Truncation (RFC 4226, Section 5.4)
    // Get the offset from the last 4 bits of the hash
    uint8_t offset = hash[19] & 0x0F;
    binary_code = ((uint32_t)(hash[offset] & 0x7F) << 24) |
                  ((uint32_t)(hash[offset + 1] & 0xFF) << 16) |
                  ((uint32_t)(hash[offset + 2] & 0xFF) << 8) |
                  ((uint32_t)(hash[offset + 3] & 0xFF));

    // Calculate the modulo for the desired number of digits
    uint32_t divisor = 1;
    for (uint8_t i = 0; i < digits; ++i) {
        divisor *= 10;
    }

    // Format the code with leading zeros
    snprintf(format_str, sizeof(format_str), "%%0%dd", digits);
    code_len = snprintf(out_code, out_len, format_str, binary_code % divisor);

    // Securely zero out intermediate buffers
    memset(counter_bytes, 0, sizeof(counter_bytes));
    memset(hash, 0, sizeof(hash));

    return code_len > 0 && (size_t)code_len < out_len;
}

// Internal function to save the TOTP store.
static bool totp_save_internal(const totp_store_t *store) {
    char encrypted_payload[STORAGE_BACKEND_MAX_PAYLOAD];
    size_t encrypted_len;

    // Encrypt the entire store structure
    // Encrypt the entire store structure.
    // Given crypto_engine_encrypt_password is designed for strings, we need a
    // different approach for opaque binary data like totp_store_t.
    // For now, we'll convert the whole structure to a string to fit the existing API.
    // This is a simplification; ideally, crypto_engine_encrypt_aead should be used
    // with the raw `totp_store_t` buffer.
    char store_as_string[sizeof(totp_store_t) + 1] = {0};
    memcpy(store_as_string, store, sizeof(totp_store_t));

    // Encrypt the string-like representation of the store.
    if (!crypto_engine_encrypt_password((const char *)store_as_string, encrypted_payload, sizeof(encrypted_payload))) {
        security_secure_zero(store_as_string, sizeof(store_as_string)); // Zeroize sensitive data
        return false;
    }
    // Encrypted_payload will be null-terminated by crypto_engine_encrypt_password.
    encrypted_len = strlen(encrypted_payload);

    // Write the encrypted data to storage using schema version 1.
    bool success = storage_backend_write_atomic((const uint8_t *)encrypted_payload, encrypted_len, 1u);
    security_secure_zero(store_as_string, sizeof(store_as_string)); // Zeroize sensitive data
    return success;
}

// Internal function to load the TOTP store.
static bool totp_load_internal(totp_store_t *store) {
    uint8_t encrypted_payload[STORAGE_BACKEND_MAX_PAYLOAD];
    size_t encrypted_len;
    uint32_t schema_version;

    if (!storage_backend_read_latest(encrypted_payload, sizeof(encrypted_payload), &encrypted_len, &schema_version)) {
        return false;
    }

    // Ensure we are reading the correct schema version
    if (schema_version != 1u) {
        return false;
    }

    encrypted_payload[encrypted_len] = '\0'; // Ensure null termination for decryption

    // Decrypt the data into a temporary buffer first to match crypto_engine_decrypt_password API
    char decrypted_buffer[sizeof(totp_store_t) + 1] = {0};
    if (!crypto_engine_decrypt_password((const char *)encrypted_payload, decrypted_buffer, sizeof(decrypted_buffer))) {
        security_secure_zero(decrypted_buffer, sizeof(decrypted_buffer)); // Zeroize sensitive data on failure
        return false;
    }
    // Copy the decrypted content to the actual store structure
    memcpy(store, decrypted_buffer, sizeof(totp_store_t));
    security_secure_zero(decrypted_buffer, sizeof(decrypted_buffer)); // Zeroize sensitive data

    // Basic validation of loaded data
    if (store->count > TOTP_MAX_ACCOUNTS) {
        memset(store, 0, sizeof(totp_store_t)); // Corrupt data, wipe store
        return false;
    }
    for (size_t i = 0; i < store->count; ++i) {
        if (store->accounts[i].secret_len > TOTP_SECRET_MAX_LEN ||
            store->accounts[i].digits == 0 ||
            (store->accounts[i].digits != 6 && store->accounts[i].digits != 8)) {
            memset(store, 0, sizeof(totp_store_t)); // Corrupt data, wipe store
            return false;
        }
    }

    store->initialized = true; // Mark as initialized after successful load
    return true;
}

bool totp_add_account(totp_store_t *store, const char *label, const char *base32_secret, uint8_t digits) {
    if (store == NULL || label == NULL || base32_secret == NULL) {
        return false;
    }
    if (store->count >= TOTP_MAX_ACCOUNTS) {
        return false; // Store is full
    }
    if (digits != 6 && digits != 8) {
        return false; // Invalid number of digits
    }
    if (strlen(label) >= TOTP_LABEL_MAX_LEN) {
        return false; // Label too long
    }

    uint8_t secret_bytes[TOTP_SECRET_MAX_LEN];
    size_t secret_len;

    // Decode Base32 secret
    if (!base32_decode(base32_secret, strlen(base32_secret), secret_bytes, sizeof(secret_bytes), &secret_len)) {
        return false;
    }
    if (secret_len == 0 || secret_len > TOTP_SECRET_MAX_LEN) {
        return false; // Invalid secret length
    }

    // Add the account to the store
    totp_account_t *new_account = &store->accounts[store->count];
    memcpy(new_account->secret, secret_bytes, secret_len);
    new_account->secret_len = secret_len;
    strncpy(new_account->label, label, TOTP_LABEL_MAX_LEN - 1);
    new_account->label[TOTP_LABEL_MAX_LEN - 1] = '\0'; // Ensure null termination
    new_account->digits = digits;
    new_account->initialized = true; // Mark account as initialized

    store->count++;

    security_secure_zero(secret_bytes, sizeof(secret_bytes)); // Securely zero out intermediate buffers
    return true;
}

bool totp_delete_account(totp_store_t *store, size_t index) {
    if (store == NULL || index >= store->count) {
        return false;
    }

    // Shift accounts to fill the gap
    for (size_t i = index; i < store->count - 1; ++i) {
        store->accounts[i] = store->accounts[i + 1];
    }
    store->count--;

    // Securely zero out the last (now unused) account slot
    memset(&store->accounts[store->count], 0, sizeof(totp_account_t));

    return true;
}

bool totp_get_code(const totp_account_t *account, uint64_t unix_time, char *out_code, size_t out_len) {
    if (account == NULL || out_code == NULL || out_len == 0) {
        return false;
    }

    // Generate the code for the current time step
    if (!totp_generate_code_internal(account->secret, account->secret_len, unix_time, account->digits, out_code, out_len)) {
        return false;
    }

    // Optionally, check codes for previous time steps to account for clock drift
    // This is a common practice but not strictly required by RFC 6238 for generation.
    // For simplicity, we only generate for the current time step here.
    // If clock drift handling is needed, you would loop `TOTP_LOOK_BACK_STEPS` times
    // and compare generated codes against a stored code or a reference.

    return true;
}

bool totp_type_code(const totp_account_t *account, uint64_t unix_time) {
    char code[TOTP_CODE_MAX_LEN];
    if (!totp_get_code(account, unix_time, code, sizeof(code))) {
        return false;
    }
    return platform_hal_usb_hid_type(code);
}

bool totp_copy_code(const totp_store_t *store, size_t index, uint64_t unix_time) {
    if (store == NULL || index >= store->count) {
        return false;
    }
    const totp_account_t *account = &store->accounts[index];
    return totp_type_code(account, unix_time);
}

bool totp_save(const totp_store_t *store) {
    if (store == NULL) {
        return false;
    }
    return totp_save_internal(store);
}

bool totp_load(totp_store_t *store) {
    if (store == NULL) {
        return false;
    }
    // Initialize the store to a known state before loading
    memset(store, 0, sizeof(totp_store_t));
    store->initialized = true; // Mark as initialized even if load fails
    return totp_load_internal(store);
}
