#ifndef PASSWORD_STORE_H
#define PASSWORD_STORE_H

#include "firmware_types.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
    bool valid;
    uint32_t id;
    char origin[96];   // scheme://host[:port]
    char app[48];      // optional app/context tag
    char username[64];
    char password_ciphertext[192];
    uint8_t password_fingerprint[16]; // salted hash fragment for reuse detection
    uint32_t created_at;
    uint32_t updated_at;
} credential_t;

typedef struct {
    credential_t credentials[32];
    size_t count;
} vault_t;

void password_store_init(vault_t *vault);
bool password_store_find_by_origin(const vault_t *vault, const char *origin, credential_t *out);
bool password_store_find_by_origin_indexed(const vault_t *vault,
                                           const char *origin,
                                           size_t start_index,
                                           credential_t *out,
                                           size_t *out_index);
bool password_store_get_by_index(const vault_t *vault, size_t index, credential_t *out);
bool password_store_upsert(vault_t *vault, const credential_t *record);
bool password_store_fingerprint_exists(const vault_t *vault, const uint8_t fp[16]);
bool password_store_exists(const vault_t *vault, const char *origin, const char *username);
uint32_t password_store_next_id(const vault_t *vault);
void password_store_make_fingerprint(const char *password, uint8_t out_fp[16]);
bool password_store_encrypt_password(const char *plaintext, char *out_ciphertext, size_t out_len);
bool password_store_decrypt_password(const char *ciphertext, char *out_plaintext, size_t out_len);
void password_store_secure_wipe(vault_t *vault);

#endif // PASSWORD_STORE_H
