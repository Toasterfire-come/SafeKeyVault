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
bool password_store_upsert(vault_t *vault, const credential_t *record);
bool password_store_fingerprint_exists(const vault_t *vault, const uint8_t fp[16]);

#endif // PASSWORD_STORE_H
