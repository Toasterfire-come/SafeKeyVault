#ifndef FIDO2_AUTHENTICATOR_H
#define FIDO2_AUTHENTICATOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint8_t id[32];
  size_t id_len;
  uint8_t public_key[64];
  size_t public_key_len;
} fido2_credential_t;

typedef struct {
  uint8_t signature[64];
  size_t signature_len;
  uint8_t user_handle[32];
  size_t user_handle_len;
  uint32_t sign_count;
} fido2_assertion_t;

void fido2_authenticator_init(void);
bool fido2_create_credential(const char *rp_id,
                             const char *user_name,
                             const uint8_t *challenge,
                             size_t challenge_len,
                             fido2_credential_t *out_credential);
bool fido2_get_assertion(const char *rp_id,
                         const uint8_t *challenge,
                         size_t challenge_len,
                         fido2_assertion_t *out_assertion);

#endif /* FIDO2_AUTHENTICATOR_H */
