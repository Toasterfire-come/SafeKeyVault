#ifndef FIDO2_AUTHENTICATOR_H
#define FIDO2_AUTHENTICATOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  bool initialized;
  bool resident_key_supported;
  bool user_verification_supported;
  bool attestation_supported;
} fido2_capabilities_t;

void fido2_authenticator_init(void);
fido2_capabilities_t fido2_authenticator_capabilities(void);

bool fido2_make_credential(const uint8_t *client_data_hash,
                           size_t hash_len,
                           const uint8_t *rp_id,
                           size_t rp_id_len,
                           uint8_t *credential_id,
                           size_t *credential_id_len);

bool fido2_get_assertion(const uint8_t *rp_id,
                         size_t rp_id_len,
                         uint8_t *assertion_sig,
                         size_t *assertion_sig_len);

#endif /* FIDO2_AUTHENTICATOR_H */
