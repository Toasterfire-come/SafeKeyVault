#include "password_store.h"

#include <string.h>
#include <stdint.h>

#include "crypto_engine.h"

void password_store_init(vault_t *vault) {
  if (vault == NULL) {
    return;
  }
  memset(vault, 0, sizeof(*vault));
}

bool password_store_find_by_origin(const vault_t *vault, const char *origin, credential_t *out) {
  if (vault == NULL || origin == NULL || out == NULL) {
    return false;
  }

  for (size_t i = 0; i < vault->count; ++i) {
    const credential_t *entry = &vault->credentials[i];
    if (!entry->valid) {
      continue;
    }
    if (strncmp(entry->origin, origin, sizeof(entry->origin)) == 0) {
      *out = *entry;
      return true;
    }
  }
  return false;
}

bool password_store_get_by_index(const vault_t *vault, size_t index, credential_t *out) {
  if (vault == NULL || out == NULL || index >= vault->count) {
    return false;
  }
  if (!vault->credentials[index].valid) {
    return false;
  }
  *out = vault->credentials[index];
  return true;
}

bool password_store_upsert(vault_t *vault, const credential_t *record) {
  if (vault == NULL || record == NULL || !record->valid) {
    return false;
  }

  for (size_t i = 0; i < vault->count; ++i) {
    credential_t *entry = &vault->credentials[i];
    if (!entry->valid) {
      continue;
    }
    if (strncmp(entry->origin, record->origin, sizeof(entry->origin)) == 0 &&
        strncmp(entry->username, record->username, sizeof(entry->username)) == 0) {
      *entry = *record;
      return true;
    }
  }

  if (vault->count >= (sizeof(vault->credentials) / sizeof(vault->credentials[0]))) {
    return false;
  }
  vault->credentials[vault->count++] = *record;
  return true;
}

bool password_store_fingerprint_exists(const vault_t *vault, const uint8_t fp[16]) {
  if (vault == NULL || fp == NULL) {
    return false;
  }
  for (size_t i = 0; i < vault->count; ++i) {
    const credential_t *entry = &vault->credentials[i];
    if (!entry->valid) {
      continue;
    }
    if (memcmp(entry->password_fingerprint, fp, 16) == 0) {
      return true;
    }
  }
  return false;
}

bool password_store_exists(const vault_t *vault, const char *origin, const char *username) {
  if (vault == NULL || origin == NULL || username == NULL) {
    return false;
  }
  for (size_t i = 0; i < vault->count; ++i) {
    const credential_t *entry = &vault->credentials[i];
    if (!entry->valid) {
      continue;
    }
    if (strncmp(entry->origin, origin, sizeof(entry->origin)) == 0 &&
        strncmp(entry->username, username, sizeof(entry->username)) == 0) {
      return true;
    }
  }
  return false;
}

uint32_t password_store_next_id(const vault_t *vault) {
  uint32_t max_id = 0u;
  if (vault == NULL) {
    return 1u;
  }
  for (size_t i = 0; i < vault->count; ++i) {
    if (vault->credentials[i].valid && vault->credentials[i].id > max_id) {
      max_id = vault->credentials[i].id;
    }
  }
  return max_id + 1u;
}

bool password_store_find_by_origin_indexed(const vault_t *vault,
                                           const char *origin,
                                           size_t start_index,
                                           credential_t *out,
                                           size_t *out_index) {
  size_t i;
  if (vault == NULL || origin == NULL || out == NULL) {
    return false;
  }
  if (vault->count == 0u) {
    return false;
  }
  if (start_index >= vault->count) {
    start_index = 0u;
  }
  for (i = 0u; i < vault->count; ++i) {
    size_t idx = (start_index + i) % vault->count;
    const credential_t *entry = &vault->credentials[idx];
    if (!entry->valid) {
      continue;
    }
    if (strncmp(entry->origin, origin, sizeof(entry->origin)) == 0) {
      *out = *entry;
      if (out_index != NULL) {
        *out_index = idx;
      }
      return true;
    }
  }
  return false;
}

void password_store_make_fingerprint(const char *password, uint8_t out_fp[16]) {
  uint8_t buffer[32];
  if (out_fp == NULL) {
    return;
  }
  memset(buffer, 0, sizeof(buffer));
  if (password != NULL) {
    size_t n = strlen(password);
    if (n > sizeof(buffer)) {
      n = sizeof(buffer);
    }
    (void)memcpy(buffer, password, n);
  }
  crypto_engine_hash16(buffer, sizeof(buffer), out_fp);
}

bool password_store_encrypt_password(const char *plaintext, char *out_ciphertext, size_t out_len) {
  return crypto_engine_encrypt_password(plaintext, out_ciphertext, out_len);
}

bool password_store_decrypt_password(const char *ciphertext, char *out_plaintext, size_t out_len) {
  return crypto_engine_decrypt_password(ciphertext, out_plaintext, out_len);
}

void password_store_secure_wipe(vault_t *vault) {
  if (vault == NULL) {
    return;
  }
  memset(vault, 0, sizeof(*vault));
}
