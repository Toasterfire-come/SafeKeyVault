#include "password_store.h"

#include <string.h>

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
