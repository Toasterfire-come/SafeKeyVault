#include "security_utils.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

bool sec_consttime_memeq(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t diff = 0u;
  if (a == NULL || b == NULL) {
    return false;
  }
  for (size_t i = 0; i < len; ++i) {
    diff |= (uint8_t)(a[i] ^ b[i]);
  }
  return diff == 0u;
}

uint32_t security_fnv1a32(const uint8_t *data, size_t len) {
  uint32_t h = 2166136261u;
  if (data == NULL) {
    return h;
  }
  for (size_t i = 0; i < len; ++i) {
    h ^= data[i];
    h *= 16777619u;
  }
  return h;
}

void security_secure_zero(void *ptr, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  if (p == NULL) {
    return;
  }
  for (size_t i = 0; i < len; ++i) {
    p[i] = 0u;
  }
}
