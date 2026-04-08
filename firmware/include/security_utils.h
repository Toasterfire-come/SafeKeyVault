#ifndef SECURITY_UTILS_H
#define SECURITY_UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* Constant-time equality check for sensitive buffers. */
bool sec_consttime_memeq(const uint8_t *a, const uint8_t *b, size_t len);

/* Non-cryptographic utility hash for checksums/test scaffolding. */
uint32_t security_fnv1a32(const uint8_t *data, size_t len);

/* Best-effort secure memory zeroization. */
void security_secure_zero(void *ptr, size_t len);

#endif /* SECURITY_UTILS_H */
