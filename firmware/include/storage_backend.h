#ifndef STORAGE_BACKEND_H
#define STORAGE_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define STORAGE_BACKEND_SLOTS 2u
#define STORAGE_BACKEND_MAX_PAYLOAD 256u

typedef struct {
  bool valid;
  uint32_t generation;
  uint32_t schema_version;
  size_t payload_len;
  uint8_t payload[STORAGE_BACKEND_MAX_PAYLOAD];
} storage_slot_t;

typedef struct {
  bool initialized;
  storage_slot_t slots[STORAGE_BACKEND_SLOTS];
} storage_backend_t;

void storage_backend_init(storage_backend_t *backend);
bool storage_backend_write_atomic(storage_backend_t *backend,
                                  const uint8_t *payload,
                                  size_t payload_len,
                                  uint32_t schema_version);
bool storage_backend_read_latest(const storage_backend_t *backend,
                                 uint8_t *out_payload,
                                 size_t out_capacity,
                                 size_t *out_len,
                                 uint32_t *out_schema_version);
bool storage_backend_corrupt_latest(storage_backend_t *backend);

#endif /* STORAGE_BACKEND_H */
