#ifndef STORAGE_BACKEND_H
#define STORAGE_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define STORAGE_BACKEND_SLOTS 2u
#define STORAGE_BACKEND_MAX_PAYLOAD 256u

typedef struct {
  bool slot_a_valid;
  bool slot_b_valid;
  uint32_t slot_a_generation;
  uint32_t slot_b_generation;
} storage_backend_debug_t;

void storage_backend_init(void);
bool storage_backend_write_atomic(const uint8_t *payload,
                                  size_t payload_len,
                                  uint32_t schema_version);
bool storage_backend_read_latest(uint8_t *out_payload,
                                 size_t out_capacity,
                                 size_t *out_len,
                                 uint32_t *out_schema_version);
bool storage_backend_debug_state(storage_backend_debug_t *out);
bool storage_backend_debug_corrupt_latest(void);
bool storage_backend_wipe(void);

#endif /* STORAGE_BACKEND_H */
