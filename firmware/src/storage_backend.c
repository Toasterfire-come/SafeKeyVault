#include "storage_backend.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "security_utils.h"

typedef struct {
  bool initialized;
  bool has_data;
  uint32_t generation;
  uint32_t rollback_guard;
  storage_record_t record;
} storage_state_t;

static storage_state_t g_storage;

static uint32_t storage_crc32(const storage_record_t *record) {
  if (record == NULL) {
    return 0u;
  }
  return security_fnv1a32((const uint8_t *)record->payload, record->payload_len);
}

void storage_backend_init(void) {
  memset(&g_storage, 0, sizeof(g_storage));
  g_storage.initialized = true;
}

bool storage_backend_write_atomic(const storage_record_t *record) {
  if (!g_storage.initialized || record == NULL) {
    return false;
  }
  if (record->payload_len == 0u || record->payload_len > STORAGE_BACKEND_MAX_PAYLOAD) {
    return false;
  }
  if (record->version == 0u) {
    return false;
  }
  if (record->rollback_counter < g_storage.rollback_guard) {
    return false;
  }
  if (record->generation < g_storage.generation) {
    return false;
  }
  if (storage_crc32(record) != record->crc32) {
    return false;
  }
  g_storage.record = *record;
  g_storage.generation = record->generation;
  g_storage.rollback_guard = record->rollback_counter;
  g_storage.has_data = true;
  return true;
}

bool storage_backend_read_latest(storage_record_t *out_record) {
  if (!g_storage.initialized || !g_storage.has_data || out_record == NULL) {
    return false;
  }
  if (storage_crc32(&g_storage.record) != g_storage.record.crc32) {
    return false;
  }
  *out_record = g_storage.record;
  return true;
}

bool storage_backend_wipe(void) {
  if (!g_storage.initialized) {
    return false;
  }
  security_secure_zero(&g_storage, sizeof(g_storage));
  g_storage.initialized = true;
  return true;
}

bool storage_backend_debug_corrupt(void) {
  if (!g_storage.initialized || !g_storage.has_data || g_storage.record.payload_len == 0u) {
    return false;
  }
  g_storage.record.payload[0] ^= 0x7Au;
  return true;
}
