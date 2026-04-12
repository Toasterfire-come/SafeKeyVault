#include "storage_backend.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h" // For secure zeroization

typedef struct {
  bool valid;
  uint32_t generation;
  uint32_t schema_version;
  size_t payload_len;
  uint8_t payload[STORAGE_BACKEND_MAX_PAYLOAD];
} storage_slot_internal_t;

typedef struct {
  bool initialized;
  storage_slot_internal_t slots[STORAGE_BACKEND_SLOTS];
} storage_backend_state_t;

static storage_backend_state_t g_storage_backend;

static bool slot_newer(const storage_slot_internal_t *a,
                       const storage_slot_internal_t *b) {
  if (a == NULL || !a->valid) {
    return false;
  }
  if (b == NULL || !b->valid) {
    return true;
  }
  return a->generation > b->generation;
}

static size_t latest_slot_index(void) {
  if (!g_storage_backend.slots[0].valid && !g_storage_backend.slots[1].valid) {
    return 0u;
  }
  return slot_newer(&g_storage_backend.slots[0], &g_storage_backend.slots[1]) ? 0u : 1u;
}

void storage_backend_init(void) {
  memset(&g_storage_backend, 0, sizeof(g_storage_backend));
  g_storage_backend.initialized = true;
}

bool storage_backend_write_atomic(const uint8_t *payload,
                                  size_t payload_len,
                                  uint32_t schema_version) {
  size_t write_idx;
  uint32_t next_generation = 1u;

  if (!g_storage_backend.initialized || payload == NULL) {
    return false;
  }
  if (payload_len == 0u || payload_len > STORAGE_BACKEND_MAX_PAYLOAD) {
    return false;
  }
  if (schema_version == 0u) {
    return false;
  }

  if (g_storage_backend.slots[0].valid || g_storage_backend.slots[1].valid) {
    size_t latest = latest_slot_index();
    next_generation = g_storage_backend.slots[latest].generation + 1u;
  }

  write_idx = slot_newer(&g_storage_backend.slots[0], &g_storage_backend.slots[1]) ? 1u : 0u;
  memset(&g_storage_backend.slots[write_idx], 0, sizeof(g_storage_backend.slots[write_idx]));
  g_storage_backend.slots[write_idx].valid = true;
  g_storage_backend.slots[write_idx].generation = next_generation;
  g_storage_backend.slots[write_idx].schema_version = schema_version;
  g_storage_backend.slots[write_idx].payload_len = payload_len;
  memcpy(g_storage_backend.slots[write_idx].payload, payload, payload_len);
  return true;
}

bool storage_backend_read_latest(uint8_t *out_payload,
                                 size_t out_capacity,
                                 size_t *out_len,
                                 uint32_t *out_schema_version) {
  size_t idx;
  const storage_slot_internal_t *slot;
  if (!g_storage_backend.initialized || out_payload == NULL ||
      out_len == NULL || out_schema_version == NULL) {
    return false;
  }
  idx = latest_slot_index();
  slot = &g_storage_backend.slots[idx];
  if (!slot->valid || slot->payload_len == 0u || slot->payload_len > out_capacity) {
    return false;
  }
  memcpy(out_payload, slot->payload, slot->payload_len);
  *out_len = slot->payload_len;
  *out_schema_version = slot->schema_version;
  return true;
}

bool storage_backend_debug_state(storage_backend_debug_t *out_debug) {
  if (out_debug == NULL) {
    return false;
  }
  out_debug->slot_a_valid = g_storage_backend.slots[0].valid;
  out_debug->slot_b_valid = g_storage_backend.slots[1].valid;
  out_debug->slot_a_generation = g_storage_backend.slots[0].generation;
  out_debug->slot_b_generation = g_storage_backend.slots[1].generation;
  return true;
}

bool storage_backend_debug_corrupt_latest(void) {
  size_t idx;
  storage_slot_internal_t *slot;
  if (!g_storage_backend.initialized) {
    return false;
  }
  idx = latest_slot_index();
  slot = &g_storage_backend.slots[idx];
  if (!slot->valid || slot->payload_len == 0u) {
    return false;
  }
  slot->payload[0] ^= 0x7Au;
  return true;
}

bool storage_backend_wipe(void) {
  if (!g_storage_backend.initialized) {
    return false;
  }

  // Securely zeroize all internal state before wiping physical storage.
  for (size_t i = 0; i < STORAGE_BACKEND_SLOTS; ++i) {
    security_secure_zero(&g_storage_backend.slots[i], sizeof(storage_slot_internal_t));
  }

  // Now, perform a secure wipe of the physical flash memory used for storage.
  // This involves overwriting multiple times if required for data remanence protection.
  // Assuming a low-level function like storage_backend_physical_erase_slot exists.
  // Overwriting with 0xFF then 0x00 is a common practice for secure erase.
  // This needs to be implemented at the hardware abstraction layer.
  // For this mock implementation, we iterate through the 'slots' in memory
  // and simulate a secure erase. In a real system, these 'slots' map to
  // physical flash sectors.
  uint8_t buffer[STORAGE_BACKEND_MAX_PAYLOAD]; // Temporary buffer for secure overwrite

  for (size_t i = 0; i < STORAGE_BACKEND_SLOTS; ++i) {
      // Step 1: Overwrite with 0xFF
      memset(buffer, 0xFF, sizeof(buffer));
      // In a real system, this buffer would be written to the flash sector.
      // E.g., storage_backend_write_physical_sector(slot_address[i], buffer, sizeof(buffer));

      // Step 2: Overwrite with 0x00 (zeroize)
      memset(buffer, 0x00, sizeof(buffer));
      // E.g., storage_backend_write_physical_sector(slot_address[i], buffer, sizeof(buffer));

      // After physical erase, mark internal slot as invalid and zeroize its contents
      memset(&g_storage_backend.slots[i], 0, sizeof(storage_slot_internal_t));
      g_storage_backend.slots[i].valid = false;
  }
  security_secure_zero(buffer, sizeof(buffer)); // Zeroize temporary buffer

  // Finally, fully clear the state back to uninitialized state data.
  memset(&g_storage_backend, 0, sizeof(g_storage_backend));
  g_storage_backend.initialized = true; // Re-initialize only the control flags

  return true;
}
