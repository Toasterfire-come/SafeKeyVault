#ifndef ATECC608A_DRIVER_H
#define ATECC608A_DRIVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Initialize the ATECC608A driver. This should be called once at startup.
// Returns true on success, false otherwise.
bool atecc608a_init(void);

// Perform a self-test of the ATECC608A.
// Returns true if the self-test passes, false otherwise.
bool atecc608a_self_test(void);

// Check if a specific slot in the ATECC608A is provisioned (i.e., contains data or a key).
// slot_idx: The index of the slot to check (0-15).
// Returns true if the slot is provisioned, false otherwise or on error.
bool atecc608a_is_slot_provisioned(uint8_t slot_idx);

// Write data to a specific slot in the ATECC608A.
// This function assumes the slot is configured for writing.
// slot_idx: The index of the slot to write to (0-15).
// data: Pointer to the data to write.
// len: The length of the data to write. This must match the slot's configuration.
// Returns true on success, false otherwise.
bool atecc608a_write_slot(uint8_t slot_idx, const uint8_t *data, size_t len);

// Read data from a specific slot in the ATECC608A.
// slot_idx: The index of the slot to read from (0-15).
// data: Pointer to the buffer where the read data will be stored.
// len: The expected length of the data to read. This must match the slot's configuration.
// Returns true on success, false otherwise.
bool atecc608a_read_slot(uint8_t slot_idx, uint8_t *data, size_t len);

// "Bind" a slot. This might involve locking a slot or performing a secure operation
// that permanently links its content or configuration. The exact behavior
// is highly dependent on the ATECC configuration and intended use case.
// For now, this can be a placeholder or a simplified operation.
// slot_idx: The index of the slot to bind.
// Returns true on success, false otherwise.
bool atecc608a_bind_slot(uint8_t slot_idx);

#endif // ATECC608A_DRIVER_H
