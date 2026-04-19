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
// This