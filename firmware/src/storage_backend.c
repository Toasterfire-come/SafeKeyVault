#include "storage_backend.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h" // For secure zeroization

// Define flash sector addresses and sizes. These are placeholders and must be
// configured based on the specific STM32U5xx microcontroller and memory map.
// Example: Assuming two sectors of 16KB each for dual-bank storage.
// These values should be derived from the device's datasheet or HAL configuration.
#define FLASH_SECTOR_SIZE_BYTES (16 * 1024) // Example sector size
#define FLASH_SECTOR_A_ADDR     (FLASH_BASE + 0x00000) // Example address for Sector A
#define FLASH_SECTOR_B_ADDR     (FLASH_BASE + FLASH_SECTOR_SIZE_BYTES) // Example address for Sector B

// Ensure that the total payload size does not exceed the sector size minus metadata.
#if STORAGE_BACKEND_MAX_PAYLOAD > (FLASH_SECTOR_SIZE_BYTES - sizeof(storage_slot_header_t))
#error "STORAGE_BACKEND_MAX_PAYLOAD is too large for the configured flash sector size."
#endif

typedef struct {
  uint32_t generation;
  uint32_t schema_version;
  uint32_t payload_len;
  uint8_t crc8[1]; // Simple CRC for header validation
} storage_slot_header_t;

typedef struct {
  storage_slot_header_t header;
  uint8_t payload[STORAGE_BACKEND_MAX_PAYLOAD];
} storage_slot_internal_t;

static bool g_storage_initialized = false;

// Helper function to calculate a simple CRC8 for the header
static uint8_t calculate_crc8(const uint8_t *data, size_t len) {
    uint8_t crc = 0u;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
    }
    return crc;
}

// Helper function to read a flash sector into memory
static bool read_flash_sector(uint32_t address, uint8_t *buffer, size_t size) {
    // Basic address validation. More robust checks might be needed depending on memory map.
    if (address < FLASH_BASE || address >= (FLASH_BASE + FLASH_BANK_SIZE)) { // Assuming FLASH_BANK_SIZE is defined in HAL
        return false;
    }
    memcpy(buffer, (uint8_t *)address, size);
    return true;
}

// Helper function to write to a flash sector (erasing first)
static bool write_flash_sector(uint32_t address, const uint8_t *data, size_t size) {
    HAL_StatusTypeDef status;
    uint32_t sector_error;

    // Basic address validation.
    if (address < FLASH_BASE || address >= (FLASH_BASE + FLASH_BANK_SIZE)) {
        return false;
    }

    // Unlock flash
    status = HAL_FLASH_Unlock();
    if (status != HAL_OK) return false;

    // Erase the target sector
    FLASH_EraseInitTypeDef erase_init_struct;
    erase_init_struct.TypeErase = FLASH_TYPEERASE_SECTORS;
    // Determine the sector number from the address
    // This mapping is highly dependent on the STM32 device.
    // For STM32U5xx, you'd need to consult the reference manual for sector mapping.
    // Example for a hypothetical mapping:
    uint32_t sector_number;
    // This mapping needs to be correctly implemented based on the specific STM32U5xx device.
    // For example, on STM32U573, sectors 0-3 are 16KB, sectors 4-7 are 128KB.
    // You would need to map FLASH_SECTOR_A_ADDR and FLASH_SECTOR_B_ADDR to the correct FLASH_SECTOR_X defines.
    // For demonstration purposes, we'll assume a simple mapping.
    if (address == FLASH_SECTOR_A_ADDR) sector_number = FLASH_SECTOR_0; // Example sector number
    else if (address == FLASH_SECTOR_B_ADDR) sector_number = FLASH_SECTOR_1; // Example sector number
    else {
        HAL_FLASH_Lock(); // Lock flash before returning
        return false; // Unknown sector address
    }

    erase_init_struct.Sector = sector_number;
    erase_init_struct.NbSectors = 1; // Erase only one sector

    status = HAL_FLASHEx_Erase(&erase_init_struct, &sector_error);
    if (status != HAL_OK) {
        HAL_FLASH_Lock();
        return false;
    }

    // Program the data
    for (size_t i = 0; i < size; ++i) {
        // Ensure we don't write past the end of the sector if size is smaller than sector size
        if (address + i >= (address + FLASH_SECTOR_SIZE_BYTES)) break;
        status = HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, address + i, data[i]);
        if (status != HAL_OK) {
            HAL_FLASH_Lock();
            return false;
        }
    }

    // Lock flash
    status = HAL_FLASH_Lock();
    if (status != HAL_OK) return false;

    return true;
}

// Helper function to check if a slot is valid and has a valid header CRC
static bool is_slot_valid(const storage_slot_internal_t *slot) {
    if (!slot || slot->header.payload_len == 0 || slot->header.payload_len > STORAGE_BACKEND_MAX_PAYLOAD) {
        return false;
    }
    // Recalculate CRC and compare
    uint8_t calculated_crc = calculate_crc8((uint8_t *)&slot->header, sizeof(storage_slot_header_t) - 1); // Exclude CRC field itself
    return calculated_crc == slot->header.crc8[0];
}

// Helper function to get the generation of a slot
static uint32_t get_slot_generation(const storage_slot_internal_t *slot) {
    // If slot is invalid or not initialized, generation is considered 0.
    if (!slot || slot->header.payload_len == 0) {
        return 0;
    }
    return slot->header.generation;
}

// Helper function to determine which slot is newer
static bool slot_newer(const storage_slot_internal_t *a, const storage_slot_internal_t *b) {
    // If 'a' is invalid, it cannot be newer.
    if (!a || a->header.payload_len == 0) return false;
    // If 'b' is invalid, 'a' is newer (assuming 'a' is valid).
    if (!b || b->header.payload_len == 0) return true;
    // Compare generations if both are valid.
    return get_slot_generation(a) > get_slot_generation(b);
}

void storage_backend_init(void) {
    if (g_storage_initialized) return;

    // Initialize flash HAL (unlocking might be needed for reads/writes)
    HAL_FLASH_Unlock();
    HAL_FLASH_Lock(); // Lock immediately after unlock if no operations are performed yet.

    storage_slot_internal_t slot_a, slot_b;
    bool slot_a_read_ok = read_flash_sector(FLASH_SECTOR_A_ADDR, (uint8_t *)&slot_a, FLASH_SECTOR_SIZE_BYTES);
    bool slot_b_read_ok = read_flash_sector(FLASH_SECTOR_B_ADDR, (uint8_t *)&slot_b, FLASH_SECTOR_SIZE_BYTES);

    // Validate slots based on read success and header CRC
    if (!slot_a_read_ok || !is_slot_valid(&slot_a)) {
        slot_a.header.payload_len = 0; // Mark as invalid
    }
    if (!slot_b_read_ok || !is_slot_valid(&slot_b)) {
        slot_b.header.payload_len = 0; // Mark as invalid
    }

    g_storage_initialized = true;
}

bool storage_backend_write_atomic(const uint8_t *payload,
                                  size_t payload_len,
                                  uint32_t schema_version) {
    if (!g_storage_initialized || payload == NULL) {
        return false;
    }
    if (payload_len == 0u || payload_len > STORAGE_BACKEND_MAX_PAYLOAD) {
        return false;
    }
    if (schema_version == 0u) { // Schema version 0 is invalid
        return false;
    }

    storage_slot_internal_t slot_a, slot_b;
    uint32_t next_generation = 1u;

    // Read current slots to determine the next generation
    bool slot_a_read_ok = read_flash_sector(FLASH_SECTOR_A_ADDR, (uint8_t *)&slot_a, FLASH_SECTOR_SIZE_BYTES);
    bool slot_b_read_ok = read_flash_sector(FLASH_SECTOR_B_ADDR, (uint8_t *)&slot_b, FLASH_SECTOR_SIZE_BYTES);

    // Validate slots before determining generation
    bool valid_a = slot_a_read_ok && is_slot_valid(&slot_a);
    bool valid_b = slot_b_read_ok && is_slot_valid(&slot_b);

    // Determine the next generation number
    uint32_t gen_a = valid_a ? get_slot_generation(&slot_a) : 0;
    uint32_t gen_b = valid_b ? get_slot_generation(&slot_b) : 0;
    next_generation = (gen_a > gen_b ? gen_a : gen_b) + 1u;

    // Prepare the new slot data
    storage_slot_internal_t new_slot;
    memset(&new_slot, 0, sizeof(new_slot)); // Zero out the entire structure first
    new_slot.header.generation = next_generation;
    new_slot.header.schema_version = schema_version;
    new_slot.header.payload_len = (uint32_t)payload_len;
    memcpy(new_slot.payload, payload, payload_len);
    // Calculate CRC for the header (excluding the CRC field itself)
    new_slot.header.crc8[0] = calculate_crc8((uint8_t *)&new_slot.header, sizeof(storage_slot_header_t) - 1);

    // Determine which sector to write to (the older one)
    uint32_t write_address;
    if (!valid_a) {
        write_address = FLASH_SECTOR_A_ADDR; // Slot A is invalid, write there
    } else if (!valid_b) {
        write_address = FLASH_SECTOR_B_ADDR; // Slot B is invalid, write there
    } else {
        // Both are valid, write to the older one
        write_address = slot_newer(&slot_a, &slot_b) ? FLASH_SECTOR_B_ADDR : FLASH_SECTOR_A_ADDR;
    }

    // Write to flash
    if (write_flash_sector(write_address, (uint8_t *)&new_slot, FLASH_SECTOR_SIZE_BYTES)) {
        return true;
    } else {
        // Write failed. In a real system, more sophisticated error handling/recovery might be needed.
        return false;
    }
}

bool storage_backend_read_latest(uint8_t *out_payload,
                                 size_t out_capacity,
                                 size_t *out_len,
                                 uint32_t *out_schema_version) {
    if (!g_storage_initialized || out_payload == NULL || out_len == NULL || out_schema_version == NULL) {
        return false;
    }

    storage_slot_internal_t slot_a, slot_b;
    bool slot_a_read_ok = read_flash_sector(FLASH_SECTOR_A_ADDR, (uint8_t *)&slot_a, FLASH_SECTOR_SIZE_BYTES);
    bool slot_b_read_ok = read_flash_sector(FLASH_SECTOR_B_ADDR, (uint8_t *)&slot_b, FLASH_SECTOR_SIZE_BYTES);

    // Validate slots
    bool valid_a = slot_a_read_ok && is_slot_valid(&slot_a);
    bool valid_b = slot_b_read_ok && is_slot_valid(&slot_b);

    storage_slot_internal_t *latest_slot = NULL;

    if (valid_a && valid_b) {
        latest_slot = slot_newer(&slot_a, &slot_b) ? &slot_a : &slot_b;
    } else if (valid_a) {
        latest_slot = &slot_a;
    } else if (valid_b) {
        latest_slot = &slot_b;
    } else {
        return false; // No valid slots found
    }

    // Check if the payload fits and is not empty
    if (latest_slot->header.payload_len == 0 || latest_slot->header.payload_len > out_capacity) {
        return false;
    }

    memcpy(out_payload, latest_slot->payload, latest_slot->header.payload_len);
    *out_len = (size_t)latest_slot->header.payload_len;
    *out_schema_version = latest_slot->header.schema_version;

    return true;
}

bool storage_backend_debug_state(storage_backend_debug_t *out_debug) {
    if (!g_storage_initialized || out_debug == NULL) {
        return false;
    }

    storage_slot_internal_t slot_a, slot_b;
    bool slot_a_read_ok = read_flash_sector(FLASH_SECTOR_A_ADDR, (uint8_t *)&slot_a, FLASH_SECTOR_SIZE_BYTES);
    bool slot_b_read_ok = read_flash_sector(FLASH_SECTOR_B_ADDR, (uint8_t *)&slot_b, FLASH_SECTOR_SIZE_BYTES);

    out_debug->slot_a_valid = slot_a_read_ok && is_slot_valid(&slot_a);
    out_debug->slot_b_valid = slot_b_read_ok && is_slot_valid(&slot_b);
    out_debug->slot_a_generation = out_debug->slot_a_valid ? slot_a.header.generation : 0;
    out_debug->slot_b_generation = out_debug->slot_b_valid ? slot_b.header.generation : 0;

    return true;
}

bool storage_backend_debug_corrupt_latest(void) {
    if (!g_storage_initialized) {
        return false;
    }

    storage_slot_internal_t slot_a, slot_b;
    bool slot_a_read_ok = read_flash_sector(FLASH_SECTOR_A_ADDR, (uint8_t *)&slot_a, FLASH_SECTOR_SIZE_BYTES);
    bool slot_b_read_ok = read_flash_sector(FLASH_SECTOR_B_ADDR, (uint8_t *)&slot_b, FLASH_SECTOR_SIZE_BYTES);

    storage_slot_internal_t *target_slot = NULL;
    uint32_t write_address = 0;

    // Validate slots
    bool valid_a = slot_a_read_ok && is_slot_valid(&slot_a);
    bool valid_b = slot_b_read_ok && is_slot_valid(&slot_b);

    if (valid_a && valid_b) {
        // Both valid, pick the newer one to corrupt
        if (slot_newer(&slot_a, &slot_b)) {
            target_slot = &slot_a;
            write_address = FLASH_SECTOR_A_ADDR;
        } else {
            target_slot = &slot_b;
            write_address = FLASH_SECTOR_B_ADDR;
        }
    } else if (valid_a) {
        target_slot = &slot_a;
        write_address = FLASH_SECTOR_A_ADDR;
    } else if (valid_b) {
        target_slot = &slot_b;
        write_address = FLASH_SECTOR_B_ADDR;
    } else {
        return false; // No valid slot to corrupt
    }

    // Ensure the slot has data to corrupt
    if (target_slot->header.payload_len == 0) {
        return false; // Slot is empty or invalid
    }

    // Corrupt the first byte of the payload
    uint8_t corrupted_payload[STORAGE_BACKEND_MAX_PAYLOAD];
    memcpy(corrupted_payload, target_slot->payload, target_slot->header.payload_len);
    corrupted_payload[0] ^= 0x7Au; // Flip some bits

    // Re-prepare the slot with corrupted payload and updated CRC
    storage_slot_internal_t corrupted_slot;
    memcpy(&corrupted_slot, target_slot, sizeof(storage_slot_internal_t)); // Copy existing data
    memcpy(corrupted_slot.payload, corrupted_payload, target_slot->header.payload_len);
    // Recalculate CRC for the header
    corrupted_slot.header.crc8[0] = calculate_crc8((uint8_t *)&corrupted_slot.header, sizeof(storage_slot_header_t) - 1);

    // Write the corrupted slot back to flash
    return write_flash_sector(write_address, (uint8_t *)&corrupted_slot, FLASH_SECTOR_SIZE_BYTES);
}

bool storage_backend_wipe(void) {
    if (!g_storage_initialized) {
        return false;
    }

    HAL_StatusTypeDef status;
    uint32_t sector_error;

    // Unlock flash
    status = HAL_FLASH_Unlock();
    if (status != HAL_OK) return false;

    // Erase both sectors
    FLASH_EraseInitTypeDef erase_init_struct;
    erase_init_struct.TypeErase = FLASH_TYPEERASE_SECTORS;
    // Again, sector mapping is device-specific. Assuming Sector 0 and Sector 1 are the target sectors.
    erase_init_struct.Sector = FLASH_SECTOR_0; // Example: Start with Sector 0
    erase_init_struct.NbSectors = 2; // Erase two sectors (Sector 0 and Sector 1)

    status = HAL_FLASHEx_Erase(&erase_init_struct, &sector_error);
    if (status != HAL_OK) {
        HAL_FLASH_Lock();
        return false;
    }

    // Lock flash
    status = HAL_FLASH_Lock();
    if (status != HAL_OK) return false;

    // Reset internal state to reflect empty storage
    g_storage_initialized = false; // Mark as uninitialized to force re-initialization
    storage_backend_init(); // Re-initialize to set up empty state

    return true;
}
