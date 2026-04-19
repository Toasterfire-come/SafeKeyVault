#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "stm32u5xx_hal.h" // Include HAL header for FLASH operations

#include "storage_backend.h"

// IMPORTANT: Define flash sector addresses and sizes based on your specific STM32U5xx MCU and linker script.
// These are EXAMPLE values and MUST be adjusted for your target hardware.
// Consult the STM32U5xx reference manual and your project's linker script (.ld file) for correct values.
// For example, if using the first two 16KB sectors of a device with 16KB sectors:
#define FLASH_SECTOR_A_ADDR 0x08000000 // Start address of Flash Sector A (e.g., Sector 0)
#define FLASH_SECTOR_B_ADDR 0x08004000 // Start address of Flash Sector B (e.g., Sector 1, assuming 16KB sectors)
#define FLASH_SECTOR_SIZE   0x4000     // Size of one flash sector (e.g., 16KB = 0x4000 bytes)
#define FLASH_BANK_SIZE     0x200000   // Total Flash memory size of the device (e.g., 2MB = 0x200000 bytes)

// Ensure that the total payload size does not exceed the sector size minus metadata.
#if STORAGE_BACKEND_MAX_PAYLOAD > (FLASH_SECTOR_SIZE - sizeof(storage_slot_header_t))
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

static uint8_t calculate_crc8(const uint8_t *data, size_t len) {
    uint8_t crc = 0u;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
    }
    return crc;
}

static bool read_flash_sector(uint32_t address, uint8_t *buffer, size_t size) {
    // Basic address validation. Ensure the address is within the flash memory range.
    if (address < FLASH_BASE || address >= (FLASH_BASE + FLASH_BANK_SIZE)) {
        return false;
    }
    // Ensure the read size does not exceed the sector size or go beyond the flash boundaries.
    if (size > FLASH_SECTOR_SIZE || (address + size) > (FLASH_BASE + FLASH_BANK_SIZE)) {
        return false;
    }
    // Read directly from the memory-mapped flash address.
    // This is the standard way to read from memory-mapped flash.
    memcpy(buffer, (uint8_t *)address, size);
    return true;
}

static bool write_flash_sector(uint32_t address, const uint8_t *data, size_t size) {
    HAL_StatusTypeDef status;
    uint32_t sector_error; // Unused variable, but kept for HAL function signature compatibility if needed.

    // Basic address validation. Ensure the address is within the flash memory range.
    if (address < FLASH_BASE || address >= (FLASH_BASE + FLASH_BANK_SIZE)) {
        return false;
    }
    // Ensure the write size does not exceed the sector size or go beyond the flash boundaries.
    if (size > FLASH_SECTOR_SIZE || (address + size) > (FLASH_BASE + FLASH_BANK_SIZE)) {
        return false;
    }

    // Unlock flash
    status = HAL_FLASH_Unlock();
    if (status != HAL_OK) {
        return false;
    }

    // Erase the sector before writing
    FLASH_EraseInitTypeDef erase_init;
    erase_init.TypeErase = FLASH_TYPEERASE_SECTORS; // Use sector erase

    // Determine the sector number from the address. This mapping is device-specific.
    // You need to consult the STM32U5xx reference manual for the correct sector mapping.
    // Example mapping for STM32U573: Sectors 0-3 are 16KB, Sectors 4-7 are 128KB.
    // The following logic assumes a simple mapping where FLASH_SECTOR_A_ADDR and FLASH_SECTOR_B_ADDR
    // correspond to specific, contiguous sectors. Adjust this logic based on your MCU's memory map.
    uint32_t sector_number;
    uint32_t bank_number = FLASH_BANK_1; // Default to Bank 1, adjust if using dual-bank features

    // This mapping logic is CRITICAL and must match your linker script and MCU's flash layout.
    // Example: If FLASH_SECTOR_A_ADDR is the start of Sector 0, and FLASH_SECTOR_B_ADDR is the start of Sector 1.
    if (address == FLASH_SECTOR_A_ADDR) {
        sector_number = FLASH_SECTOR_0; // Assuming Sector A maps to Sector 0
    } else if (address == FLASH_SECTOR_B_ADDR) {
        sector_number = FLASH_SECTOR_1; // Assuming Sector B maps to Sector 1
    } else {
        // If the address doesn't match known sectors, it's an error.
        HAL_FLASH_Lock(); // Lock flash before returning
        return false; // Unknown sector address
    }
    erase_init.Sector = sector_number;
    erase_init.NbSectors = 1; // Erase only one sector

    // Ensure the correct bank is selected if applicable (for dual-bank devices)
    // This requires knowing which bank FLASH_SECTOR_A_ADDR and FLASH_SECTOR_B_ADDR belong to.
    // For simplicity, assuming single bank or both sectors are in Bank 1.
    // erase_init.Banks = bank_number; // Uncomment and set correctly if using dual banks

    status = HAL_FLASHEx_Erase(&erase_init, &sector_error);
    if (status != HAL_OK) {
        HAL_FLASH_Lock(); // Lock flash before returning
        return false;
    }

    // Program the data in 32-bit words for efficiency
    // The HAL_FLASH_Program function programs in 32-bit words.
    for (size_t i = 0; i < size; i += 4) {
        uint32_t data_word = 0;
        // Copy up to 4 bytes for the current word, handling the end of the data
        size_t bytes_to_copy = (size - i < 4) ? (size - i) : 4;
        memcpy(&data_word, data + i, bytes_to_copy);

        // Ensure we don't write past the end of the sector if size is smaller than sector size
        // This check is important to avoid writing beyond the intended data size within the sector.
        if (address + i >= (address + size)) break; // Stop if we've written all requested data

        status = HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, address + i, data_word);
        if (status != HAL_OK) {
            HAL_FLASH_Lock(); // Lock flash before returning
            return false;
        }
    }

    // Lock flash
    status = HAL_FLASH_Lock();
    if (status != HAL_OK) {
        return false;
    }

    return true;
}

static bool is_slot_valid(const storage_slot_internal_t *slot) {
    // Check for null pointer, zero payload length, or payload exceeding max capacity
    if (!slot || slot->header.payload_len == 0 || slot->header.payload_len > STORAGE_BACKEND_MAX_PAYLOAD) {
        return false;
    }
    // Recalculate CRC and compare
    // Ensure the CRC calculation covers the header fields *excluding* the CRC field itself.
    uint8_t calculated_crc = calculate_crc8((uint8_t *)&slot->header, sizeof(storage_slot_header_t) - sizeof(slot->header.crc8));
    return calculated_crc == slot->header.crc8[0];
}

static uint32_t get_slot_generation(const storage_slot_internal_t *slot) {
    // If slot is invalid or not initialized, generation is considered 0.
    if (!slot || slot->header.payload_len == 0) {
        return 0;
    }
    return slot->header.generation;
}

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

    // The HAL_Init() function (typically called in main.c) initializes the HAL system,
    // including the FLASH peripheral clock and configuration.
    // Explicit HAL_FLASH_Unlock/Lock are handled within write_flash_sector.

    storage_slot_internal_t slot_a, slot_b;
    // Attempt to read both sectors. If a read fails, the corresponding slot will be considered invalid.
    bool slot_a_read_ok = read_flash_sector(FLASH_SECTOR_A_ADDR, (uint8_t *)&slot_a, FLASH_SECTOR_SIZE);
    bool slot_b_read_ok = read_flash_sector(FLASH_SECTOR_B_ADDR, (uint8_t *)&slot_b, FLASH_SECTOR_SIZE);

    // The debug_state variable was declared but not used within this function. Removed for cleanliness.
    // storage_backend_debug_t debug_state;
    // debug_state.slot_a_valid = slot_a_read_ok && is_slot_valid(&slot_a);
    // debug_state.slot_b_valid = slot_b_read_ok && is_slot_valid(&slot_b);
    // debug_state.slot_a_generation = debug_state.slot_a_valid ? slot_a.header.generation : 0;
    // debug_state.slot_b_generation = debug_state.slot_b_valid ? slot_b.header.generation : 0;

    // If neither slot is valid, the storage is considered empty.
    // Subsequent writes will initialize the storage.

    g_storage_initialized = true;
}

bool storage_backend_write_atomic(const uint8_t *payload,
                                  size_t payload_len,
                                  uint32_t schema_version) {
    if (!g_storage_initialized || payload == NULL || payload_len == 0 || payload_len > STORAGE_BACKEND_MAX_PAYLOAD) {
        return false;
    }

    storage_slot_internal_t slot_a, slot_b;
    bool slot_a_read_ok = read_flash_sector(FLASH_SECTOR_A_ADDR, (uint8_t *)&slot_a, FLASH_SECTOR_SIZE);
    bool slot_b_read_ok = read_flash_sector(FLASH_SECTOR_B_ADDR, (uint8_t *)&slot_b, FLASH_SECTOR_SIZE);

    // Determine the next generation number
    uint32_t next_generation = 0;
    bool valid_a = slot_a_read_ok && is_slot_valid(&slot_a);
    bool valid_b = slot_b_read_ok && is_slot_valid(&slot_b);

    if (valid_a && valid_b) {
        // Both slots are valid, increment the generation of the older one.
        next_generation = (slot_a.header.generation > slot_b.header.generation ? slot_a.header.generation : slot_b.header.generation) + 1;
    } else if (valid_a) {
        // Only slot A is valid, increment its generation.
        next_generation = slot_a.header.generation + 1;
    } else if (valid_b) {
        // Only slot B is valid, increment its generation.
        next_generation = slot_b.header.generation + 1;
    } else {
        // If both slots are invalid, start from generation 1.
        next_generation = 1;
    }

    storage_slot_internal_t new_slot;
    new_slot.header.generation = next_generation;
    new_slot.header.schema_version = schema_version;
    new_slot.header.payload_len = (uint32_t)payload_len;
    memcpy(new_slot.payload, payload, payload_len);
    // Calculate CRC for the header (excluding the CRC field itself)
    new_slot.header.crc8[0] = calculate_crc8((uint8_t *)&new_slot.header, sizeof(storage_slot_header_t) - sizeof(new_slot.header.crc8));

    // Determine which slot to write to (the older one, or an invalid one).
    uint32_t write_address;
    if (!valid_a) {
        write_address = FLASH_SECTOR_A_ADDR; // Slot A is invalid, write there.
    } else if (!valid_b) {
        write_address = FLASH_SECTOR_B_ADDR; // Slot B is invalid, write there.
    } else {
        // Both are valid, write to the older one to maintain wear-leveling.
        write_address = slot_newer(&slot_a, &slot_b) ? FLASH_SECTOR_B_ADDR : FLASH_SECTOR_A_ADDR;
    }

    // Write to the chosen flash sector.
    if (write_flash_sector(write_address, (uint8_t *)&new_slot, sizeof(storage_slot_internal_t))) {
        return true;
    }

    return false;
}

bool storage_backend_read_latest(uint8_t *out_payload,
                                 size_t out_capacity,
                                 size_t *out_len,
                                 uint32_t *out_schema_version) {
    if (!g_storage_initialized || !out_payload || !out_len || !out_schema_version) {
        return false;
    }

    storage_slot_internal_t slot_a, slot_b;
    bool slot_a_read_ok = read_flash_sector(FLASH_SECTOR_A_ADDR, (uint8_t *)&slot_a, FLASH_SECTOR_SIZE);
    bool slot_b_read_ok = read_flash_sector(FLASH_SECTOR_B_ADDR, (uint8_t *)&slot_b, FLASH_SECTOR_SIZE);

    bool valid_a = slot_a_read_ok && is_slot_valid(&slot_a);
    bool valid_b = slot_b_read_ok && is_slot_valid(&slot_b);

    storage_slot_internal_t *latest_slot = NULL;

    if (valid_a && valid_b) {
        // Both slots are valid, pick the one with the higher generation.
        latest_slot = slot_newer(&slot_a, &slot_b) ? &slot_a : &slot_b;
    } else if (valid_a) {
        // Only slot A is valid.
        latest_slot = &slot_a;
    } else if (valid_b) {
        // Only slot B is valid.
        latest_slot = &slot_b;
    } else {
        // No valid slots found.
        *out_len = 0;
        *out_schema_version = 0;
        return false;
    }

    // Copy data to output buffers.
    if (latest_slot->header.payload_len > out_capacity) {
        // Payload is too large for the provided buffer.
        *out_len = 0;
        *out_schema_version = 0;
        return false;
    }

    memcpy(out_payload, latest_slot->payload, latest_slot->header.payload_len);
    *out_len = latest_slot->header.payload_len;
    *out_schema_version = latest_slot->header.schema_version;

    // IMPORTANT: If 'out_payload' contains sensitive data, the caller is responsible
    // for securely zeroing it out after it's no longer needed.
    // Example:
    // uint8_t sensitive_data[STORAGE_BACKEND_MAX_PAYLOAD];
    // size_t len;
    // uint32_t schema;
    // if (storage_backend_read_latest(sensitive_data, sizeof(sensitive_data), &len, &schema)) {
    //     // ... use sensitive_data ...
    //     security_secure_zero(sensitive_data, sizeof(sensitive_data)); // Zero out after use
    // }

    return true;
}

bool storage_backend_debug_state(storage_backend_debug_t *out_debug) {
    if (!g_storage_initialized || out_debug == NULL) {
        return false;
    }

    storage_slot_internal_t slot_a, slot_b;
    bool slot_a_read_ok = read_flash_sector(FLASH_SECTOR_A_ADDR, (uint8_t *)&slot_a, FLASH_SECTOR_SIZE);
    bool slot_b_read_ok = read_flash_sector(FLASH_SECTOR_B_ADDR, (uint8_t *)&slot_b, FLASH_SECTOR_SIZE);

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
    bool slot_a_read_ok = read_flash_sector(FLASH_SECTOR_A_ADDR, (uint8_t *)&slot_a, FLASH_SECTOR_SIZE);
    bool slot_b_read_ok = read_flash_sector(FLASH_SECTOR_B_ADDR, (uint8_t *)&slot_b, FLASH_SECTOR_SIZE);

    storage_slot_internal_t *target_slot = NULL;
    uint32_t target_address = 0;

    bool valid_a = slot_a_read_ok && is_slot_valid(&slot_a);
    bool valid_b = slot_b_read_ok && is_slot_valid(&slot_b);

    if (valid_a && valid_b) {
        // Both valid, pick the newer one to corrupt.
        if (slot_newer(&slot_a, &slot_b)) {
            target_slot = &slot_a;
            target_address = FLASH_SECTOR_A_ADDR;
        } else {
            target_slot = &slot_b;
            target_address = FLASH_SECTOR_B_ADDR;
        }
    } else if (valid_a) {
        target_slot = &slot_a;
        target_address = FLASH_SECTOR_A_ADDR;
    } else if (valid_b) {
        target_slot = &slot_b;
        target_address = FLASH_SECTOR_B_ADDR;
    } else {
        // No valid slots to corrupt.
        return false;
    }

    // Corrupt the CRC by incrementing it. This will make the slot invalid.
    target_slot->header.crc8[0]++;

    // Write the corrupted slot back to flash.
    return write_flash_sector(target_address, (uint8_t *)target_slot, sizeof(storage_slot_internal_t));
}

bool storage_backend_wipe(void) {
    if (!g_storage_initialized) {
        return false;
    }

    HAL_StatusTypeDef status;
    // uint32_t sector_error; // Removed unused variable

    // Unlock flash
    status = HAL_FLASH_Unlock();
    if (status != HAL_OK) {
        return false;
    }

    // Erase Sector A
    FLASH_EraseInitTypeDef erase_init_a;
    erase_init_a.TypeErase = FLASH_TYPEERASE_SECTORS;
    // Determine the sector number for Sector A. This mapping is device-specific.
    uint32_t sector_number_a;
    // This mapping logic is CRITICAL and must match your linker script and MCU's flash layout.
    if (FLASH_SECTOR_A_ADDR == 0x08000000) sector_number_a = FLASH_SECTOR_0; // Example: Sector 0
    else if (FLASH_SECTOR_A_ADDR == 0x08004000) sector_number_a = FLASH_SECTOR_1; // Example: Sector 1
    // Add more conditions here if FLASH_SECTOR_A_ADDR can map to other sectors.
    else {
        HAL_FLASH_Lock(); // Lock flash before returning
        return false; // Unknown sector address for Sector A
    }
    erase_init_a.Sector = sector_number_a;
    erase_init_a.NbSectors = 1;
    // erase_init_a.Banks = FLASH_BANK_1; // Specify bank if using dual-bank configuration

    status = HAL_FLASHEx_Erase(&erase_init_a, NULL); // Pass NULL for sector_error as it's unused
    if (status != HAL_OK) {
        HAL_FLASH_Lock();
        return false;
    }

    // Erase Sector B
    FLASH_EraseInitTypeDef erase_init_b;
    erase_init_b.TypeErase = FLASH_TYPEERASE_SECTORS;
    // Determine the sector number for Sector B. This mapping is device-specific.
    uint32_t sector_number_b;
    // This mapping logic is CRITICAL and must match your linker script and MCU's flash layout.
    if (FLASH_SECTOR_B_ADDR == 0x08000000) sector_number_b = FLASH_SECTOR_0; // Example: Sector 0
    else if (FLASH_SECTOR_B_ADDR == 0x08004000) sector_number_b = FLASH_SECTOR_1; // Example: Sector 1
    // Add more conditions here if FLASH_SECTOR_B_ADDR can map to other sectors.
    else {
        HAL_FLASH_Lock(); // Lock flash before returning
        return false; // Unknown sector address for Sector B
    }
    erase_init_b.Sector = sector_number_b;
    erase_init_b.NbSectors = 1;
    // erase_init_b.Banks = FLASH_BANK_1; // Specify bank if using dual-bank configuration

    status = HAL_FLASHEx_Erase(&erase_init_b, NULL); // Pass NULL for sector_error as it's unused
    if (status != HAL_OK) {
        HAL_FLASH_Lock();
        return false;
    }

    // Lock flash
    status = HAL_FLASH_Lock();
    if (status != HAL_OK) {
        return false;
    }

    // Reset internal state to reflect empty storage.
    // Setting g_storage_initialized to false will cause storage_backend_init()
    // to re-run on the next call, effectively re-initializing the storage state.
    g_storage_initialized = false;

    return true;
}
