#include "usb_msc.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "companion_html.h" // For k_companion_html (the virtual disk content)
#include "stm32u5xx_hal.h"   // For HAL_StatusTypeDef, LOBYTE, HIBYTE, etc.
#include "pcd_hal.h"         // For pcd_hal_is_connected and potentially lower-level USB ops

// Forward declaration for the companion HTML content
extern const uint8_t k_companion_html[];
extern const size_t k_companion_html_size;

// Helper macros for extracting bytes from words (from STM32 HAL typically)
#ifndef LOBYTE
#define LOBYTE(x)  ((uint8_t)(x & 0x00FFU))
#endif
#ifndef HIBYTE
#define HIBYTE(x)  ((uint8_t)((x & 0xFF00U) >> 8U))
#endif

// Command Block Wrapper (CBW) and Command Status Wrapper (CSW) structures
// Defined by the USB Mass Storage Class Bulk-Only Transport (BOT) Specification.
typedef struct {
    uint32_t dSignature;    // Signature (0x43425355 for CBW)
    uint32_t dTag;          // Command Tag
    uint32_t dDataLength;   // Number of bytes of data that the host expects to transfer
    uint8_t bmFlags;        // Data transfer direction (bit 7: 0=OUT, 1=IN)
    uint8_t bLUN;           // Logical Unit Number
    uint8_t bCBLength;      // Length of the CBWCB (Command Block)
    uint8_t CB[16];         // Command Block (e.g., SCSI command packet)
} CBW_t;

typedef struct {
    uint32_t dSignature;
    uint32_t dTag;
    uint32_t dDataResidue;
    uint8_t bStatus;
} CSW_t;

// Global variables
static CBW_t g_cbw;
static CSW_t g_csw;
static uint32_t g_tag = 0;

// Disk parameters
#define SECTOR_SIZE 512
// Calculate number of sectors needed to hold the companion_html content.
// Add 1 for the MBR.
#define NUM_DATA_SECTORS ((k_companion_html_size + SECTOR_SIZE - 1) / SECTOR_SIZE)
#define NUM_SECTORS (NUM_DATA_SECTORS + 1) // +1 for MBR

// Master Boot Record (MBR) for FAT12
// This is a simplified MBR for a single partition.
static const uint8_t mbr_sector[] = {
    // Boot sector code (jmp instruction + bootloader stub)
    0xEB, 0x3C, 0x90, // JMP SHORT 0x3c; NOP
    0x4D, 0x53, 0x44, 0x4F, 0x53, 0x35, 0x2E, 0x30, 0x00, // "MSDOS5.0" boot message
    0x02, 0x01, 0x01, 0x00, // Reserved sectors (2), FAT count (1), Root entry count (1)
    (uint8_t)(NUM_SECTORS & 0xFF), (uint8_t)(NUM_SECTORS >> 8), // Total sectors (low byte, high byte) - This should be NUM_SECTORS for FAT12
    0xF8, // Media descriptor (fixed disk)
    0x09, 0x00, // Sectors per FAT (9 sectors * 512 bytes/sector = 4.5KB, enough for ~16MB disk)
    0x12, 0x00, // Sectors per track
    0x02, 0x00, // Number of heads
    0x00, 0x00, 0x00, 0x00, // Hidden sectors (start of partition)

    // Partition Table Entry 1 (covers the entire disk)
    0x80, // Boot indicator (active partition)
    0x01, 0x00, 0x00, // Starting sector (relative to MBR, 0 for first partition)
    0x06, // Partition type (0x06 = FAT16, but we'll use FAT12 logic)
    (uint8_t)(NUM_SECTORS & 0xFF), (uint8_t)(NUM_SECTORS >> 8), // Total sectors in partition (low byte, high byte)
    0x00, 0x00, 0x00, 0x00, // Starting absolute sector (relative to disk)

    // Boot signature (0xAA55)
    0x55, 0xAA
};

// FAT Table (simplified for FAT12)
// Each entry is 1.5 bytes (12 bits).
// We need enough entries to cover all data clusters.
// For simplicity, we'll make a small FAT that covers the companion_html size.
// A real FAT would be more complex to calculate.
// The size of the FAT table needs to be sufficient for the number of clusters.
// For FAT12, the number of sectors per FAT is calculated as:
// (TotalClusters / (BytesPerSector / 1.5)) / BytesPerSector
// TotalClusters = NUM_DATA_SECTORS (approx)
// Let's assume 2KB for the FAT table, which should be enough for a small disk.
#define FAT_TABLE_SIZE (2 * 1024)
static uint8_t fat_table[FAT_TABLE_SIZE] = {0};

// Function to get a FAT entry
static uint32_t get_fat_entry(uint32_t cluster_id) {
    if (cluster_id == 0) return 0xFFF; // End of chain marker for FAT12
    uint32_t byte_offset = (cluster_id * 3) / 2;
    uint16_t entry;
    if (cluster_id % 2 == 1) { // Odd cluster ID, entry spans across two bytes
        entry = (fat_table[byte_offset] >> 4) | ((uint16_t)fat_table[byte_offset + 1] << 4);
    } else { // Even cluster ID, entry is within one byte and the next
        entry = (fat_table[byte_offset] | ((uint16_t)fat_table[byte_offset + 1] << 8)) & 0x0FFF;
    }
    return entry;
}

// Function to set a FAT entry
static void set_fat_entry(uint32_t cluster_id, uint32_t value) {
    if (cluster_id == 0) return; // Cannot set cluster 0
    uint32_t byte_offset = (cluster_id * 3) / 2;
    uint16_t entry = (uint16_t)value;

    if (cluster_id % 2 == 1) { // Odd cluster ID
        fat_table[byte_offset] = (fat_table[byte_offset] & 0x0F) | ((entry << 4) & 0xF0);
        fat_table[byte_offset + 1] = (entry >> 4) & 0xFF;
    } else { // Even cluster ID
        fat_table[byte_offset] = entry & 0xFF;
        fat_table[byte_offset + 1] = (fat_table[byte_offset + 1] & 0xF0) | ((entry >> 8) & 0x0F);
    }
}

// Initialize the FAT table
static void init_fat_table(void) {
    // Cluster 0 and 1 are reserved (0xFFF for FAT12)
    fat_table[0] = 0xFF;
    fat_table[1] = 0xFF;
    fat_table[2] = 0xFF;

    // Mark the first cluster used by the companion_html as allocated
    // The first data cluster is typically cluster 2.
    uint32_t current_cluster = 2;
    uint32_t next_cluster = 0xFFF; // End of chain

    // Fill FAT entries for the companion_html content
    size_t remaining_size = k_companion_html_size;
    while (remaining_size > 0) {
        set_fat_entry(current_cluster, next_cluster);
        if (remaining_size <= SECTOR_SIZE) {
            next_cluster = 0xFFF; // Last cluster
        } else {
            // Allocate next cluster
            current_cluster++;
            next_cluster = current_cluster;
        }
        remaining_size -= SECTOR_SIZE;
    }
}

// Get the data for a specific sector
static const uint8_t* get_sector_data(uint32_t lba) {
    if (lba == 0) {
        return mbr_sector;
    }
    // Data sectors start after MBR and FAT
    // Cluster 2 corresponds to the first data sector after MBR and FAT
    uint32_t data_sector_index = lba - 1; // Adjust for MBR being sector 0

    // Calculate which cluster this sector belongs to
    // Assuming 1 sector per cluster for simplicity in this example.
    // A real FAT filesystem would have cluster sizes defined.
    uint32_t cluster_id = 2 + data_sector_index;

    // Check if the cluster is allocated in the FAT
    uint32_t current_cluster = 2;
    uint32_t cluster_offset = 0;
    while (current_cluster < cluster_id && current_cluster != 0xFFF) {
        uint32_t next_cluster = get_fat_entry(current_cluster);
        if (next_cluster == 0xFFF) break; // End of chain
        cluster_offset++;
        current_cluster = next_cluster;
    }

    if (current_cluster != cluster_id) {
        // Cluster not allocated or out of bounds
        return NULL;
    }

    // Calculate the offset within the companion_html data
    size_t data_offset = (cluster_id - 2) * SECTOR_SIZE;
    if (data_offset < k_companion_html_size) {
        // Return a pointer to the relevant part of k_companion_html
        // Note: This assumes k_companion_html is aligned to sector boundaries.
        // If not, we'd need to copy data into a buffer.
        return k_companion_html + data_offset;
    }

    return NULL; // Sector out of bounds
}

/* -------------------------------------------------------------------------
 * USB MSC Initialization and Poll
 * ------------------------------------------------------------------------- */
void usb_msc_init(void) {
    // Initialize the FAT table
    init_fat_table();
}

void usb_msc_poll(void) {
    // Check if USB is connected and data is available
    if (!pcd_hal_is_connected()) {
        return;
    }

    // This function would typically be called periodically to check for
    // incoming USB commands and manage data transfers.
    // The actual processing of CBWs and CSWs is handled by process_cbw().
    // This poll function would manage the USB endpoint communication.
    // For this example, we'll assume the main loop or interrupt handler
    // calls a function that checks for and processes USB events.
}

/* -------------------------------------------------------------------------
 * USB MSC Get Sector
 * ------------------------------------------------------------------------- */
bool usb_msc_get_sector(uint32_t lba, uint8_t *buf) {
    if (buf == NULL) {
        return false;
    }

    const uint8_t *sector_data = get_sector_data(lba);

    if (sector_data != NULL) {
        memcpy(buf, sector_data, SECTOR_SIZE);
        return true;
    } else {
        // If the sector is not found, fill the buffer with zeros (or a specific error pattern)
        memset(buf, 0, SECTOR_SIZE);
        return false; // Indicate that the sector could not be retrieved
    }
}

/* -------------------------------------------------------------------------
 * USB MSC Send/Receive Data (simplified)
 *
 * These functions would handle the actual USB data transfer using the HAL.
 * For this example, we'll provide basic implementations that might be
 * called by a higher-level USB MSC driver.
 * ------------------------------------------------------------------------- */

// Function to process a received CBW
static void process_cbw(void) {
    // Reset CSW for this command
    memset(&g_csw, 0, sizeof(g_csw));
    g_csw.dSignature = 0x53574253; // "SWB"
    g_csw.dTag = g_cbw.dTag;
    g_csw.dDataResidue = g_cbw.dDataLength; // Assume all data is transferred initially

    // Extract command details
    uint8_t command = g_cbw.CB[0];
    uint32_t transfer_length = g_cbw.dDataLength;
    uint32_t lba = 0;
    uint16_t block_count = 0;

    // Process common SCSI commands
    switch (command) {
        case 0x00: // TEST UNIT READY
            g_csw.bStatus = 0; // Success
            break;

        case 0x01: // INQUIRY
            // Respond with inquiry data (e.g., device type, vendor, product)
            {
                uint8_t inquiry_data[36] = {0};
                inquiry_data[0] = 0x00; // Direct Access Device
                inquiry_data[1] = 0x80; // Removable media
                inquiry_data[2] = 0x02; // Version 2
                memcpy(&inquiry_data[8], "STM32 MSC", 9); // Vendor
                memcpy(&inquiry_data[16], "Virtual Disk", 12); // Product
                memcpy(&inquiry_data[32], "1.00", 4); // Revision

                if (g_cbw.dDataLength >= sizeof(inquiry_data)) {
                    if (usb_msc_send_data(inquiry_data, sizeof(inquiry_data))) {
                        g_csw.dDataResidue -= sizeof(inquiry_data);
                        g_csw.bStatus = 0; // Success
                    } else {
                        g_csw.bStatus = 1; // Command failed
                    }
                } else {
                    g_csw.bStatus = 1; // Command failed (buffer too small)
                }
            }
            break;

        case 0x03: // REQUEST SENSE
            // Respond with sense data (e.g., no sense data available)
            {
                uint8_t sense_data[18] = {0};
                sense_data[0] = 0x70; // Fixed format
                sense_data[2] = 0x00; // No additional sense information
                // Other fields can be set to 0 for simplicity

                if (g_cbw.dDataLength >= sizeof(sense_data)) {
                    if (usb_msc_send_data(sense_data, sizeof(sense_data))) {
                        g_csw.dDataResidue -= sizeof(sense_data);
                        g_csw.bStatus = 0; // Success
                    } else {
                        g_csw.bStatus = 1; // Command failed
                    }
                } else {
                    g_csw.bStatus = 1; // Command failed (buffer too small)
                }
            }
            break;

        case 0x12: // READ CAPACITY (10)
            // Respond with the total number of sectors and sector size
            {
                uint8_t capacity_data[8] = {0};
                uint32_t total_sectors = NUM_SECTORS; // Total sectors on the virtual disk
                uint32_t sector_size = SECTOR_SIZE;

                capacity_data[0] = (total_sectors >> 24) & 0xFF;
                capacity_data[1] = (total_sectors >> 16) & 0xFF;
                capacity_data[2] = (total_sectors >> 8) & 0xFF;
                capacity_data[3] = total_sectors & 0xFF;
                capacity_data[4] = (sector_size >> 24) & 0xFF;
                capacity_data[5] = (sector_size >> 16) & 0xFF;
                capacity_data[6] = (sector_size >> 8) & 0xFF;
                capacity_data[7] = sector_size & 0xFF;

                if (g_cbw.dDataLength >= sizeof(capacity_data)) {
                    if (usb_msc_send_data(capacity_data, sizeof(capacity_data))) {
                        g_csw.dDataResidue -= sizeof(capacity_data);
                        g_csw.bStatus = 0; // Success
                    } else {
                        g_csw.bStatus = 1; // Command failed
                    }
                } else {
                    g_csw.bStatus = 1; // Command failed (buffer too small)
                }
            }
            break;

        case 0x28: // READ (10)
            // Extract LBA and block count
            lba = ((uint32_t)g_cbw.CB[2] << 24) | ((uint32_t)g_cbw.CB[3] << 16) |
                  ((uint32_t)g_cbw.CB[4] << 8) | g_cbw.CB[5];
            block_count = ((uint16_t)g_cbw.CB[7] << 8) | g_cbw.CB[8];

            // Calculate total bytes to read
            uint32_t bytes_to_read = block_count * SECTOR_SIZE;
            if (bytes_to_read > transfer_length) {
                bytes_to_read = transfer_length; // Don't read more than requested
            }

            uint8_t sector_buffer[SECTOR_SIZE];
            uint32_t sectors_read = 0;
            for (uint32_t i = 0; i < block_count; ++i) {
                uint32_t current_lba = lba + i;
                if (current_lba >= NUM_SECTORS) {
                    break; // Out of bounds
                }

                if (usb_msc_get_sector(current_lba, sector_buffer)) {
                    if (usb_msc_send_data(sector_buffer, SECTOR_SIZE)) {
                        g_csw.dDataResidue -= SECTOR_SIZE;
                        sectors_read++;
                    } else {
                        break; // Send failed
                    }
                } else {
                    break; // Get sector failed
                }
            }
            g_csw.bStatus = (sectors_read == block_count) ? 0 : 1; // Success if all blocks read
            break;

        case 0x2F: // READ (16) - Not fully supported, but can handle basic read
            // Extract LBA and block count
            lba = ((uint32_t)g_cbw.CB[2] << 24) | ((uint32_t)g_cbw.CB[3] << 16) |
                  ((uint32_t)g_cbw.CB[4] << 8) | g_cbw.CB[5];
            block_count = ((uint16_t)g_cbw.CB[12] << 8) | g_cbw.CB[13];

            // Calculate total bytes to read
            bytes_to_read = block_count * SECTOR_SIZE;
            if (bytes_to_read > transfer_length) {
                bytes_to_read = transfer_length; // Don't read more than requested
            }

            // Similar logic to READ (10)
            for (uint32_t i = 0; i < block_count; ++i) {
                uint32_t current_lba = lba + i;
                if (current_lba >= NUM_SECTORS) {
                    break; // Out of bounds
                }

                uint8_t sector_buffer[SECTOR_SIZE];
                if (usb_msc_get_sector(current_lba, sector_buffer)) {
                    if (usb_msc_send_data(sector_buffer, SECTOR_SIZE)) {
                        g_csw.dDataResidue -= SECTOR_SIZE;
                        sectors_read++;
                    } else {
                        break; // Send failed
                    }
                } else {
                    break; // Get sector failed
                }
            }
            g_csw.bStatus = (sectors_read == block_count) ? 0 : 1; // Success if all blocks read
            break;

        case 0x1E: // MODE SENSE (6)
            // Respond with mode sense data (e.g., block descriptor)
            {
                uint8_t mode_sense_data[8] = {0};
                mode_sense_data[0] = 0x00; // Mode data length
                mode_sense_data[1] = 0x00; // Medium type
                mode_sense_data[2] = 0x00; // Device specific parameter
                mode_sense_data[3] = 0x00; // Block descriptor length
                // No block descriptor for this simple implementation

                if (g_cbw.dDataLength >= sizeof(mode_sense_data)) {
                    if (usb_msc_send_data(mode_sense_data, sizeof(mode_sense_data))) {
                        g_csw.dDataResidue -= sizeof(mode_sense_data);
                        g_csw.bStatus = 0; // Success
                    } else {
                        g_csw.bStatus = 1; // Command failed
                    }
                } else {
                    g_csw.bStatus = 1; // Command failed (buffer too small)
                }
            }
            break;

        case 0x3F: // MODE SENSE (10)
            // Similar to MODE SENSE (6), but with a larger header.
            // For simplicity, we'll return a minimal response.
            {
                uint8_t mode_sense_data[10] = {0};
                mode_sense_data[0] = 0x00; // Mode data length
                mode_sense_data[1] = 0x00; // Medium type
                mode_sense_data[2] = 0x00; // Device specific parameter
                mode_sense_data[3] = 0x00; // Block descriptor length
                // No block descriptor for this simple implementation

                if (g_cbw.dDataLength >= sizeof(mode_sense_data)) {
                    if (usb_msc_send_data(mode_sense_data, sizeof(mode_sense_data))) {
                        g_csw.dDataResidue -= sizeof(mode_sense_data);
                        g_csw.bStatus = 0; // Success
                    } else {
                        g_csw.bStatus = 1; // Command failed
                    }
                } else {
                    g_csw.bStatus = 1; // Command failed (buffer too small)
                }
            }
            break;

        case 0x00: // SYNCHRONIZE CACHE
        case 0x04: // VERIFY
        case 0x08: // READ (6) - Not typically used with LBA
        case 0x1B: // START STOP UNIT
        case 0x35: // MOVE MEDIUM
        case 0x39: // LOCATE (10)
        case 0x42: // READ FORMATTED CAPACITY
        case 0x46: // READ CAPACITY (16)
        case 0x4A: // WRITE (16)
        case 0x5A: // WRITE (10)
            // Commands that modify data or are complex are not supported
            // For these, we'll return success but indicate no data transfer if applicable.
            g_csw.bStatus = 0; // Assume success for unsupported commands
            break;

        default:
            // Unsupported command
            g_csw.bStatus = 2; // Command failed (Phase error or unknown command)
            break;
    }

    // Send the CSW
    if (!usb_msc_send_data((const uint8_t*)&g_csw, sizeof(g_csw))) {
        // Handle CSW send failure (e.g., log error)
    }
}

// This function would be called by the USB peripheral interrupt handler
// or a periodic poll to process incoming USB MSC traffic.
void usb_msc_process_usb_event(void) {
    if (!pcd_hal_is_connected()) {
        return;
    }

    // In a real implementation, this would involve:
    // 1. Checking for incoming data on the OUT endpoint.
    // 2. If data is available, read it into a buffer.
    // 3. If the buffer contains a CBW, parse it and store in g_cbw.
    // 4. Increment g_tag.
    // 5. Call process_cbw() to handle the command.
    // 6. If data transfer is required (e.g., READ, WRITE), handle it via usb_msc_send_data/receive_data.
    // 7. Send the CSW.

    // Simplified example: Assume a CBW is ready to be read.
    // This part needs to be integrated with the actual USB peripheral driver.
    // For now, we'll just simulate receiving a CBW.

    // Example: Simulate receiving a READ command CBW
    // This is for demonstration purposes and would not be in the final code.
    /*
    if (some_condition_to_receive_cbw) {
        memset(&g_cbw, 0, sizeof(g_cbw));
        g_cbw.dSignature = 0x43425355; // CBW signature
        g_cbw.dTag = g_tag++;
        g_cbw.dDataLength = 512 * 2; // Requesting 2 sectors
        g_cbw.bmFlags = 0x80; // Direction: Host to Device (IN)
        g_cbw.bLUN = 0;
        g_cbw.bCBLength = 10;
        // SCSI READ (10) command
        g_cbw.CB[0] = 0x28; // READ (10)
        g_cbw.CB[2] = 0x00; // LBA (high byte)
        g_cbw.CB[3] = 0x00; // LBA
        g_cbw.CB[4] = 0x00; // LBA
        g_cbw.CB[5] = 0x01; // LBA (low byte) - starting at sector 1
        g_cbw.CB[7] = 0x00; // Number of blocks (high byte)
        g_cbw.CB[8] = 0x02; // Number of blocks (low byte) - 2 sectors

        process_cbw();
    }
    */
}
