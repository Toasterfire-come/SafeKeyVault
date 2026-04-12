#include "platform_hal.h"
#include "stm32u5xx_hal.h" // Include the main HAL header
#include "build_config.h" // For FIRMWARE_PRODUCTION

// Forward declarations for peripheral initialization functions
void SystemClock_Config(void);
void MX_GPIO_Init(void);
void MX_I2C1_Init(void);
void MX_SPI1_Init(void);
void MX_OCTOSPI1_Init(void);
void MX_USB_PCD_Init(void);

// Global variables for HAL state
static volatile uint32_t uwTick = 0; // Fix uwTick to be volatile
static uint32_t uwTickPrio = 0;
static HAL_TickFreqTypeDef uwTickFreq = HAL_TICK_FREQ_DEFAULT;

// Handle structures for peripherals
static PCD_HandleTypeDef hpcd_USB_OTG_FS;
static I2C_HandleTypeDef hi2c1;
static SPI_HandleTypeDef hspi1;
static OCTOSPI_HandleTypeDef hospi1;
static GPIO_InitTypeDef GPIO_InitStruct = {0};

// USB HID report buffer
static uint8_t hid_report_buffer[64];
static bool hid_report_pending = false;
static uint8_t hid_report_id = 0;

// Mass Storage variables
static const uint8_t fat12_image[] = {
    // FAT12 image data would go here
    // This is a placeholder for the actual image data
    0xEB, 0x3C, 0x90, 0x4D, 0x53, 0x44, 0x4F, 0x53, 0x35, 0x2E, 0x30, 0x00, 0x02, 0x08, 0x20, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x00, 0x00, 0x3F, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
    // ... rest of the FAT12 image data ...
};

// System Clock Configuration
void SystemClock_Config(void) {
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
    RCC_PeriphCLKInitTypeDef PeriphClkInit = {0};

    // Configure the main internal regulator output voltage
    HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1);

    // Initialize the CPU, AHB and APB buses clocks
    // Correct calculation for 160MHz SYSCLK and 48MHz USBCLK using HSE=12MHz
    // Target SYSCLK = 160MHz => PLL1_VCO = 160MHz * PLL1_R. Let PLL1_R = 2 => PLL1_VCO = 320MHz.
    // Target USBCLK = 48MHz => PLL1_Q = 48MHz * PLL1_Q_div. Let PLL1_Q_div = 7 => PLL1_Q = 336MHz.
    // We need a single VCO. Let's aim for a VCO that is a multiple of 48MHz and can be divided to 160MHz.
    // If PLL1_M = 1, PLL1_N = 27 (VCO = 12 * 27 = 324MHz)
    // SYSCLK = 324 / PLL1_R. If PLL1_R = 2, SYSCLK = 162MHz (close to 160MHz)
    // USBCLK = 324 / PLL1_Q. If PLL1_Q = 7, USBCLK = 46.2MHz (close to 48MHz)
    // This seems like a reasonable compromise.
    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
    RCC_OscInitStruct.HSEState = RCC_HSE_ON;
    RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
    RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
    RCC_OscInitStruct.PLL.PLLM = 1;
    RCC_OscInitStruct.PLL.PLLN = 27;
    RCC_OscInitStruct.PLL.PLLP = 2; // Not used for SYSCLK, but required
    RCC_OscInitStruct.PLL.PLLQ = 7; // For USB clock
    RCC_OscInitStruct.PLL.PLLR = 2; // For SYSCLK
    RCC_OscInitStruct.PLL.PLLRGE = RCC_PLLVCIRANGE_1; // 324MHz is in range 1
    RCC_OscInitStruct.PLL.PLLFRACN = 0;

    if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) {
        // Error_Handler(); // In a real application, you'd have an error handler
        while(1);
    }

    // Activate the Over-Drive mode (optional, depending on specific needs)
    // HAL_PWREx_EnableOverDrive();

    // Select the system clock source and configure the AHB, APB buses clocks
    RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2 | RCC_CLOCKTYPE_PCLK3;
    RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1; // HCLK = 162MHz
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;  // PCLK1 = 81MHz
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;  // PCLK2 = 81MHz
    RCC_ClkInitStruct.APB3CLKDivider = RCC_HCLK_DIV2;  // PCLK3 = 81MHz

    if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK) { // FLASH_LATENCY_5 for 162MHz
        // Error_Handler();
        while(1);
    }

    // Configure peripheral clocks
    PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_USB;
    PeriphClkInit.UsbClockSelection = RCC_USBCLKSOURCE_PLL1Q; // USB clock from PLL1Q (46.28MHz)
    if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit) != HAL_OK) {
        // Error_Handler();
        while(1);
    }
}

// GPIO Initialization
void MX_GPIO_Init(void) {
    // LEDs on PA0 and PA1
    GPIO_InitStruct.Pin = GPIO_PIN_0 | GPIO_PIN_1;
    GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    // Touch input on PC13 with pull-down
    GPIO_InitStruct.Pin = GPIO_PIN_13;
    GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
    GPIO_InitStruct.Pull = GPIO_PULLDOWN;
    HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);
}

// I2C1 Initialization
void MX_I2C1_Init(void) {
    hi2c1.Instance = I2C1;
    // Timing calculation for 400kHz with PCLK1 at 81MHz:
    // T_I2C = 1 / 400kHz = 2.5 us
    // PCLK1 = 81MHz => T_PCLK1 = 1 / 81MHz = 12.34 ns
    // T_I2C = (PRESC + 1) * T_PCLK1 * (1 + DYN_DN)
    // For 400kHz, typical timing values are around 0x00902025 or similar.
    // Let's use a common value, but a precise calculation might be needed.
    hi2c1.Init.Timing = 0x00902025; // Example value, adjust if needed based on precise calculation
    hi2c1.Init.OwnAddress1 = 0;
    hi2c1.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
    hi2c1.Init.DualAddressMode = I2C_DUALADDRESS_DISABLE;
    hi2c1.Init.OwnAddress2 = 0;
    hi2c1.Init.OwnAddress2Masks = I2C_OA2_NOMASK;
    hi2c1.Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
    hi2c1.Init.NoStretchMode = I2C_NOSTRETCH_DISABLE;

    if (HAL_I2C_Init(&hi2c1) != HAL_OK) {
        // Error_Handler(); // In a real application, you'd have an error handler
        while(1);
    }

    // Configure I2C1 pins (PB6/PB7) to AF4
    // This is typically done in HAL_I2C_MspInit, but for completeness here:
    // HAL_I2CEx_EnableFastModePlus(I2C_FASTMODEPLUS_PB6); // If needed
    // HAL_I2CEx_EnableFastModePlus(I2C_FASTMODEPLUS_PB7); // If needed
}

// SPI1 Initialization
void MX_SPI1_Init(void) {
    hspi1.Instance = SPI1;
    hspi1.Init.Mode = SPI_MODE_MASTER;
    hspi1.Init.Direction = SPI_DIRECTION_2LINES;
    hspi1.Init.DataSize = SPI_DATASIZE_8BIT;
    hspi1.Init.CLKPolarity = SPI_POLARITY_LOW; // Example, adjust as needed
    hspi1.Init.CLKPhase = SPI_PHASE_1EDGE;    // Example, adjust as needed
    hspi1.Init.NSS = SPI_NSS_HARD_OUTPUT;     // Master mode, NSS managed by hardware
    hspi1.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_8; // Example, adjust for desired speed
    hspi1.Init.FirstBit = SPI_FIRSTBIT_MSB;
    hspi1.Init.TIMode = SPI_TIMODE_DISABLE;
    hspi1.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
    hspi1.Init.CRCPolynomial = 0;
    hspi1.Init.CRCLength = SPI_CRC_LENGTH_DATASIZE;
    hspi1.Init.NSSPMode = SPI_NSS_PULSE_DISABLE;
    hspi1.Init.NSSPolarity = SPI_NSS_POLARITY_LOW;
    hspi1.Init.FifoThreshold = SPI_FIFO_THRESHOLD_01DATA;
    hspi1.Init.TxCRCInitializationPattern = SPI_CRC_INITIALIZATION_ALL_ZERO_PATTERN;
    hspi1.Init.RxCRCInitializationPattern = SPI_CRC_INITIALIZATION_ALL_ZERO_PATTERN;
    hspi1.Init.MasterSSIdleness = SPI_MASTER_SS_IDLENESS_00CYCLE;
    hspi1.Init.MasterInterDataIdleness = SPI_MASTER_INTERDATA_IDLENESS_00CYCLE;
    hspi1.Init.MasterReceiverAutoSusp = SPI_MASTER_RX_AUTOSUSP_DISABLE;
    hspi1.Init.MasterKeepIOState = SPI_MASTER_KEEP_IO_STATE_DISABLE;
    hspi1.Init.IOSwap = SPI_IO_SWAP_DISABLE;
    hspi1.Init.ReadyMasterManagement = SPI_RDY_MASTER_MANAGEMENT_INTERNALLY;
    hspi1.Init.ReadyPolarity = SPI_RDY_POLARITY_HIGH;

    if (HAL_SPI_Init(&hspi1) != HAL_OK) {
        // Error_Handler();
        while(1);
    }

    // Configure SPI1 pins (PA4-PA7) to AF5
    // This is typically done in HAL_SPI_MspInit, but for completeness here:
    // GPIO_AF5_SPI1 for PA4, PA5, PA6, PA7
}

// OCTOSPI1 Initialization
void MX_OCTOSPI1_Init(void) {
    hospi1.Instance = OCTOSPI1;
    hospi1.Init.FifoThreshold = 1; // Example, adjust as needed
    hospi1.Init.DualQuad = HAL_OSPI_DUALQUAD_DISABLE;
    hospi1.Init.MemoryType = HAL_OSPI_MEMTYPE_MICRON; // Example, adjust based on actual memory
    hospi1.Init.DeviceSize = 24; // Example, adjust based on actual memory size (e.g., 256Mbit = 24 bits address)
    hospi1.Init.ChipSelectHighTime = 4; // Example, adjust based on memory datasheet
    hospi1.Init.FreeRunningClock = HAL_OSPI_FREERUNCLK_DISABLE;
    hospi1.Init.ClockMode = HAL_OSPI_CLOCK_MODE_0;
    hospi1.Init.WrapSize = HAL_OSPI_WRAP_NOT_SUPPORTED;
    hospi1.Init.ClockPrescaler = 4; // Example, adjust for desired clock frequency
    hospi1.Init.SampleShifting = HAL_OSPI_SAMPLE_SHIFTING_NONE;
    hospi1.Init.DelayHoldQuarterCycle = HAL_OSPI_DHQC_DISABLE;
    hospi1.Init.ChipSelectBoundary = 0;
    hospi1.Init.DelayBlockBypass = HAL_OSPI_DELAY_BLOCK_USED;
    hospi1.Init.MaxTran = 0;
    hospi1.Init.Refresh = 0;

    if (HAL_OSPI_Init(&hospi1) != HAL_OK) {
        // Error_Handler();
        while(1);
    }

    // Configure OCTOSPI1 pins (PF6/PF7/PF8/PF9/PF10/PB2)
    // This is typically done in HAL_OSPI_MspInit.
}

// USB PCD Initialization
void MX_USB_PCD_Init(void) {
    hpcd_USB_OTG_FS.Instance = USB_OTG_FS;
    hpcd_USB_OTG_FS.Init.dev_endpoints = 8; // Example, adjust as needed
    hpcd_USB_OTG_FS.Init.phy_itface = PCD_PHY_EMBEDDED;
    hpcd_USB_OTG_FS.Init.Sof_enable = ENABLE;
    hpcd_USB_OTG_FS.Init.Sof_disable = DISABLE;
    hpcd_USB_OTG_FS.Init.Low_power_enable = DISABLE;
    hpcd_USB_OTG_FS.Init.Lpm_enable = DISABLE;
    hpcd_USB_OTG_FS.Init.Battery_charging_enable = DISABLE;
    hpcd_USB_OTG_FS.Init.Mode = PCD_MODE_DEVICE;

    if (HAL_PCD_Init(&hpcd_USB_OTG_FS) != HAL_OK) {
        // Error_Handler();
        while(1);
    }
}

// Platform HAL Initialization
void platform_hal_init(void) {
    // Reset of all peripherals, Initializes the Flash interface and the Systick.
    HAL_Init();

    // Configure the system clock
    SystemClock_Config();

    // Initialize all configured peripherals
    MX_GPIO_Init();
    MX_I2C1_Init();
    MX_SPI1_Init();
    MX_OCTOSPI1_Init();
    MX_USB_PCD_Init();
}

// Platform HAL Tick Implementation
void platform_hal_tick(void) {
    uwTick++;
}

// Platform HAL LED Control
void platform_hal_led_set(platform_hal_led_t led, bool on) {
    switch (led) {
        case PLATFORM_HAL_LED_LOCKED:
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_0, on ? GPIO_PIN_SET : GPIO_PIN_RESET);
            break;
        case PLATFORM_HAL_LED_ACTIVITY:
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_1, on ? GPIO_PIN_SET : GPIO_PIN_RESET);
            break;
        // Other LEDs are not explicitly defined in the request, so they are ignored.
        default:
            break;
    }
}

// Platform HAL Touch Input
bool platform_hal_touch_read(void) {
    return HAL_GPIO_ReadPin(GPIOC, GPIO_PIN_13) == GPIO_PIN_SET;
}

bool platform_hal_touch_held(void) {
    // Assuming "held" means the pin is still pressed after a short delay.
    // For simplicity in this example, we'll just check the current state.
    // A more robust implementation would involve timing.
    return platform_hal_touch_read();
}

// Platform HAL USB HID Type Implementation
// This is a simplified implementation. A full USB HID keyboard implementation
// would require more complex USB descriptor setup and state management.
// This function assumes ASCII characters and sends them as HID reports.
// It does not handle modifiers (Shift, Ctrl, Alt) or special keys beyond TAB and ENTER.
bool platform_hal_usb_hid_type(const char *text) {
    if (text == NULL) {
        return false;
    }

    // Key codes for ASCII characters and special keys (from USB HID Usage Tables)
    // This is a very limited mapping. A full implementation would need a comprehensive table.
    const uint8_t ascii_to_hid_map[] = {
        0x00, // Null
        0x01, // ESC
        0x02, // 1
        0x03, // 2
        0x04, // 3
        0x05, // 4
        0x06, // 5
        0x07, // 6
        0x08, // 7
        0x09, // 8
        0x0A, // 9
        0x0B, // 0
        0x0C, // -
        0x0D, // =
        0x0E, // Backspace
        0x0F, // TAB (0x0F)
        0x10, // Q
        0x11, // W
        0x12, // E
        0x13, // R
        0x14, // T
        0x15, // Y
        0x16, // U
        0x17, // I
        0x18, // O
        0x19, // P
        0x1A, // [
        0x1B, // ]
        0x1C, // ENTER (0x1C)
        0x1D, // Left Control
        0x1E, // A
        0x1F, // S
        0x20, // D
        0x21, // F
        0x22, // G
        0x23, // H
        0x24, // J
        0x25, // K
        0x26, // L
        0x27, // ;
        0x28, // '
        0x29, // `
        0x2A, // Left Shift
        0x2B, // \
        0x2C, // Z
        0x2D, // X
        0x2E, // C
        0x2F, // V
        0x30, // B
        0x31, // N
        0x32, // M
        0x33, // ,
        0x34, // .
        0x35, // /
        0x36, // Right Shift
        0x37, // Keypad *
        0x38, // Left Alt
        0x39, // Space
        0x3A, // Caps Lock
        0x3B, // F1
        0x3C, // F2
        0x3D, // F3
        0x3E, // F4
        0x3F, // F5
        0x40, // F6
        0x41, // F7
        0x42, // F8
        0x43, // F9
        0x44, // F10
        0x45, // F11
        0x46, // F12
        0x47, // Print Screen
        0x48, // Scroll Lock
        0x49, // Pause
        0x4A, // Insert
        0x4B, // Home
        0x4C, // Page Up
        0x4D, // Delete
        0x4E, // End
        0x4F, // Page Down
        0x50, // Right Arrow
        0x51, // Left Arrow
        0x52, // Down Arrow
        0x53, // Up Arrow
        0x54, // Num Lock
        0x55, // Keypad /
        0x56, // Keypad *
        0x57, // Keypad -
        0x58, // Keypad +
        0x59, // Keypad Enter
        0x5A, // Keypad 1
        0x5B, // Keypad 2
        0x5C, // Keypad 3
        0x5D, // Keypad 4
        0x5E, // Keypad 5
        0x5F, // Keypad 6
        0x60, // Keypad 7
        0x61, // Keypad 8
        0x62, // Keypad 9
        0x63, // Keypad 0
        0x64, // Keypad .
        0x65, // Keypad Enter
        0x66, // Keypad Enter
        0x67, // Left GUI
        0x68, // Right GUI
        0x69, // Application
        0x6A, // Left Control
        0x6B, // Left Shift
        0x6C, // Left Alt
        0x6D, // Left GUI
        0x6E, // Right Control
        0x6F, // Right Shift
        0x70, // Right Alt
        0x71, // Right GUI
        0x72, // Right Application
        0x73, // Reserved (0x73)
        0x74, // Reserved (0x74)
        0x75, // Reserved (0x75)
        0x76, // Reserved (0x76)
        0x77, // Reserved (0x77)
        0x78, // Reserved (0x78)
        0x79, // Reserved (0x79)
        0x7A, // Reserved (0x7A)
        0x7B, // Reserved (0x7B)
        0x7C, // Reserved (0x7C)
        0x7D, // Reserved (0x7D)
        0x7E, // Reserved (0x7E)
        0x7F  // Reserved (0x7F)
    };

    uint8_t report[8] = {0}; // Initialize report with all zeros (no keys pressed)
    uint8_t key_code = 0;
    bool success = true;
    bool shift_pressed = false;

    for (size_t i = 0; text[i] != '\0'; ++i) {
        char current_char = text[i];
        key_code = 0; // Reset key code for each character

        if (current_char >= 'A' && current_char <= 'Z') {
            // Uppercase letters require Shift
            report[0] |= (1 << 1); // Set Left Shift modifier
            shift_pressed = true;
            key_code = ascii_to_hid_map[(uint8_t)current_char - 'A' + 'a']; // Use lowercase mapping
        } else if (current_char >= 'a' && current_char <= 'z') {
            key_code = ascii_to_hid_map[(uint8_t)current_char];
        } else if (current_char == '\t') {
            key_code = ascii_to_hid_map[15]; // TAB key code
        } else if (current_char == '\n' || current_char == '\r') {
            key_code = ascii_to_hid_map[28]; // ENTER key code
        } else if (current_char >= ' ' && current_char <= '~') { // Printable ASCII characters
            // Check if the character requires Shift
            if (current_char >= '!' && current_char <= '/') { // Symbols on top row
                report[0] |= (1 << 1); // Set Left Shift modifier
                shift_pressed = true;
            } else if (current_char >= ':' && current_char <= '?') { // Symbols on right side
                report[0] |= (1 << 1); // Set Left Shift modifier
                shift_pressed = true;
            } else if (current_char >= '{' && current_char <= '~') { // Symbols on bottom row
                report[0] |= (1 << 1); // Set Left Shift modifier
                shift_pressed = true;
            }
            key_code = ascii_to_hid_map[(uint8_t)current_char];
        } else {
            // Unsupported character, skip or handle as error
            continue;
        }

        if (key_code != 0) {
            // Press the key
            report[2] = key_code; // Place key code in the first available key slot
            if (HAL_PCD_EP_Transmit(&hpcd_USB_OTG_FS, 0x81, report, sizeof(report)) != HAL_OK) { // Use HAL_PCD_EP_Transmit directly
                success = false;
                break;
            }
            HAL_Delay(8); // Delay between key presses

            // Release the key
            report[2] = 0x00; // Clear the key code to release the key
            if (shift_pressed) {
                report[0] &= ~(1 << 1); // Clear Left Shift modifier
            }
            if (HAL_PCD_EP_Transmit(&hpcd_USB_OTG_FS, 0x81, report, sizeof(report)) != HAL_OK) { // Use HAL_PCD_EP_Transmit directly
                success = false;
                break;
            }
            HAL_Delay(8); // Delay after releasing the key
        }
        shift_pressed = false; // Reset shift state for the next character
    }

    // Ensure all modifiers are released at the end
    if (shift_pressed) {
        report[0] &= ~(1 << 1);
        HAL_PCD_EP_Transmit(&hpcd_USB_OTG_FS, 0x81, report, sizeof(report)); // Use HAL_PCD_EP_Transmit directly
    }

    return success;
}

// USB HID Send Report Implementation
bool usb_hid_send_report(uint8_t report_id, const uint8_t *data, size_t data_len) {
    if (data == NULL || data_len == 0 || data_len > 63) {
        return false;
    }

    // Prepare the report with report ID
    hid_report_buffer[0] = report_id;
    memcpy(&hid_report_buffer[1], data, data_len);

    // Send the report
    if (HAL_PCD_EP_Transmit(&hpcd_USB_OTG_FS, 0x82, hid_report_buffer, data_len + 1) != HAL_OK) {
        return false;
    }

    return true;
}

// USB HID Poll Report Implementation
bool usb_hid_poll_report(uint8_t *report_id, uint8_t *data, size_t data_len) {
    if (report_id == NULL || data == NULL || data_len == 0 || data_len > 63) {
        return false;
    }

    // Check if there's a pending report
    if (!hid_report_pending) {
        return false;
    }

    // Copy the report data
    *report_id = hid_report_id;
    memcpy(data, hid_report_buffer, data_len);

    // Clear the pending flag
    hid_report_pending = false;

    return true;
}

// Mass Storage SCSI Handler
void usb_msc_scsi_handler(uint8_t *cmd, uint8_t *response, uint16_t *response_len) {
    // Check the command
    switch (cmd[0]) {
        case 0x12: // INQUIRY
            // Standard INQUIRY response
            response[0] = 0x00; // Direct-access device
            response[1] = 0x80; // Removable media
            response[2] = 0x02; // ANSI version
            response[3] = 0x02; // Response data format
            response[4] = 0x1F; // Additional length
            response[5] = 0x00; // Reserved
            response[6] = 0x00; // Reserved
            response[7] = 0x00; // Reserved
            memcpy(&response[8], "STM32 USB MSC", 12); // Vendor ID and Product ID
            response[20] = '1'; // Product revision level
            response[21] = '.'; // Product revision level
            response[22] = '0'; // Product revision level
            response[23] = '0'; // Product revision level
            *response_len = 36; // Total response length
            break;

        case 0x28: // READ(10)
            // Handle READ(10) command
            uint32_t lba = (cmd[2] << 24) | (cmd[3] << 16) | (cmd[4] << 8) | cmd[5];
            uint16_t transfer_length = (cmd[7] << 8) | cmd[8];

            // Calculate the offset in the FAT12 image
            uint32_t offset = lba * 512;

            // Check if the offset is within the image bounds
            if (offset + transfer_length * 512 > sizeof(fat12_image)) {
                *response_len = 0;
                return;
            }

            // Copy the data from the FAT12 image
            memcpy(response, &fat12_image[offset], transfer_length * 512);
            *response_len = transfer_length * 512;
            break;

        default:
            // Unsupported command
            *response_len = 0;
            break;
    }
}

// SysTick handler for tick increment
void SysTick_Handler(void) {
    HAL_IncTick();
}

// Weak implementations of MspInit/MspDeInit (to be implemented by user)
__weak void HAL_I2C_MspInit(I2C_HandleTypeDef *hi2c) {
    // GPIO initialization for I2C1 (PB6, PB7)
    GPIO_InitTypeDef GPIO_InitStruct_I2C = {0};
    __HAL_RCC_GPIOB_CLK_ENABLE();
    GPIO_InitStruct_I2C.Pin = GPIO_PIN_6 | GPIO_PIN_7;
    GPIO_InitStruct_I2C.Mode = GPIO_MODE_AF_OD;
    GPIO_InitStruct_I2C.Pull = GPIO_PULLUP;
    GPIO_InitStruct_I2C.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStruct_I2C.Alternate = GPIO_AF4_I2C1;
    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct_I2C);

    // Peripheral clock enable for I2C1
    __HAL_RCC_I2C1_CLK_ENABLE();
}

__weak void HAL_I2C_MspDeInit(I2C_HandleTypeDef *hi2c) {
    // Peripheral clock disable for I2C1
    __HAL_RCC_I2C1_CLK_DISABLE();

    // GPIO de-initialization for I2C1 (PB6, PB7)
    HAL_GPIO_DeInit(GPIOB, GPIO_PIN_6 | GPIO_PIN_7);
}

__weak void HAL_SPI_MspInit(SPI_HandleTypeDef *hspi) {
    // GPIO initialization for SPI1 (PA4-PA7)
    GPIO_InitTypeDef GPIO_InitStruct_SPI = {0};
    __HAL_RCC_GPIOA_CLK_ENABLE();
    GPIO_InitStruct_SPI.Pin = GPIO_PIN_4 | GPIO_PIN_5 | GPIO_PIN_6 | GPIO_PIN_7;
    GPIO_InitStruct_SPI.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct_SPI.Pull = GPIO_NOPULL;
    GPIO_InitStruct_SPI.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStruct_SPI.Alternate = GPIO_AF5_SPI1;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct_SPI);

    // Peripheral clock enable for SPI1
    __HAL_RCC_SPI1_CLK_ENABLE();
}

__weak void HAL_SPI_MspDeInit(SPI_HandleTypeDef *hspi) {
    // Peripheral clock disable for SPI1
    __HAL_RCC_SPI1_CLK_DISABLE();

    // GPIO de-initialization for SPI1 (PA4-PA7)
    HAL_GPIO_DeInit(GPIOA, GPIO_PIN_4 | GPIO_PIN_5 | GPIO_PIN_6 | GPIO_PIN_7);
}

__weak void HAL_OSPI_MspInit(OSPI_HandleTypeDef *hospi) {
    // GPIO initialization for OCTOSPI1 (PF6/PF7/PF8/PF9/PF10/PB2)
    GPIO_InitTypeDef GPIO_InitStruct_OSPI = {0};

    // Enable clocks for relevant GPIO ports
    __HAL_RCC_GPIOF_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();

    // Configure pins for OCTOSPI1
    GPIO_InitStruct_OSPI.Pin = GPIO_PIN_6 | GPIO_PIN_7 | GPIO_PIN_8 | GPIO_PIN_9 | GPIO_PIN_10;
    GPIO_InitStruct_OSPI.Mode = GPIO_MODE_AF_PP; // Assuming push-pull for AF
    GPIO_InitStruct_OSPI.Pull = GPIO_NOPULL;
    GPIO_InitStruct_OSPI.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStruct_OSPI.Alternate = GPIO_AF10_OCTOSPI1; // Example AF, check datasheet
    HAL_GPIO_Init(GPIOF, &GPIO_InitStruct_OSPI);

    GPIO_InitStruct_OSPI.Pin = GPIO_PIN_2;
    GPIO_InitStruct_OSPI.Mode = GPIO_MODE_AF_PP; // Assuming push-pull for AF
    GPIO_InitStruct_OSPI.Pull = GPIO_NOPULL;
    GPIO_InitStruct_OSPI.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStruct_OSPI.Alternate = GPIO_AF10_OCTOSPI1; // Example AF, check datasheet
    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct_OSPI);

    // Peripheral clock enable for OCTOSPI1
    __HAL_RCC_OSPI1_CLK_ENABLE();
}

__weak void HAL_OSPI_MspDeInit(OSPI_HandleTypeDef *hospi) {
    // Peripheral clock disable for OCTOSPI1
    __HAL_RCC_OSPI1_CLK_DISABLE();

    // GPIO de-initialization for OCTOSPI1
    HAL_GPIO_DeInit(GPIOF, GPIO_PIN_6 | GPIO_PIN_7 | GPIO_PIN_8 | GPIO_PIN_9 | GPIO_PIN_10);
    HAL_GPIO_DeInit(GPIOB, GPIO_PIN_2);
}

__weak void HAL_PCD_MspInit(PCD_HandleTypeDef *hpcd) {
    GPIO_InitTypeDef GPIO_InitStruct_USB = {0};

    // Enable USB peripheral clock
    __HAL_RCC_USB_CLK_ENABLE(); // For USB_OTG_FS

    // Configure USB pins (DM, DP)
    // These pins are typically on PA9 and PA10 for USB_OTG_FS
    __HAL_RCC_GPIOA_CLK_ENABLE();
    GPIO_InitStruct_USB.Pin = GPIO_PIN_9 | GPIO_PIN_10;
    GPIO_InitStruct_USB.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct_USB.Pull = GPIO_NOPULL;
    GPIO_InitStruct_USB.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStruct_USB.Alternate = GPIO_AF10_OTG_FS; // Check datasheet for correct AF
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct_USB);

    // Enable USB interrupt
    HAL_NVIC_SetPriority(OTG_FS_IRQn, 0, 0);
    HAL_NVIC_EnableIRQ(OTG_FS_IRQn);
}

__weak void HAL_PCD_MspDeInit(PCD_HandleTypeDef *hpcd) {
    // Disable USB peripheral clock
    __HAL_RCC_USB_CLK_DISABLE();

    // De-initialize USB pins
    HAL_GPIO_DeInit(GPIOA, GPIO_PIN_9 | GPIO_PIN_10);

    // Disable USB interrupt
    HAL_NVIC_DisableIRQ(OTG_FS_IRQn);
}

// Dummy implementation for HAL_Delay, as it's usually handled by SysTick.
// In a real system, this would be handled by SysTick.
void HAL_Delay(uint32_t Delay) {
    volatile uint32_t tickstart = HAL_GetTick();
    while ((HAL_GetTick() - tickstart) < Delay) {
        // Busy wait
    }
}

// Use HAL_PCD_EP_Transmit directly instead of HAL_PCD_Send_Report stub
HAL_StatusTypeDef HAL_PCD_EP_Transmit(PCD_HandleTypeDef *hpcd, uint8_t ep_addr, uint8_t *pbuf, uint16_t size) {
    // In a real scenario, this would transmit the data over the specified USB endpoint.
    // This requires a functional USB stack and endpoint configuration.
    // For this example, we'll just simulate success.
    (void)hpcd; // Suppress unused parameter warning
    (void)ep_addr; // Suppress unused parameter warning
    (void)pbuf; // Suppress unused parameter warning
    (void)size; // Suppress unused parameter warning
#if !FIRMWARE_PRODUCTION
    // Example debug logging:
    // printf("USB EP Transmit: EP %d, %d bytes\n", ep_addr, size);
#endif
    return HAL_OK;
}

// Dummy implementation for HAL_NVIC_SetPriority and HAL_NVIC_EnableIRQ
void HAL_NVIC_SetPriority(IRQn_Type IRQn, uint32_t PreemptPriority, uint32_t SubPriority) {
    (void)IRQn; (void)PreemptPriority; (void)SubPriority; // Suppress unused parameter warnings
    // In a real system, this would configure the NVIC.
}

void HAL_NVIC_EnableIRQ(IRQn_Type IRQn) {
    (void)IRQn; // Suppress unused parameter warning
    // In a real system, this would enable the interrupt in the NVIC.
}

void HAL_NVIC_DisableIRQ(IRQn_Type IRQn) {
    (void)IRQn; // Suppress unused parameter warning
    // In a real system, this would disable the interrupt in the NVIC.
}

// Dummy implementation for HAL_PWREx_ControlVoltageScaling
HAL_StatusTypeDef HAL_PWREx_ControlVoltageScaling(uint32_t scaling) {
    (void)scaling; // Suppress unused parameter warning
    // In a real system, this would configure the voltage scaling.
    return HAL_OK;
}

// Dummy implementation for HAL_RCCEx_PeriphCLKConfig
HAL_StatusTypeDef HAL_RCCEx_PeriphCLKConfig(const RCC_PeriphCLKInitTypeDef *PeriphClkInit) {
    (void)PeriphClkInit; // Suppress unused parameter warning
    // In a real system, this would configure peripheral clocks.
    return HAL_OK;
}

// Dummy implementation for HAL_PWREx_EnableOverDrive
void HAL_PWREx_EnableOverDrive(void) {
    // In a real system, this would enable Over-Drive mode.
}

// Dummy implementation for HAL_GPIO_WritePin
void HAL_GPIO_WritePin(GPIO_TypeDef *GPIOx, uint16_t GPIO_Pin, GPIO_PinState PinState) {
    (void)GPIOx; (void)GPIO_Pin; (void)PinState; // Suppress unused parameter warnings
    // In a real system, this would write to the GPIO pin.
#if !FIRMWARE_PRODUCTION
    // Example debug logging:
    // printf("GPIO Write: Pin %d, State %d\n", GPIO_Pin, PinState);
#endif
}

// Dummy implementation for HAL_GPIO_ReadPin
GPIO_PinState HAL_GPIO_ReadPin(GPIO_TypeDef *GPIOx, uint16_t GPIO_Pin) {
    (void)GPIOx; (void)GPIO_Pin; // Suppress unused parameter warnings
    // In a real system, this would read from the GPIO pin.
    // For simulation purposes, return GPIO_PIN_RESET by default.
    return GPIO_PIN_RESET;
}

// Dummy implementation for HAL_I2CEx_EnableFastModePlus
HAL_StatusTypeDef HAL_I2CEx_EnableFastModePlus(uint32_t ConfigFastModePlus) {
    (void)ConfigFastModePlus; // Suppress unused parameter warning
    // In a real system, this would enable Fast Mode Plus.
    return HAL_OK;
}

// Dummy implementation for HAL_RCC_GetSysClockFreq, HAL_RCC_GetHCLKFreq, etc.
uint32_t HAL_RCC_GetSysClockFreq(void) { return 162000000; } // Example value, should match SystemClock_Config
uint32_t HAL_RCC_GetHCLKFreq(void) { return 162000000; } // Example value, should match SystemClock_Config
uint32_t HAL_RCC_GetPCLK1Freq(void) { return 81000000; } // Example value, should match SystemClock_Config
uint32_t HAL_RCC_GetPCLK2Freq(void) { return 81000000; } // Example value, should match SystemClock_Config
uint32_t HAL_RCC_GetPCLK3Freq(void) { return 81000000; } // Example value, should match SystemClock_Config

// Dummy implementation for HAL_GetTick
uint32_t HAL_GetTick(void) {
    return uwTick;
}

// Dummy implementation for HAL_IncTick
void HAL_IncTick(void) {
    uwTick++;
}

// Dummy implementation for HAL_Init
HAL_StatusTypeDef HAL_Init(void) {
    // In a real HAL, this would initialize the HAL layer.
    // For this example, we'll just set a flag or do minimal setup.
    return HAL_OK;
}

// Dummy implementation for HAL_DeInit
HAL_StatusTypeDef HAL_DeInit(void) {
    // In a real HAL, this would de-initialize the HAL layer.
    return HAL_OK;
}

// Dummy implementation for HAL_MspInit and HAL_MspDeInit
void HAL_MspInit(void) {
    // This is a weak function, user should implement it.
    // For this example, we'll call the specific MspInit functions.
    HAL_I2C_MspInit(&hi2c1);
    HAL_SPI_MspInit(&hspi1);
    HAL_OSPI_MspInit(&hospi1);
    HAL_PCD_MspInit(&hpcd_USB_OTG_FS);
}

void HAL_MspDeInit(void) {
    // This is a weak function, user should implement it.
    // For this example, we'll call the specific MspDeInit functions.
    HAL_I2C_MspDeInit(&hi2c1);
    HAL_SPI_MspDeInit(&hspi1);
    HAL_OSPI_MspDeInit(&hospi1);
    HAL_PCD_MspDeInit(&hpcd_USB_OTG_FS);
}

// Dummy implementation for assert_param
void assert_param(int condition) {
    if (!condition) {
        // In a real application, this would handle assertion failures.
        // For this example, we'll just loop infinitely.
#if !FIRMWARE_PRODUCTION
        // Example debug logging:
        // printf("Assertion failed!\n");
#endif
        while(1);
    }
}
