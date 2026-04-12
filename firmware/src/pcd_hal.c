#include "pcd_hal.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "stm32u5xx_hal.h"
#include "stm32u5xx_hal_pcd.h"

// Forward declarations for HAL callbacks
extern PCD_HandleTypeDef hpcd_USB_OTG_FS;
void HAL_PCD_DisconnectCallback(PCD_HandleTypeDef *hpcd);

// USB Descriptors
#define USB_DEVICE_DESCRIPTOR_TYPE 0x01
#define USB_CONFIGURATION_DESCRIPTOR_TYPE 0x02
#define USB_INTERFACE_DESCRIPTOR_TYPE 0x04
#define USB_HID_DESCRIPTOR_TYPE 0x21
#define USB_REPORT_DESCRIPTOR_TYPE 0x22

#define USB_MAX_EP0_SIZE 64
#define USB_MAX_EP_SIZE 64

#define HID_KEYBOARD_REPORT_SIZE 8
#define HID_KEYBOARD_IN_EP 0x81

#define HID_USAGE_PAGE_GENERIC_DESKTOP 0x01
#define HID_USAGE_KEYBOARD 0x06

#define CONFIG_DESC_TOTAL_LEN (9 + 9 + 9 + 7) // Device, Config, Interface, HID

// Device Descriptor
static const uint8_t usb_device_descriptor[] = {
    USB_DESC_DEVICE_LEN,       // bLength
    USB_DEVICE_DESCRIPTOR_TYPE, // bDescriptorType
    0x01, 0x02,                // bcdUSB (1.1)
    0x00,                      // bDeviceClass (defined at interface level)
    0x00,                      // bDeviceSubClass (defined at interface level)
    0x00,                      // bDeviceProtocol (defined at interface level)
    USB_MAX_EP0_SIZE,          // bMaxPacketSize0
    0x12, 0x34,                // idVendor
    0x56, 0x78,                // idProduct
    0x00, 0x01,                // bcdDevice (1.0)
    0x01,                      // iManufacturer
    0x02,                      // iProduct
    0x03,                      // iSerialNumber
    0x01                       // bNumConfigurations
};

// Configuration Descriptor
static const uint8_t usb_config_descriptor[] = {
    USB_DESC_CONFIG_LEN,       // bLength
    USB_CONFIGURATION_DESCRIPTOR_TYPE, // bDescriptorType
    (uint8_t)(CONFIG_DESC_TOTAL_LEN & 0xFF), // wTotalLength (low byte)
    (uint8_t)(CONFIG_DESC_TOTAL_LEN >> 8),  // wTotalLength (high byte)
    0x01,                      // bNumInterfaces
    0x01,                      // bConfigurationValue
    0x00,                      // iConfiguration
    0x80,                      // bmAttributes (Self-powered)
    0x32                       // bMaxPower (100mA)
};

// Interface Descriptor
static const uint8_t usb_interface_descriptor[] = {
    USB_DESC_INTERFACE_LEN,    // bLength
    USB_INTERFACE_DESCRIPTOR_TYPE, // bDescriptorType
    0x00,                      // bInterfaceNumber
    0x00,                      // bAlternateSetting
    0x01,                      // bNumEndpoints
    0x03,                      // bInterfaceClass (HID)
    0x01,                      // bInterfaceSubClass (Boot Interface Protocol)
    0x01,                      // bInterfaceProtocol (Keyboard)
    0x00                       // iInterface
};

// HID Descriptor
static const uint8_t usb_hid_descriptor[] = {
    USB_DESC_HID_LEN,          // bLength
    USB_HID_DESCRIPTOR_TYPE,   // bDescriptorType
    0x01, 0x01,                // bcdHID (1.1)
    0x00,                      // bCountryCode
    0x01,                      // bNumDescriptors
    USB_REPORT_DESCRIPTOR_TYPE, // bDescriptorType
    (uint8_t)(sizeof(usb_hid_report_descriptor) & 0xFF), // wDescriptorLength (low byte)
    (uint8_t)(sizeof(usb_hid_report_descriptor) >> 8)   // wDescriptorLength (high byte)
};

// HID Report Descriptor (Keyboard)
static const uint8_t usb_hid_report_descriptor[] = {
    0x05, HID_USAGE_PAGE_GENERIC_DESKTOP, // Usage Page (Generic Desktop)
    0x19, HID_USAGE_KEYBOARD,             // Usage Minimum (Keyboard)
    0x29, HID_USAGE_KEYBOARD,             // Usage Maximum (Keyboard)
    0x15, 0x00,                           // Logical Minimum (0)
    0x25, 0x01,                           // Logical Maximum (1)
    0x75, 0x01,                           // Report Size (1 byte)
    0x95, 0x08,                           // Report Count (8 bytes)
    0x81, 0x02,                           // Input (Data, Var, Abs) - Modifier byte
    0x95, 0x01,                           // Report Count (1 byte)
    0x75, 0x08,                           // Report Size (8 bytes)
    0x81, 0x03,                           // Input (Cnst, Var, Abs) - Reserved byte
    0x95, 0x05,                           // Report Count (5 bytes)
    0x75, 0x01,                           // Report Size (1 byte)
    0x05, 0x07,                           // Usage Page (Key Codes)
    0x19, 0x00,                           // Usage Minimum (0)
    0x29, 0x65,                           // Usage Maximum (101)
    0x81, 0x00,                           // Input (Data, Arr, Abs) - Key codes (up to 5)
    0xc0                                  // End Collection
};

// ASCII to HID Keycode Mapping
// This table maps ASCII characters to their corresponding HID keycodes.
// It includes standard alphanumeric characters, symbols, and some control keys.
// Entries are 2 bytes: {modifier, keycode}. 0x00, 0x00 means no mapping.
static const uint8_t ascii_to_hid_map[128][2] = {
    {0x00, 0x00}, // 0x00 NUL
    {0x00, 0x00}, // 0x01 SOH
    {0x00, 0x00}, // 0x02 STX
    {0x00, 0x00}, // 0x03 ETX
    {0x00, 0x00}, // 0x04 EOT
    {0x00, 0x00}, // 0x05 ENQ
    {0x00, 0x00}, // 0x06 ACK
    {0x00, 0x00}, // 0x07 BEL
    {0x00, 0x00}, // 0x08 BS
    {0x00, 0x00}, // 0x09 HT
    {0x00, 0x00}, // 0x0A LF
    {0x00, 0x00}, // 0x0B VT
    {0x00, 0x00}, // 0x0C FF
    {0x00, 0x00}, // 0x0D CR
    {0x00, 0x00}, // 0x0E SI
    {0x00, 0x00}, // 0x0F SO
    {0x00, 0x00}, // 0x10 DLE
    {0x00, 0x00}, // 0x11 DC1
    {0x00, 0x00}, // 0x12 DC2
    {0x00, 0x00}, // 0x13 DC3
    {0x00, 0x00}, // 0x14 DC4
    {0x00, 0x00}, // 0x15 NAK
    {0x00, 0x00}, // 0x16 SYN
    {0x00, 0x00}, // 0x17 ETB
    {0x00, 0x00}, // 0x18 CAN
    {0x00, 0x00}, // 0x19 EM
    {0x00, 0x00}, // 0x1A SUB
    {0x00, 0x00}, // 0x1B ESC
    {0x00, 0x00}, // 0x1C FS
    {0x00, 0x00}, // 0x1D GS
    {0x00, 0x00}, // 0x1E RS
    {0x00, 0x00}, // 0x1F US
    {0x00, 0x20}, // 0x20 Space
    {0x02, 0x11}, // 0x21 ! (Shift + 1)
    {0x00, 0x22}, // 0x22 " (Shift + ')
    {0x04, 0x21}, // 0x23 # (Shift + 3)
    {0x04, 0x27}, // 0x24 $ (Shift + 4)
    {0x04, 0x2B}, // 0x25 % (Shift + 5)
    {0x04, 0x25}, // 0x26 & (Shift + 7)
    {0x02, 0x27}, // 0x27 '
    {0x04, 0x29}, // 0x28 ( (Shift + 9)
    {0x04, 0x28}, // 0x29 ) (Shift + 0)
    {0x04, 0x37}, // 0x2A * (Shift + 8)
    {0x04, 0x2A}, // 0x2B + (Shift + =)
    {0x00, 0x33}, // 0x2C ,
    {0x00, 0x2D}, // 0x2D -
    {0x00, 0x34}, // 0x2E .
    {0x00, 0x35}, // 0x2F /
    {0x00, 0x0B}, // 0x30 0
    {0x00, 0x02}, // 0x31 1
    {0x00, 0x03}, // 0x32 2
    {0x00, 0x04}, // 0x33 3
    {0x00, 0x05}, // 0x34 4
    {0x00, 0x06}, // 0x35 5
    {0x00, 0x07}, // 0x36 6
    {0x00, 0x08}, // 0x37 7
    {0x00, 0x09}, // 0x38 8
    {0x00, 0x0A}, // 0x39 9
    {0x04, 0x36}, // 0x3A : (Shift + ;)
    {0x04, 0x33}, // 0x3B ;
    {0x04, 0x30}, // 0x3C < (Shift + ,)
    {0x00, 0x2D}, // 0x3D =
    {0x04, 0x32}, // 0x3E > (Shift + .)
    {0x04, 0x31}, // 0x3F ? (Shift + /)
    {0x04, 0x02}, // 0x40 @ (Shift + 2)
    {0x02, 0x02}, // 0x41 A
    {0x02, 0x03}, // 0x42 B
    {0x02, 0x04}, // 0x43 C
    {0x02, 0x05}, // 0x44 D
    {0x02, 0x06}, // 0x45 E
    {0x02, 0x07}, // 0x46 F
    {0x02, 0x08}, // 0x47 G
    {0x02, 0x09}, // 0x48 H
    {0x02, 0x0A}, // 0x49 I
    {0x02, 0x0B}, // 0x4A J
    {0x02, 0x0C}, // 0x4B K
    {0x02, 0x0D}, // 0x4C L
    {0x02, 0x0E}, // 0x4D M
    {0x02, 0x0F}, // 0x4E N
    {0x02, 0x10}, // 0x4F O
    {0x02, 0x11}, // 0x50 P
    {0x02, 0x12}, // 0x51 Q
    {0x02, 0x13}, // 0x52 R
    {0x02, 0x14}, // 0x53 S
    {0x02, 0x15}, // 0x54 T
    {0x02, 0x16}, // 0x55 U
    {0x02, 0x17}, // 0x56 V
    {0x02, 0x18}, // 0x57 W
    {0x02, 0x19}, // 0x58 X
    {0x02, 0x1A}, // 0x59 Y
    {0x02, 0x1B}, // 0x5A Z
    {0x04, 0x2F}, // 0x5B [ (Shift + [)
    {0x04, 0x31}, // 0x5C \ (Shift + \)
    {0x04, 0x2B}, // 0x5D ] (Shift + ])
    {0x04, 0x2C}, // 0x5E ^ (Shift + 6)
    {0x04, 0x2D}, // 0x5F _ (Shift + -)
    {0x04, 0x35}, // 0x60 ` (Shift + `)
    {0x02, 0x02}, // 0x61 a
    {0x02, 0x03}, // 0x62 b
    {0x02, 0x04}, // 0x63 c
    {0x02, 0x05}, // 0x64 d
    {0x02, 0x06}, // 0x65 e
    {0x02, 0x07}, // 0x66 f
    {0x02, 0x08}, // 0x67 g
    {0x02, 0x09}, // 0x68 h
    {0x02, 0x0A}, // 0x69 i
    {0x02, 0x0B}, // 0x6A j
    {0x02, 0x0C}, // 0x6B k
    {0x02, 0x0D}, // 0x6C l
    {0x02, 0x0E}, // 0x6D m
    {0x02, 0x0F}, // 0x6E n
    {0x02, 0x10}, // 0x6F o
    {0x02, 0x11}, // 0x70 p
    {0x02, 0x12}, // 0x71 q
    {0x02, 0x13}, // 0x72 r
    {0x02, 0x14}, // 0x73 s
    {0x02, 0x15}, // 0x74 t
    {0x02, 0x16}, // 0x75 u
    {0x02, 0x17}, // 0x76 v
    {0x02, 0x18}, // 0x77 w
    {0x02, 0x19}, // 0x78 x
    {0x02, 0x1A}, // 0x79 y
    {0x02, 0x1B}, // 0x7A z
    {0x04, 0x2D}, // 0x7B { (Shift + [)
    {0x04, 0x2E}, // 0x7C | (Shift + \)
    {0x04, 0x2C}, // 0x7D } (Shift + ])
    {0x04, 0x34}, // 0x7E ~ (Shift + `)
    {0x00, 0x00}  // 0x7F DEL
};

static usb_disconnect_callback_t g_disconnect_callback = NULL;
static PCD_HandleTypeDef hpcd_USB_OTG_FS; // Assuming this is defined elsewhere or globally

// Helper function to get the USB PCD handle
static PCD_HandleTypeDef* get_pcd_handle(void) {
    // In a real STM32 project, hpcd_USB_OTG_FS would be initialized
    // by CubeMX or HAL_Init. For this example, we assume it's available.
    // If not, you'd need to initialize it here or ensure it's globally accessible.
    return &hpcd_USB_OTG_FS;
}

// USB interrupt handler (needs to be called from the main interrupt vector)
// Placeholder for the global PCD handle if not defined elsewhere (e.g., from CubeMX)
PCD_HandleTypeDef hpcd_USB_OTG_FS;

// USB interrupt handler (needs to be called from the main interrupt vector)
void USB_OTG_FS_IRQHandler(void) {
    HAL_PCD_IRQHandler(&hpcd_USB_OTG_FS);
}

// HAL PCD Callbacks
void HAL_PCD_MspInit(PCD_HandleTypeDef* hpcd) {
    GPIO_InitTypeDef GPIO_InitStruct = {0};
    if (hpcd->Instance == USB_OTG_FS) {
        // Enable USB peripheral clock
        __HAL_RCC_USB_OTG_FS_CLK_ENABLE();
        __HAL_RCC_GPIOA_CLK_ENABLE();

        // Configure USB DM and DP pins
        GPIO_InitStruct.Pin = GPIO_PIN_11 | GPIO_PIN_12;
        GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
        GPIO_InitStruct.Pull = GPIO_NOPULL;
        GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
        GPIO_InitStruct.Alternate = GPIO_AF10_OTG_FS; // Check your MCU's alternate function mapping
        HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

        // Enable and set USB interrupt priority
        HAL_NVIC_SetPriority(USB_OTG_FS_IRQn, 0, 0); // Adjust priority as needed
        HAL_NVIC_EnableIRQ(USB_OTG_FS_IRQn);
    }
}

void HAL_PCD_SetupStageCallback(PCD_HandleTypeDef *hpcd) {
    if (hpcd->Instance == USB_OTG_FS) {
        HAL_PCD_EP0_Setup(hpcd, hpcd->Setup);
    }
}

void HAL_PCD_DataOutStageCallback(PCD_HandleTypeDef *hpcd, uint8_t epnum) {
    if (hpcd->Instance == USB_OTG_FS && epnum == (HID_KEYBOARD_IN_EP & 0x7F)) {
        // Handle data OUT for control endpoint 0 if necessary
        // For HID keyboard, we primarily use IN endpoints.
    }
}

void HAL_PCD_DataInStageCallback(PCD_HandleTypeDef *hpcd, uint8_t epnum) {
    if (hpcd->Instance == USB_OTG_FS && epnum == (HID_KEYBOARD_IN_EP & 0x7F)) {
        // Data IN transfer completed on HID_KEYBOARD_IN_EP.
        // No specific action needed here for this example,
        // but in a complex USB driver, this could signal a TX complete event.
    }
}

void HAL_PCD_SOFCallback(PCD_HandleTypeDef *hpcd) {
    // Start of Frame callback
}

void HAL_PCD_SuspendCallback(PCD_HandleTypeDef *hpcd) {
    // USB Suspend callback
}

void HAL_PCD_ResumeCallback(PCD_HandleTypeDef *hpcd) {
    // USB Resume callback
}

void HAL_PCD_ResetCallback(PCD_HandleTypeDef *hpcd) {
    if (hpcd->Instance == USB_OTG_FS) {
        // Resetting endpoints
        HAL_PCD_EP_SetAddress(hpcd, 0x00);

        HAL_PCD_EP_Disable(hpcd, HID_KEYBOARD_IN_EP);
        HAL_PCD_EP_Disable(hpcd, HID_KEYBOARD_IN_EP | 0x80); // Disable OUT endpoint if it exists

        // Configure Endpoint 0 for control transfers
        PCD_EPTypeDef *ep0 = &hpcd->IN_ep[0];
        ep0->max_len = USB_MAX_EP0_SIZE;
        ep0->is_in = 1;
        ep0->type = EP_CONTROL;
        HAL_PCD_EP_Open(hpcd, 0x00, USB_MAX_EP0_SIZE, EP_CONTROL);

        // Configure Endpoint 0x81 for HID Keyboard IN
        HAL_PCD_EP_Open(hpcd, HID_KEYBOARD_IN_EP, USB_MAX_EP_SIZE, EP_INT);

        // Prepare for the first IN transaction on EP0
        HAL_PCD_EP0_PrepareReceive(hpcd, hpcd->Setup, USB_MAX_EP0_SIZE);
    }
}

void HAL_PCD_DisconnectCallback(PCD_HandleTypeDef *hpcd) {
    if (g_disconnect_callback) {
        g_disconnect_callback();
    }
}

// --- PCD HAL Implementation ---

void pcd_hal_init(void) {
    hpcd_USB_OTG_FS.Instance = USB_OTG_FS;
    hpcd_USB_OTG_FS.Init.dev_endpoints = 6; // Max endpoints for your MCU
    hpcd_USB_OTG_FS.Init.phy_itface = PCD_PHY_EMBEDDED;
    hpcd_USB_OTG_FS.Init.Sof_enable = true;
    hpcd_USB_OTG_FS.Init.low_power_enable = PCD_LOW_POWER_DISABLE;
    hpcd_USB_OTG_FS.Init.lpm_enable = PCD_LPM_DISABLE;
    hpcd_USB_OTG_FS.Init.battery_charging_enable = PCD_Battery_Charging_DISABLE;

    if (HAL_PCD_Init(&hpcd_USB_OTG_FS) != HAL_OK) {
        // Handle error
        Error_Handler();
    }

    // Registering endpoint 0x81 as interrupt IN endpoint
    // This is done within HAL_PCD_ResetCallback after a USB reset.
    // We just need to ensure the HAL_PCD_Init is called.

    // Enable USB global interrupt
    HAL_NVIC_SetPriority(USB_OTG_FS_IRQn, 0, 0); // Adjust priority as needed
    HAL_NVIC_EnableIRQ(USB_OTG_FS_IRQn);
}

bool pcd_hal_send_hid_report(const uint8_t *report) {
    if (!pcd_hal_is_connected()) {
        return false;
    }
    // Send the report via HAL_PCD_EP_Transmit on endpoint 0x81
    if (HAL_PCD_EP_Transmit(get_pcd_handle(), HID_KEYBOARD_IN_EP, (uint8_t *)report, HID_KEYBOARD_REPORT_SIZE) != HAL_OK) {
        return false;
    }
    return true;
}

void pcd_hal_send_key(uint8_t modifier, uint8_t keycode) {
    uint8_t report[HID_KEYBOARD_REPORT_SIZE] = {0};

    // Build the key press report
    report[0] = modifier; // Modifier byte
    report[2] = keycode;  // Keycode byte (first key)

    // Send the key press report
    if (pcd_hal_send_hid_report(report)) {
        // Send a null report to simulate key release
        memset(report, 0, HID_KEYBOARD_REPORT_SIZE);
        pcd_hal_send_hid_report(report);
    }
}

void pcd_hal_type_string(const char *str) {
    if (!str) {
        return;
    }

    while (*str) {
        char c = *str++;
        uint8_t modifier = 0;
        uint8_t keycode = 0;

        if (c < 128) {
            modifier = ascii_to_hid_map[(uint8_t)c][0];
            keycode = ascii_to_hid_map[(uint8_t)c][1];
        }

        if (keycode != 0x00) {
            pcd_hal_send_key(modifier, keycode);
            HAL_Delay(8); // Small delay between keypress and release
        } else if (c == '\n') {
            // Handle newline specifically if needed, e.g., send Enter keycode
            pcd_hal_send_key(0x00, 0x28); // Enter keycode
            HAL_Delay(8);
        } else if (c == '\r') {
            // Ignore carriage return if already handling newline
        } else {
            // Character not found in map, ignore or handle as error
        }
    }
}

void pcd_hal_register_callback(usb_disconnect_callback_t callback) {
    g_disconnect_callback = callback;
}

bool pcd_hal_is_connected(void) {
    return hpcd_USB_OTG_FS.State == HAL_PCD_STATE_READY;
}

// Dummy Error_Handler for compilation
void Error_Handler(void) {
    while (1) {}
}
