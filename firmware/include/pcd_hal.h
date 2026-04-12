#ifndef PCD_HAL_H
#define PCD_HAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "stm32u5xx_hal_pcd.h" // Required for PCD_HandleTypeDef

// Defined HID Keyboard Report Size
#define HID_KEYBOARD_REPORT_SIZE 8

// HID modifier bitmasks
#define MOD_NONE        0x00
#define MOD_LEFT_CTRL   0x01
#define MOD_LEFT_SHIFT  0x02
#define MOD_LEFT_ALT    0x04
#define MOD_LEFT_GUI    0x08
#define MOD_RIGHT_CTRL  0x10
#define MOD_RIGHT_SHIFT 0x20
#define MOD_RIGHT_ALT   0x40
#define MOD_RIGHT_GUI   0x80

// Standard HID keycodes
#define KEY_NONE        0x00
#define KEY_A           0x04
#define KEY_B           0x05
#define KEY_C           0x06
#define KEY_D           0x07
#define KEY_E           0x08
#define KEY_F           0x09
#define KEY_G           0x0A
#define KEY_H           0x0B
#define KEY_I           0x0C
#define KEY_J           0x0D
##define KEY_K           0x0E
#define KEY_L           0x0F
#define KEY_M           0x10
#define KEY_N           0x11
#define KEY_O           0x12
#define KEY_P           0x13
#define KEY_Q           0x14
#define KEY_R           0x15
#define KEY_S           0x16
#define KEY_T           0x17
#define KEY_U           0x18
#define KEY_V           0x19
#define KEY_W           0x1A
#define KEY_X           0x1B
#define KEY_Y           0x1C
#define KEY_Z           0x1D
#define KEY_1           0x1E
#define KEY_2           0x1F
#define KEY_3           0x20
#define KEY_4           0x21
#define KEY_5           0x22
#define KEY_6           0x23
#define KEY_7           0x24
#define KEY_8           0x25
#define KEY_9           0x26
#define KEY_0           0x27
#define KEY_ENTER       0x28
#define KEY_ESCAPE      0x29
#define KEY_BACKSPACE   0x2A
#define KEY_TAB         0x2B
#define KEY_SPACE       0x2C
#define KEY_MINUS       0x2D
#define KEY_EQUAL       0x2E
#define KEY_LEFTBRACE   0x2F
#define KEY_RIGHTBRACE  0x30
#define KEY_BACKSLASH   0x31
#define KEY_HASHTILDE   0x32
#define KEY_SEMICOLON   0x33
#define KEY_APOSTROPHE  0x34
#define KEY_GRAVE       0x35
#define KEY_COMMA       0x36
#define KEY_DOT         0x37
#define KEY_SLASH       0x38
#define KEY_CAPSLOCK    0x39
#define KEY_F1          0x3A
#define KEY_F2          0x3B
#define KEY_F3          0x3C
#define KEY_F4          0x3D
#define KEY_F5          0x3E
#define KEY_F6          0x3F
#define KEY_F7          0x40
#define KEY_F8          0x41
#define KEY_F9          0x42
#define KEY_F10         0x43
#define KEY_F11         0x44
#define KEY_F12         0x45
#define KEY_PRINTSCREEN 0x46
#define KEY_SCROLLLOCK  0x47
#define KEY_PAUSE       0x48
#define KEY_INSERT      0x49
#define KEY_HOME        0x4A
#define KEY_PAGEUP      0x4B
#define KEY_DELETE      0x4C
#define KEY_END         0x4D
#define KEY_PAGEDOWN    0x4E
#define KEY_RIGHT       0x4F
#define KEY_LEFT        0x50
#define KEY_DOWN        0x51
#define KEY_UP          0x52
#define KEY_NUMLOCK     0x53
#define KEY_KPSLASH     0x54
#define KEY_KPASTERISK  0x55
#define KEY_KPMINUS     0x56
#define KEY_KPPLUS      0x57
#define KEY_KPENTER     0x58
#define KEY_KP1         0x59
#define KEY_KP2         0x5A
#define KEY_KP3         0x5B
#define KEY_KP4         0x5C
#define KEY_KP5         0x5D
#define KEY_KP6         0x5E
#define KEY_KP7         0x5F
#define KEY_KP8         0x60
#define KEY_KP9         0x61
#define KEY_KP0         0x62
#define KEY_KPDOT       0x63
#define KEY_102ND       0x64
#define KEY_COMPOSE     0x65
#define KEY_POWER       0x66
#define KEY_KPEQUAL     0x67
#define KEY_F13         0x68
#define KEY_F14         0x69
#define KEY_F15         0x6A
#define KEY_F16         0x6B
#define KEY_F17         0x6C
#define KEY_F18         0x6D
#define KEY_F19         0x6E
#define KEY_F20         0x6F
#define KEY_F21         0x70
#define KEY_F22         0x71
#define KEY_F23         0x72
#define KEY_F24         0x73

// Callback function type for USB disconnect events
typedef void (*usb_disconnect_callback_t)(void);

/**
 * @brief Initializes the USB PCD HAL for composite device.
 *
 * This function handles the low-level initialization of the USB Peripheral Controller.
 * It does not start the USB enumeration process, which is done by HAL_PCD_Start.
 */
void pcd_hal_init(void);

/**
 * @brief Sends an 8-byte HID keyboard report.
 *
 * @param report A pointer to the 8-byte report data, conforming to HID keyboard report format.
 * @return true if the report was sent successfully, false otherwise.
 */
bool pcd_hal_send_hid_report(const uint8_t *report);

/**
 * @brief Sends a single key press and release event.
 *
 * @param modifier The modifier keys bitmask (e.g., MOD_LEFT_SHIFT).
 * @param keycode The HID keycode of the pressed key (e.g., KEY_A).
 */
void pcd_hal_send_key(uint8_t modifier, uint8_t keycode);


/**
 * @brief Types a string using the USB HID keyboard.
 *
 * Each character is converted to its corresponding HID keycode and sent,
 * followed by a null report to release the key. A small delay is introduced
 * between keypresses to ensure proper recognition by the host.
 *
 * @param str The null-terminated string to type. It should contain printable ASCII characters.
 * @return true if the string was typed successfully, false otherwise.
 */
bool pcd_hal_type_string(const char *str);

/**
 * @brief Registers a callback function to be called on USB disconnect.
 *
 * @param callback The function pointer to the callback function.
 */
void pcd_hal_register_callback(usb_disconnect_callback_t callback);

/**
 * @brief Checks if the USB device is connected to a host and fully enumerated.
 *
 * @return true if the USB PCD is in a ready state (connected and configured), false otherwise.
 */
bool pcd_hal_is_connected(void);

/**
 * @brief Send a custom HID report from device to host.
 * @param report_id The report ID for the custom report.
 * @param data Pointer to the data payload.
 * @param data_len Length of the data payload.
 * @return true if the report was sent successfully, false otherwise.
 */
bool pcd_hal_custom_hid_send_report(uint8_t report_id, const uint8_t *data, size_t data_len);

/**
 * @brief Receive a custom HID report from host to device.
 * @param report_id Pointer to store the received report ID.
 * @param data Buffer to store the received data payload.
 * @param data_len Maximum length of the data buffer.
 * @param received_len Pointer to store the actual received data length.
 * @return true if a report was received successfully and is pending, false otherwise.
 */
bool pcd_hal_custom_hid_receive_report(uint8_t *report_id, uint8_t *data, size_t data_len, size_t *received_len);


#endif /* PCD_HAL_H */
