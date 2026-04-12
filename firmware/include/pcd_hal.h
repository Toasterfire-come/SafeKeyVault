#ifndef PCD_HAL_H
#define PCD_HAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Callback function type for USB disconnect events
typedef void (*usb_disconnect_callback_t)(void);

/**
 * @brief Initializes the USB PCD HAL for HID keyboard device.
 *
 * This function configures the USB peripheral in device mode, sets up endpoint 0x81
 * as an interrupt IN endpoint, and registers the necessary callbacks.
 */
void pcd_hal_init(void);

/**
 * @brief Sends an 8-byte HID keyboard report.
 *
 * @param report A pointer to the 8-byte report data.
 * @return true if the report was sent successfully, false otherwise.
 */
bool pcd_hal_send_hid_report(const uint8_t *report);

/**
 * @brief Sends a single key press and release event.
 *
 * @param modifier The modifier keys (e.g., Ctrl, Shift, Alt).
 * @param keycode The keycode of the pressed key.
 */
void pcd_hal_send_key(uint8_t modifier, uint8_t keycode);

/**
 * @brief Types a string using the USB HID keyboard.
 *
 * Each character is converted to its corresponding HID keycode and sent,
 * followed by a null report to release the key. A small delay is introduced
 * between keypresses to ensure proper recognition by the host.
 *
 * @param str The null-terminated string to type.
 */
void pcd_hal_type_string(const char *str);

/**
 * @brief Registers a callback function to be called on USB disconnect.
 *
 * @param callback The function pointer to the callback function.
 */
void pcd_hal_register_callback(usb_disconnect_callback_t callback);

/**
 * @brief Checks if the USB device is connected to a host.
 *
 * @return true if the USB PCD is in the ready state (connected), false otherwise.
 */
bool pcd_hal_is_connected(void);

#endif /* PCD_HAL_H */
