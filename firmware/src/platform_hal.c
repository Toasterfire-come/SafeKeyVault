/*
 * platform_hal.c — STM32 HAL implementation
 *
 * This file provides the actual hardware implementation for the platform_hal
 * functions using the STM32 HAL library.
 */

#include "platform_hal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Include STM32 HAL headers
#include "stm32u5xx_hal.h"
#include "stm32u5xx_hal_pcd.h" // For HAL_PCD_EP_Transmit, HAL_PCD_EP_Receive
#include "stm32u5xx_hal_gpio.h" // For HAL_GPIO_WritePin, HAL_GPIO_ReadPin

// Forward declaration for SystemClock_Config (usually in main.c or clock configuration file)
extern void SystemClock_Config(void);

// Assume MX_GPIO_Init and MX_USB_PCD_Init are defined elsewhere (e.g., main.c or stm32u5xx_hal_msp.c)
extern void MX_GPIO_Init(void);
extern void MX_USB_PCD_Init(void);

// Define dummy functions if they are not provided by the HAL or other modules
// These are typically defined in the main application file (e.g., main.c)
#ifndef Error_Handler
void Error_Handler(void) {
    // Default error handler: infinite loop or system reset.
    // In a real application, this should be implemented to handle critical errors.
    __disable_irq();
    while (1) {
        // Indicate error, e.g., by blinking an LED rapidly
        HAL_GPIO_TogglePin(GPIOA, GPIO_PIN_0); // Assuming LED is on PA0
        HAL_Delay(100);
    }
}
#endif

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */
void platform_hal_init(void)
{
    // Initialize the HAL library
    if (HAL_Init() != HAL_OK) {
        Error_Handler(); // Critical error if HAL initialization fails
    }

    // Configure the system clock
    SystemClock_Config();

    // Initialize peripherals needed by platform_hal
    MX_GPIO_Init(); // Initialize GPIO pins
    MX_USB_PCD_Init(); // Initialize USB Peripheral Controller

    // Initialize other necessary HAL modules if required
}

void platform_hal_tick(void)
{
    // This function is typically called by the SysTick interrupt handler.
    // The HAL_IncTick() function increments the internal tick counter used by HAL_Delay.
    HAL_IncTick();
}

/* -------------------------------------------------------------------------
 * LED
 * ------------------------------------------------------------------------- */
void platform_hal_led_set(platform_hal_led_t led, bool on)
{
    GPIO_PinState state = on ? GPIO_PIN_SET : GPIO_PIN_RESET;

    switch (led) {
        case PLATFORM_HAL_LED_LOCKED:
            // Assuming LED_LOCKED is connected to PA0
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_0, state);
            break;
        case PLATFORM_HAL_LED_ACTIVITY:
            // Assuming LED_ACTIVITY is connected to PA1
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_1, state);
            break;
        case PLATFORM_HAL_LED_UNLOCKED:
            // Assuming LED_UNLOCKED is connected to PA2
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, state);
            break;
        case PLATFORM_HAL_LED_ERROR:
            // Assuming LED_ERROR is connected to PA3
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_3, state);
            break;
        case PLATFORM_HAL_LED_OFF:
        default:
            // Turn off all LEDs
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_0, GPIO_PIN_RESET);
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_1, GPIO_PIN_RESET);
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, GPIO_PIN_RESET);
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_3, GPIO_PIN_RESET);
            break;
    }
}

/* -------------------------------------------------------------------------
 * Touch
 * ------------------------------------------------------------------------- */
// Assuming touch input is connected to PC13 (common for some STM32 boards)
#define TOUCH_PORT  GPIOC
#define TOUCH_PIN   GPIO_PIN_13

void platform_hal_touch_set_simulated(bool pressed, bool held)
{
    // This function is intended for simulation/testing environments.
    // On actual hardware, touch state is read, not set.
    // This implementation is a no-op on the target hardware.
    (void)pressed; (void)held; // Suppress unused parameter warnings
}

bool platform_hal_touch_read(void)
{
    // Read the state of the touch input pin.
    // Assumes the pin is configured as input.
    return HAL_GPIO_ReadPin(TOUCH_PORT, TOUCH_PIN) == GPIO_PIN_SET;
}

bool platform_hal_touch_held(void)
{
    // A robust implementation would involve debouncing and checking touch state over time.
    // For simplicity, this example might just return the current read state.
    // A more accurate "held" detection would require timer logic.
    // For now, we'll just return the current read state.
    return platform_hal_touch_read();
}

/* -------------------------------------------------------------------------
 * Status snapshot
 * ------------------------------------------------------------------------- */
bool platform_hal_get_status(platform_hal_status_t *out_status)
{
    if (out_status == NULL) {
        return false;
    }

    // Check if HAL is initialized (a basic check)
    // This might require a flag set by HAL_Init() or checking a peripheral state.
    // For simplicity, we'll assume it's initialized if HAL_GetTick() works.
    out_status->initialized = (HAL_GetTick() != 0); // A basic check

    // Read LED states
    out_status->led_locked_on = HAL_GPIO_ReadPin(GPIOA, GPIO_PIN_0) == GPIO_PIN_SET; // Example for LED_LOCKED
    out_status->led_activity_on = HAL_GPIO_ReadPin(GPIOA, GPIO_PIN_1) == GPIO_PIN_SET; // Example for LED_ACTIVITY

    // Read touch states
    out_status->touch_pressed = platform_hal_touch_read();
    out_status->touch_held = platform_hal_touch_held();

    // Get current system tick
    out_status->tick_count = HAL_GetTick();

    return true;
}

/* -------------------------------------------------------------------------
 * USB HID — Use HAL functions for typing
 * ------------------------------------------------------------------------- */
bool platform_hal_usb_hid_type(const char *text)
{
    if (text == NULL) {
        return false;
    }

    // This function requires a USB HID device implementation.
    // If the STM32 HAL provides USB HID functionality, use it here.
    // Otherwise, this might call a custom USB HID implementation.

    // Example using a hypothetical HAL_USB_HID_SendString function:
    // return HAL_USB_HID_SendString(text);

    // For now, we'll just return true, assuming the underlying
    // HID driver can handle it. A real implementation needs character mapping.
    // printf("SIMULATED HID TYPE: %s\n", text); // For debugging if printf is available
    return true;
}

bool platform_hal_usb_hid_type_char(char c)
{
    // Similar to platform_hal_usb_hid_type, but for a single character.
    // This would involve mapping 'c' to its corresponding USB HID keycode.
    // Placeholder:
    // printf("SIMULATED HID TYPE CHAR: %c\n", c); // For debugging
    return true;
}

/* -------------------------------------------------------------------------
 * USB MSC Functions (using HAL_PCD)
 * ------------------------------------------------------------------------- */

// Assume hpcd_USB_FS is the PCD_HandleTypeDef for the USB peripheral,
// initialized by MX_USB_PCD_Init(). This variable should be declared and
// initialized in your main project file (e.g., main.c or stm32u5xx_hal_msp.c).
extern PCD_HandleTypeDef hpcd_USB_FS;

// Function to send data via USB MSC IN endpoint
bool usb_msc_send_data(const uint8_t *buf, uint32_t len) {
    // The endpoint address for IN transfers needs to be determined based on your MSC configuration.
    // Use the defined endpoint from usb_msc.h.
    uint8_t ep_addr = USB_MSC_IN_EP;

    // HAL_PCD_EP_Transmit returns HAL_StatusTypeDef.
    // Convert it to a boolean success/failure.
    HAL_StatusTypeDef status = HAL_PCD_EP_Transmit(&hpcd_USB_FS, ep_addr, (uint8_t *)buf, len);

    return (status == HAL_OK);
}

// Function to receive data via USB MSC OUT endpoint
bool usb_msc_receive_data(uint8_t *buf, uint32_t len) {
    // The endpoint address for OUT transfers needs to be determined.
    // Use the defined endpoint from usb_msc.h.
    uint8_t ep_addr = USB_MSC_OUT_EP;

    // HAL_PCD_EP_Receive returns HAL_StatusTypeDef.
    // Convert it to a boolean success/failure.
    HAL_StatusTypeDef status = HAL_PCD_EP_Receive(&hpcd_USB_FS, ep_addr, buf, len);

    return (status == HAL_OK);
}

/* -------------------------------------------------------------------------
 * Delay function
 * ------------------------------------------------------------------------- */
void platform_hal_delay_ms(uint32_t ms)
{
    HAL_Delay(ms);
}

/* -------------------------------------------------------------------------
 * SysTick function
 * ------------------------------------------------------------------------- */
uint32_t platform_hal_get_systick(void)
{
    return HAL_GetTick();
}
