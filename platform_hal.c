/*
 * platform_hal.c — Hardware Abstraction Layer (HAL) implementation
 *
 * This file provides the actual HAL functions for the STM32U5xx microcontroller.
 */

#include "platform_hal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Include the STM32 HAL header */
#include "stm32u5xx_hal.h"

/* -------------------------------------------------------------------------
 * Internal state for platform_hal functions
 * ------------------------------------------------------------------------- */
// These variables will hold the current state of the platform hardware.
// They are updated by the HAL functions.
static bool s_led_locked_on = false;
static bool s_led_activity_on = false;
static bool s_touch_pressed = false;
static bool s_touch_held = false;

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */
void platform_hal_init(void)
{
    /* Initialize the HAL library */
    if (HAL_Init() != HAL_OK) {
        Error_Handler(); // Use the system's Error_Handler
    }

    /* Configure the system clock */
    SystemClock_Config();

    /* Initialize GPIOs for LEDs */
    GPIO_InitTypeDef GPIO_InitStruct = {0};

    // Enable clocks for GPIO ports used by LEDs
    __HAL_RCC_GPIOA_CLK_ENABLE(); // Example: Enable clock for GPIOA
    __HAL_RCC_GPIOB_CLK_ENABLE(); // Example: Enable clock for GPIOB
    __HAL_RCC_GPIOC_CLK_ENABLE(); // Example: Enable clock for GPIOC

    // Configure LED pins as output
    // PLATFORM_HAL_LED_LOCKED (e.g., PA0)
    GPIO_InitStruct.Pin = GPIO_PIN_0;
    GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    // PLATFORM_HAL_LED_UNLOCKED (e.g., PA1)
    GPIO_InitStruct.Pin = GPIO_PIN_1;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    // PLATFORM_HAL_LED_ACTIVITY (e.g., PB0)
    GPIO_InitStruct.Pin = GPIO_PIN_0;
    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

    // PLATFORM_HAL_LED_ERROR (e.g., PC0)
    GPIO_InitStruct.Pin = GPIO_PIN_0;
    HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

    // Initialize touch input pin if applicable
    // Example: Assuming touch is on PD0
    // __HAL_RCC_GPIOD_CLK_ENABLE();
    // GPIO_InitStruct.Pin = GPIO_PIN_0;
    // GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
    // GPIO_InitStruct.Pull = GPIO_PULLUP; // Or GPIO_PULLDOWN depending on sensor
    // HAL_GPIO_Init(GPIOD, &GPIO_InitStruct);

    // Ensure all LEDs are off initially
    platform_hal_led_set(PLATFORM_HAL_LED_OFF, true);
}

void platform_hal_tick(void)
{
    // The HAL_IncTick() function is typically called by the SysTick_Handler.
    // Ensure that your stm32u5xx_it.c file has the following in SysTick_Handler:
    // void SysTick_Handler(void)
    // {
    //   HAL_IncTick();
    // }
    // This function itself doesn't need to do anything if SysTick is configured correctly.
}

/* -------------------------------------------------------------------------
 * LED
 * ------------------------------------------------------------------------- */
void platform_hal_led_set(platform_hal_led_t led, bool on)
{
    GPIO_PinState state = on ? GPIO_PIN_SET : GPIO_PIN_RESET;

    switch (led) {
        case PLATFORM_HAL_LED_LOCKED:
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_0, state); // Example: PA0 for locked LED
            s_led_locked_on = on;
            break;
        case PLATFORM_HAL_LED_UNLOCKED:
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_1, state); // Example: PA1 for unlocked LED
            s_led_locked_on = !on; // Assuming unlocked is the opposite of locked
            break;
        case PLATFORM_HAL_LED_ACTIVITY:
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_0, state); // Example: PB0 for activity LED
            s_led_activity_on = on;
            break;
        case PLATFORM_HAL_LED_ERROR:
            HAL_GPIO_WritePin(GPIOC, GPIO_PIN_0, state); // Example: PC0 for error LED
            // Error LED might override other states, or be a distinct indicator.
            // For simplicity, we'll just set it.
            break;
        case PLATFORM_HAL_LED_OFF:
        default:
            // Turn off all LEDs
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_0, GPIO_PIN_RESET);
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_1, GPIO_PIN_RESET);
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_0, GPIO_PIN_RESET);
            HAL_GPIO_WritePin(GPIOC, GPIO_PIN_0, GPIO_PIN_RESET);
            s_led_locked_on = false;
            s_led_activity_on = false;
            break;
    }
}

/* -------------------------------------------------------------------------
 * Touch
 * ------------------------------------------------------------------------- */
void platform_hal_touch_set_simulated(bool pressed, bool held)
{
    // This function is for simulation/testing purposes.
    // In a real hardware implementation, touch input is read, not set.
    // If this function is called on hardware, it might be ignored or trigger a simulated event.
    // For a true hardware implementation, this function might not be needed,
    // or it could be used to inject simulated touch events for testing.
    s_touch_pressed = pressed;
    s_touch_held = held;
}

bool platform_hal_touch_read(void)
{
    // Replace with actual hardware read if applicable.
    // Example: return HAL_GPIO_ReadPin(GPIOD, GPIO_PIN_0) == GPIO_PIN_SET; // Assuming PD0 is touch input
    // For now, return the simulated state if not using actual hardware.
    return s_touch_pressed;
}

bool platform_hal_touch_held(void)
{
    // Replace with actual hardware read if applicable.
    // This might involve checking touch duration or a specific sensor state.
    // For now, return the simulated state if not using actual hardware.
    return s_touch_held;
}

/* -------------------------------------------------------------------------
 * Status snapshot
 * ------------------------------------------------------------------------- */
bool platform_hal_get_status(platform_hal_status_t *out_status)
{
    if (out_status == NULL) {
        return false;
    }

    /* Populate status from HAL state and internal variables */
    out_status->initialized = (HAL_GetTick() > 0); // Check if HAL tick has started
    out_status->led_locked_on = s_led_locked_on;
    out_status->led_activity_on = s_led_activity_on;
    out_status->touch_pressed = platform_hal_touch_read(); // Read current touch state
    out_status->touch_held = platform_hal_touch_held();   // Read current touch held state
    out_status->tick_count = HAL_GetTick();              // Get current system tick

    return true;
}

/* -------------------------------------------------------------------------
 * USB HID
 * ------------------------------------------------------------------------- */
bool platform_hal_usb_hid_type(const char *text)
{
    if (text == NULL) {
        return false;
    }
    // This function should send the string via USB HID.
    // This typically involves calling a USB HID driver function provided by the HAL or a middleware.
    // Example: return YOUR_USB_HID_SEND_STRING_FUNCTION(text);
    // For this example, we'll assume a function `usb_hid_send_string` exists and is implemented elsewhere.
    // If you are using STM32CubeMX, it might generate USB HID functions.
    // For now, we'll return true, assuming the underlying HID driver is functional.
    // You will need to replace this with the actual call to your USB HID send function.
    (void)text; // Suppress unused parameter warning if not implemented
    return true;
}

bool platform_hal_usb_hid_type_char(char c)
{
    // This function should send a single character via USB HID.
    // Example: return YOUR_USB_HID_SEND_CHAR_FUNCTION(c);
    // For now, we'll return true.
    (void)c; // Suppress unused parameter warning
    return true;
}

/* -------------------------------------------------------------------------
 * SystemClock_Config — This function is typically defined in main.c or clock configuration file.
 * It needs to be implemented for the specific STM32U5xx board.
 * ------------------------------------------------------------------------- */
// The actual SystemClock_Config function should be defined elsewhere,
// typically in main.c or a dedicated clock configuration file (e.g., stm32u5xx_hal_msp.c or similar).
// If it's not defined, you'll get a linker error.
// For this example, we'll provide a minimal stub here, but it MUST be replaced
// with the actual board-specific clock configuration.
void SystemClock_Config(void)
{
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
    RCC_PeriphCLKInitTypeDef PeriphClkInit = {0};

    /** Configure the main internal regulator output voltage
    */
    HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1);
    /** Initializes the RCC Oscillators according to the specified parameters
    * in the RCC_OscInitTypeDef structure.
    */
    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
    RCC_OscInitStruct.HSEState = RCC_HSE_ON;
    RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
    RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
    RCC_OscInitStruct.PLL.PLLM = 1;
    RCC_OscInitStruct.PLL.PLLN = 20;
    RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
    RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV2;
    if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
    {
        Error_Handler();
    }
    /** Initializes the CPU, AHB and APB buses clocks
    */
    RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                                |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
    RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

    if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_4) != HAL_OK)
    {
        Error_Handler();
    }
    PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_USB;
    PeriphClkInit.UsbClockSelection = RCC_USBCLKSOURCE_PLLSAI1;
    PeriphClkInit.PLLSAI1.PLLSAI1N = 12;
    PeriphClkInit.PLLSAI1.PLLSAI1P = RCC_PLLSAI1P_DIV4;
    PeriphClkInit.PLLSAI1.PLLSAI1Q = RCC_PLLSAI1Q_DIV2;
    PeriphClkInit.PLLSAI1.PLLSAI1R = RCC_PLLSAI1R_DIV2;
    PeriphClkInit.PLLSAI1.PLLSAI1ClockOut = RCC_PLLSAI1_USB;
    if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit) != HAL_OK)
    {
        Error_Handler();
    }
}

/* -------------------------------------------------------------------------
 * Error_Handler — This function is typically defined in main.c or similar.
 * It should handle fatal errors.
 * ------------------------------------------------------------------------- */
// If Error_Handler is not defined elsewhere (e.g., in main.c),
// you'll need to provide a definition here.
// For example:
#ifndef Error_Handler
void Error_Handler(void) {
    // In production, this should indicate a fatal, unrecoverable error
    // e.g., by halting the system, or blinking an error LED pattern.
    __disable_irq();
    while (1) {
        // Example: Blink an error LED rapidly
        HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_0); // Assuming PC0 is the error LED
        HAL_Delay(100);
    }
}
#endif
