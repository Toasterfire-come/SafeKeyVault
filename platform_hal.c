/*
 * platform_hal.c — host-test stub
 *
 * This file is compiled only in the host-test (non-embedded) build.
 * The real hardware implementation lives in firmware/src/platform_hal.c.
 *
 * All functions here provide safe, side-effect-free behaviour so that
 * unit tests can exercise firmware logic without STM32 hardware.
 */

#include "platform_hal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Internal simulated state
 * ------------------------------------------------------------------------- */
static platform_hal_status_t s_status = {
    .initialized     = false,
    .led_locked_on   = false,
    .led_activity_on = false,
    .touch_pressed   = false,
    .touch_held      = false,
    .tick_count      = 0u,
};

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */
void platform_hal_init(void)
{
    memset(&s_status, 0, sizeof(s_status));
    s_status.initialized = true;
}

void platform_hal_tick(void)
{
    s_status.tick_count++;
}

/* -------------------------------------------------------------------------
 * LED
 * ------------------------------------------------------------------------- */
void platform_hal_led_set(platform_hal_led_t led, bool on)
{
    switch (led) {
        case PLATFORM_HAL_LED_LOCKED:
            s_status.led_locked_on = on;
            break;
        case PLATFORM_HAL_LED_ACTIVITY:
        case PLATFORM_HAL_LED_UNLOCKED:
            s_status.led_activity_on = on;
            break;
        case PLATFORM_HAL_LED_ERROR:
            s_status.led_locked_on   = on;
            s_status.led_activity_on = on;
            break;
        case PLATFORM_HAL_LED_OFF:
        default:
            s_status.led_locked_on   = false;
            s_status.led_activity_on = false;
            break;
    }
}

/* -------------------------------------------------------------------------
 * Touch
 * ------------------------------------------------------------------------- */
void platform_hal_touch_set_simulated(bool pressed, bool held)
{
    s_status.touch_pressed = pressed;
    s_status.touch_held    = held;
}

bool platform_hal_touch_read(void)
{
    return s_status.touch_pressed;
}

bool platform_hal_touch_held(void)
{
    return s_status.touch_held;
}

/* -------------------------------------------------------------------------
 * Status snapshot
 * ------------------------------------------------------------------------- */
bool platform_hal_get_status(platform_hal_status_t *out_status)
{
    if (out_status == NULL) {
        return false;
    }
    *out_status = s_status;
    return true;
}

/* -------------------------------------------------------------------------
 * USB HID — no-op in host tests; returns true to allow logic to proceed
 * ------------------------------------------------------------------------- */
bool platform_hal_usb_hid_type(const char *text)
{
    /* Suppress unused-parameter warning */
    (void)text;
    return true;
}

/* -------------------------------------------------------------------------
 * SystemClock_Config — no-op on host
 * ------------------------------------------------------------------------- */
void SystemClock_Config(void)
{
    /* Nothing to do on host */
}

// No change needed in platform_hal.c for Error_Handler. The one in main.c is the system one.
// This Error_Handler is for host tests only and correctly uses __builtin_trap().
// Do not modify.
