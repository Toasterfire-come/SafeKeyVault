#include "platform_hal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Mock platform HAL state for host tests.
// In a real embedded environment, this would interact with hardware registers.
typedef struct {
  bool initialized;
  bool led_locked_on;
  bool led_activity_on;
  bool touch_pressed;
  bool touch_held;
  uint32_t tick_count;
} platform_hal_state_t;

static platform_hal_state_t g_hal;

void platform_hal_init(void) {
  memset(&g_hal, 0, sizeof(g_hal));
  g_hal.initialized = true;
}

void platform_hal_tick(void) {
  g_hal.tick_count++;
}

void platform_hal_led_set(platform_hal_led_t led, bool on) {
  if (led == PLATFORM_HAL_LED_LOCKED) {
    g_hal.led_locked_on = on;
  } else if (led == PLATFORM_HAL_LED_ACTIVITY) {
    g_hal.led_activity_on = on;
  }
  // Other LEDs (ERROR, OFF) are not explicitly managed here in the mock.
}

void platform_hal_touch_set_simulated(bool pressed, bool held) {
  g_hal.touch_pressed = pressed;
  g_hal.touch_held = held;
}

bool platform_hal_usb_hid_type(const char *text) {
  // In host tests, we don't actually type anything.
  // We can optionally log this for debugging.
  // printf("SIMULATED HID TYPE: %s\n", text);
  return true; // Assume success for simulation
}

bool platform_hal_get_status(platform_hal_status_t *out_status) {
  if (out_status == NULL) {
    return false;
  }
  out_status->initialized = g_hal.initialized;
  out_status->led_locked_on = g_hal.led_locked_on;
  out_status->led_activity_on = g_hal.led_activity_on;
  out_status->touch_pressed = g_hal.touch_pressed;
  out_status->touch_held = g_hal.touch_held;
  out_status->tick_count = g_hal.tick_count;
  return true;
}
