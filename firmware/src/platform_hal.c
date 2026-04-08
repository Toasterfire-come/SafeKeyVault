#include "platform_hal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  bool usb_ready;
  bool touch_initialized;
  bool leds_initialized;
} hal_state_t;

static hal_state_t g_hal_state;

bool platform_hal_init(void) {
  g_hal_state.usb_ready = true;
  g_hal_state.touch_initialized = true;
  g_hal_state.leds_initialized = true;
  return true;
}

bool platform_hal_usb_hid_type(const char *text) {
  (void)text;
  return g_hal_state.usb_ready;
}

bool platform_hal_touch_pressed(void) {
  return false;
}

bool platform_hal_touch_held(void) {
  return false;
}

void platform_hal_led_set(uint8_t pattern_id) {
  (void)pattern_id;
}

void platform_hal_delay_ms(uint32_t ms) {
  (void)ms;
}
