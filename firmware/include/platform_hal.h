#ifndef PLATFORM_HAL_H
#define PLATFORM_HAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  HAL_LED_OFF = 0,
  HAL_LED_LOCKED,
  HAL_LED_UNLOCKED,
  HAL_LED_ERROR,
  HAL_LED_TYPING,
  HAL_LED_SETTINGS
} hal_led_mode_t;

typedef struct {
  bool (*usb_hid_send_keys)(const char *text);
  bool (*touch_is_pressed)(void);
  bool (*button_is_pressed)(void);
  void (*led_set_mode)(hal_led_mode_t mode);
  uint32_t (*millis_now)(void);
} platform_hal_vtable_t;

void platform_hal_bind(const platform_hal_vtable_t *vtable);
bool platform_hal_ready(void);

bool platform_hal_usb_hid_send_keys(const char *text);
bool platform_hal_touch_is_pressed(void);
bool platform_hal_button_is_pressed(void);
void platform_hal_led_set_mode(hal_led_mode_t mode);
uint32_t platform_hal_millis_now(void);

#endif /* PLATFORM_HAL_H */
