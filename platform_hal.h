#ifndef PLATFORM_HAL_H
#define PLATFORM_HAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  PLATFORM_HAL_LED_OFF = 0,
  PLATFORM_HAL_LED_1, // Generic LED 1 (e.g., for locked/unlocked status)
  PLATFORM_HAL_LED_2, // Generic LED 2 (e.g., for action confirmation)
  PLATFORM_HAL_LED_ERROR // For persistent error indication
} platform_hal_led_t;

typedef struct {
  bool initialized;
  bool led_locked_on;
  bool led_activity_on;
  bool touch_pressed;
  bool touch_held;
  uint32_t tick_count;
} platform_hal_status_t;

void platform_hal_init(void);
void platform_hal_tick(void);
void platform_hal_led_set(platform_hal_led_t led, bool on);
void platform_hal_touch_set_simulated(bool pressed, bool held);
bool platform_hal_usb_hid_type(const char *text); // For typing strings
bool platform_hal_usb_hid_type_char(char c); // For typing individual characters
bool platform_hal_get_status(platform_hal_status_t *out_status);
bool usb_hid_send_report(uint8_t report_id, const uint8_t *data, size_t data_len);
bool usb_hid_poll_report(uint8_t *report_id, uint8_t *data, size_t data_len);
uint32_t platform_hal_get_systick(void); // Function to get system tick for timing
void platform_hal_delay_ms(uint32_t ms); // Function to provide a delay in milliseconds

#endif /* PLATFORM_HAL_H */
