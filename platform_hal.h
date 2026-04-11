#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "stm32u5xx_hal.h"

#define LED1_PIN GPIO_PIN_0
#define LED1_PORT GPIOA
#define LED2_PIN GPIO_PIN_1
#define LED2_PORT GPIOA
#define TOUCH_PIN GPIO_PIN_13
#define TOUCH_PORT GPIOC
#define I2C1_SCL_PIN GPIO_PIN_6
#define I2C1_SCL_PORT GPIOB
#define I2C1_SDA_PIN GPIO_PIN_7
#define I2C1_SDA_PORT GPIOB
#define SPI1_CS_PIN GPIO_PIN_4
#define SPI1_CS_PORT GPIOA
#define SPI1_CLK_PIN GPIO_PIN_5
#define SPI1_CLK_PORT GPIOA
#define SPI1_MISO_PIN GPIO_PIN_6
#define SPI1_MISO_PORT GPIOA
#define SPI1_MOSI_PIN GPIO_PIN_7
#define SPI1_MOSI_PORT GPIOA

typedef enum {
  PLATFORM_HAL_LED_LOCKED,
  PLATFORM_HAL_LED_ACTIVITY,
  PLATFORM_HAL_LED_ERROR,
  PLATFORM_HAL_LED_OFF
} platform_hal_led_t;

typedef struct {
  bool initialized;
  bool touch_pressed;
  bool touch_held;
  bool led_locked_on;
  bool led_activity_on;
  uint32_t tick_count;
} platform_hal_status_t;

void platform_hal_init(void);
void platform_hal_tick(void);
void platform_hal_led_set(platform_hal_led_t led, bool on);
bool platform_hal_touch_read(void);
bool platform_hal_touch_held(void);
bool platform_hal_usb_hid_type(const char *text);
bool platform_hal_get_status(platform_hal_status_t *out_status);

#endif /* PLATFORM_HAL_H */
