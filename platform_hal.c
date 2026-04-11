#include "platform_hal.h"
#include "stm32u5xx_hal.h"

// Mock platform HAL state for host tests.
typedef struct {
  bool initialized;
  bool led_locked_on;
  bool led_activity_on;
  bool touch_pressed;
  bool touch_held;
  uint32_t tick_count;
} platform_hal_state_t;

static platform_hal_state_t g_hal;
static uint32_t systick_counter = 0;

void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_I2C1_Init(void);
static void MX_SPI1_Init(void);
static void MX_OCTOSPI1_Init(void);
static void MX_USB_PCD_Init(void);

void platform_hal_init(void) {
  HAL_Init();
  SystemClock_Config();
  MX_GPIO_Init();
  MX_I2C1_Init();
  MX_SPI1_Init();
  MX_OCTOSPI1_Init();
  MX_USB_PCD_Init();
  g_hal.initialized = true;
}

void SystemClock_Config(void) {
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 10;
  RCC_OscInitStruct.PLL.PLLN = 256;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 8;
  RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV2;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK) {
    Error_Handler();
  }
}

static void MX_GPIO_Init(void) {
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();

  GPIO_InitTypeDef GPIO_InitStruct = {0};

  // Configure PA0 and PA1 as GPIO_OUTPUT push-pull for LEDs
  GPIO_InitStruct.Pin = GPIO_PIN_0 | GPIO_PIN_1;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

  // Configure PC13 as GPIO_INPUT with GPIO_PULLDOWN for touch
  GPIO_InitStruct.Pin = GPIO_PIN_13;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_PULLDOWN;
  HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);
}

static void MX_I2C1_Init(void) {
  hi2c1.Instance = I2C1;
  hi2c1.Init.ClockSpeed = 400000;
  hi2c1.Init.DutyCycle = I2C_DUTYCYCLE_2;
  hi2c1.Init.OwnAddress1 = 0;
  hi2c1.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
  hi2c1.Init.DualAddressMode = I2C_DUALADDRESS_DISABLE;
  hi2c1.Init.OwnAddress2 = 0;
  hi2c1.Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
  hi2c1.Init.NoStretchMode = I2C_NOSTRETCH_DISABLE;
  if (HAL_I2C_Init(&hi2c1) != HAL_OK) {
    Error_Handler();
  }
}

static void MX_SPI1_Init(void) {
  hspi1.Instance = SPI1;
  hspi1.Init.Mode = SPI_MODE_MASTER;
  hspi1.Init.Direction = SPI_DIRECTION_2LINES;
  hspi1.Init.DataSize = SPI_DATASIZE_8BIT;
  hspi1.Init.CLKPolarity = SPI_POLARITY_LOW;
  hspi1.Init.CLKPhase = SPI_PHASE_1EDGE;
  hspi1.Init.NSS = SPI_NSS_SOFT;
  hspi1.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_2;
  hspi1.Init.FirstBit = SPI_FIRSTBIT_MSB;
  hspi1.Init.TIMode = SPI_TIMODE_DISABLE;
  hspi1.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
  hspi1.Init.CRCPolynomial = 7;
  if (HAL_SPI_Init(&hspi1) != HAL_OK) {
    Error_Handler();
  }
}

static void MX_OCTOSPI1_Init(void) {
  hospi1.Instance = OCTOSPI1;
  hospi1.Init.ClockPrescaler = 2;
  hospi1.Init.DualOutputEnable = HAL_FALSE;
  hospi1.Init.AddressHoldTime = 0;
  hospi1.Init.AddressSetupTime = 1;
  hospi1.Init.BurstLength = 1;
  hospi1.Init.ClockMode = 0;
  hospi1.Init.DeviceType = OCTOSPI_DEVICE_TYPE_MACRONIX;
  hospi1.Init.DQSMode = HAL_FALSE;
  hospi1.Init.Mode = OCTOSPI_MODE_SERIAL;
  hospi1.Init.NumberOfClkCycles = 2;
  hospi1.Init.OctalDTRMode = HAL_FALSE;
  hospi1.Init.SIOOMode = HAL_FALSE;
  hospi1.Init.StatusRegisterSize = 0;
  hospi1.Init.TimeOutValue = 0xFFFFFFFF;
  if (HAL_OCTOSPI_Init(&hospi1) != HAL_OK) {
    Error_Handler();
  }
}

static void MX_USB_PCD_Init(void) {
  hpcd_USB_OTG_FS.Instance = USB_OTG_FS;
  hpcd_USB_OTG_FS.Init.dev_endpoints = 4;
  hpcd_USB_OTG_FS.Init.speed = PCD_SPEED_FULL;
  hpcd_USB_OTG_FS.Init.phy_itface = PCD_PHY_EMBEDDED;
  hpcd_USB_OTG_FS.Init.low_power_enable = DISABLE;
  hpcd_USB_OTG_FS.Init.vbus_sensing_enable = ENABLE;
  hpcd_USB_OTG_FS.Init.use_dedicated_ep0 = DISABLE;
  if (HAL_PCD_Init(&hpcd_USB_OTG_FS) != HAL_OK) {
    Error_Handler();
  }
}

void platform_hal_led_set(platform_hal_led_t led, bool on) {
  switch (led) {
    case PLATFORM_HAL_LED_LOCKED:
      HAL_GPIO_WritePin(GPIOA, GPIO_PIN_0, on ? GPIO_PIN_SET : GPIO_PIN_RESET);
      break;
    case PLATFORM_HAL_LED_ACTIVITY:
      HAL_GPIO_WritePin(GPIOA, GPIO_PIN_1, on ? GPIO_PIN_SET : GPIO_PIN_RESET);
      break;
    default:
      // Other LEDs are not explicitly managed here
      break;
  }
}

bool platform_hal_touch_read(void) {
  return HAL_GPIO_ReadPin(GPIOC, GPIO_PIN_13) == GPIO_PIN_RESET;
}

bool platform_hal_touch_held(void) {
  static bool last_state = false;
  bool current_state = HAL_GPIO_ReadPin(GPIOC, GPIO_PIN_13);
  if (current_state != last_state) {
    last_state = current_state;
    return true;
  }
  return false;
}

void platform_hal_usb_hid_type(const char *text) {
  // Implement HID keyboard report sending here
}

void platform_hal_tick(void) {
  systick_counter++;
}

uint32_t platform_hal_get_tick_count(void) {
  return systick_counter;
}
