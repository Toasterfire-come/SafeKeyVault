cmake_minimum_required(VERSION 3.13)
project(stm32u5_password_key_firmware C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Toolchain configuration for ARM Cortex-M33
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Set the cross-compilation toolchain
# Ensure arm-none-eabi-gcc is in your PATH or set CMAKE_C_COMPILER explicitly
# Example: set(CMAKE_C_COMPILER ${CMAKE_BINARY_DIR}/../toolchains/arm-none-eabi/bin/arm-none-eabi-gcc)
set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_CXX_COMPILER arm-none-eabi-g++) # Assuming C++ might be used later

# CPU and FPU specific flags for Cortex-M33
set(CMAKE_C_FLAGS_DEFAULT "${CMAKE_C_FLAGS_DEFAULT} -mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard")
set(CMAKE_CXX_FLAGS_DEFAULT "${CMAKE_CXX_FLAGS_DEFAULT} -mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard")

# Optimization flags
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Os -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Os -DNDEBUG")

# Define the target microcontroller
set(MICROCONTROLLER STM32U585AIIX)

# Include directories
include_directories(
    include
    Drivers/STM32U5xx_HAL_Driver/Inc
    Drivers/CMSIS/Device/ST/STM32U5xx/Include
)

# Source files
set(FIRMWARE_SOURCES
    src/platform_hal.c
    src/crypto_engine.c
    src/storage_backend.c
    src/usb_session.c
    src/fido2_authenticator.c
    src/state_machine.c
    src/vault.c
    src/settings_store.c
    src/action_engine.c
    src/browser_protocol.c
    src/command_codec.c
    src/rate_limiter.c
    src/secure_boot.c
    src/security_utils.c
    src/ui_feedback.c
    src/totp.c
    # Add STM32CubeU5 HAL driver sources here if not managed by a separate library
    # Example: Drivers/STM32U5xx_HAL_Driver/Src/stm32u5xx_hal_uart.c
    # ... and so on for all necessary HAL drivers
)

add_executable(firmware ${FIRMWARE_SOURCES})

# Linker script
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -TSTM32U585AIIX_FLASH.ld")

# Link against CMSIS core library (usually provided by CMSIS-Core package)
# You might need to find and link against the appropriate CMSIS core library.
# Example: target_link_libraries(firmware PRIVATE cmsis_core)

# Add any other necessary libraries (e.g., FreeRTOS if used)
# target_link_libraries(firmware PRIVATE freertos)

# Define the target microcontroller for the compiler
target_compile_definitions(firmware PRIVATE ${MICROCONTROLLER}=1)

# Enable production hardening if FIRMWARE_PRODUCTION is ON
if(FIRMWARE_PRODUCTION)
  target_compile_definitions(firmware PUBLIC FIRMWARE_PRODUCTION=1)
else()
  target_compile_definitions(firmware PUBLIC FIRMWARE_PRODUCTION=0)
endif()

# Add STM32U5 specific defines
target_compile_definitions(firmware PRIVATE
    "USE_HAL_DRIVER"
    "STM32U5xx"
)

# Enable testing
enable_testing()

# Add a test executable (if you have tests)
# add_executable(firmware_tests tests/test_main.c)
# target_link_libraries(firmware_tests PRIVATE firmware)
# add_test(NAME firmware_tests COMMAND firmware_tests)
