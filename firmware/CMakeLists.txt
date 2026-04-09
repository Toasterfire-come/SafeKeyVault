cmake_minimum_required(VERSION 3.13)
project(rp2040_password_key_firmware C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
option(FIRMWARE_PRODUCTION "Enable production hardening mode" OFF)

add_library(firmware_core
  src/action_engine.c
  src/storage_backend.c
  src/command_codec.c
  src/crypto_engine.c
  src/secure_boot.c
  src/usb_session.c
  src/fido2_authenticator.c
  src/platform_hal.c
  src/rate_limiter.c
  src/security_utils.c
  src/settings_store.c
  src/ui_feedback.c
  src/crypto_stub.c
  src/state_machine.c
  src/password_policy.c
  src/password_generator.c
  src/browser_protocol.c
  src/common_passwords.c
  src/vault.c
)

target_include_directories(firmware_core
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(FIRMWARE_PRODUCTION)
  target_compile_definitions(firmware_core PUBLIC FIRMWARE_PRODUCTION=1)
else()
  target_compile_definitions(firmware_core PUBLIC FIRMWARE_PRODUCTION=0)
endif()

add_executable(firmware_tests
  tests/test_main.c
)

target_link_libraries(firmware_tests
  PRIVATE firmware_core
)

enable_testing()
add_test(NAME firmware_tests COMMAND firmware_tests)
