#ifndef FIRMWARE_TYPES_H
#define FIRMWARE_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_ORIGIN_LEN 128
#define MAX_USERNAME_LEN 96
#define MAX_PASSWORD_LEN 128
#define MAX_SITE_CREDENTIALS 16
#define MAX_STORED_CREDENTIALS 64
#define PASSWORD_FINGERPRINT_BYTES 32

typedef enum {
    DEVICE_LOCKED = 0,
    DEVICE_UNLOCKED,
    DEVICE_PROMPT_FILL,
    DEVICE_PROMPT_SAVE,
    DEVICE_SELECT_CREDENTIAL,
    DEVICE_EDIT_CREDENTIAL,
    DEVICE_CONFIRM_TYPE,
    DEVICE_FIDO_PROMPT,
    DEVICE_LOCKED_OUT
} device_state_t;

typedef struct {
    char origin[MAX_ORIGIN_LEN];
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    uint32_t updated_at_epoch;
    bool auto_type_enabled;
    bool requires_touch;
} credential_record_t;

typedef struct {
    uint8_t data[PASSWORD_FINGERPRINT_BYTES];
} password_fingerprint_t;

typedef struct {
    uint8_t min_length;
    bool allow_common_passwords;
    bool allow_reused_passwords;
} password_policy_t;

typedef struct {
    bool auto_popup_enabled;
    bool manual_popup_requires_touch;
    bool require_touch_for_fill;
    bool hold_required_for_selection;
    uint16_t autolock_seconds;
} runtime_settings_t;

typedef struct {
    bool exists;
    size_t index;
    size_t count;
} origin_lookup_result_t;

#endif
