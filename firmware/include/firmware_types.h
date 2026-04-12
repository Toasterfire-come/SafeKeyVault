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

// New settings added to runtime_settings_t
#define PIN_ATTEMPT_LIMIT_3 3u
#define PIN_ATTEMPT_LIMIT_5 5u
#define PIN_ATTEMPT_LIMIT_10 10u

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
    // Existing settings
    bool auto_popup_enabled;
    bool manual_popup_requires_touch;
    bool require_touch_for_fill;
    bool hold_required_for_selection;
    uint16_t autolock_seconds;

    // New settings
    uint8_t pin_attempt_limit;       // 3/5/10
    bool wipe_on_lockout;
    bool passkeys_enabled;
    bool totp_enabled;
    uint8_t default_account_index;
    bool auto_type_on_plugin;
    uint8_t totp_display_mode;       // e.g., 0 for default, 1 for compact, etc.
} runtime_settings_t;

typedef struct {
    bool exists;
    size_t index;
    size_t count;
} origin_lookup_result_t;

#endif
