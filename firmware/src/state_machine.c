#include "state_machine.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "browser_protocol.h"
#include "crypto_stub.h"
#include "password_store.h"
#include "security_utils.h"

#define LOCKOUT_TICKS_BASE 3u
#define LOCKOUT_TICKS_STEP 2u

static runtime_settings_t g_settings = {
    .auto_popup_enabled = true,
    .manual_popup_requires_touch = true,
    .require_touch_for_fill = true,
    .hold_required_for_selection = true,
    .autolock_seconds = AUTO_LOCK_TIMEOUT_SECONDS_DEFAULT,
};
static uint8_t g_pin_verifier[16];
static bool g_pin_verifier_set = false;

static void reset_unlock_session(device_context_t *ctx) {
    ctx->unlocked = false;
    ctx->inactivity_seconds = 0u;
    if (ctx->state != DEVICE_LOCKED_OUT) {
        ctx->state = DEVICE_LOCKED;
    }
}

void state_machine_init(device_context_t *ctx) {
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = DEVICE_LOCKED;
}

void state_machine_tick(device_context_t *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->state == DEVICE_LOCKED_OUT && ctx->lockout_ticks_remaining > 0u) {
        ctx->lockout_ticks_remaining--;
        if (ctx->lockout_ticks_remaining == 0u && !ctx->wiped) {
            ctx->state = DEVICE_LOCKED;
        }
        return;
    }

    if (!ctx->unlocked || ctx->state == DEVICE_LOCKED_OUT) {
        return;
    }
    ctx->inactivity_seconds++;
    if (ctx->inactivity_seconds >= g_settings.autolock_seconds) {
        reset_unlock_session(ctx);
    }
}

void state_machine_on_touch_tap(device_context_t *ctx) {
    if (ctx == NULL) {
        return;
    }

    ctx->inactivity_seconds = 0u;
    if (!ctx->unlocked) {
        return;
    }

    switch (ctx->state) {
        case DEVICE_PROMPT_FILL:
            ctx->state = DEVICE_CONFIRM_TYPE;
            break;
        case DEVICE_CONFIRM_TYPE:
            ctx->state = DEVICE_UNLOCKED;
            break;
        case DEVICE_PROMPT_SAVE:
            ctx->state = DEVICE_EDIT_CREDENTIAL;
            break;
        default:
            break;
    }
}

void state_machine_on_touch_hold(device_context_t *ctx) {
    if (ctx == NULL) {
        return;
    }

    ctx->inactivity_seconds = 0u;
    if (!ctx->unlocked) {
        return;
    }

    switch (ctx->state) {
        case DEVICE_UNLOCKED:
            ctx->state = DEVICE_SELECT_CREDENTIAL;
            break;
        case DEVICE_PROMPT_FILL:
            /* Hold confirms elevated-risk fill operations. */
            ctx->state = DEVICE_CONFIRM_TYPE;
            break;
        case DEVICE_EDIT_CREDENTIAL:
            /* Hold commits sensitive save/update actions. */
            ctx->state = DEVICE_UNLOCKED;
            break;
        default:
            break;
    }
}

bool state_machine_try_unlock(device_context_t *ctx, const char *pin) {
    bool all_digits = true;
    size_t pin_len = 0u;

    if (ctx == NULL || pin == NULL || ctx->wiped) {
        return false;
    }

    if (ctx->state == DEVICE_LOCKED_OUT && ctx->lockout_ticks_remaining > 0u) {
        return false;
    }

    for (pin_len = 0u; pin[pin_len] != '\0'; ++pin_len) {
        if (pin[pin_len] < '0' || pin[pin_len] > '9') {
            all_digits = false;
            break;
        }
    }

    if (!g_pin_verifier_set) {
        crypto_stub_hash16((const uint8_t *)"12345", 5u, g_pin_verifier);
        g_pin_verifier_set = true;
    }

    {
        uint8_t candidate[16] = {0};
        crypto_stub_hash16((const uint8_t *)pin, pin_len, candidate);
        if (pin_len == PIN_DIGITS && all_digits &&
            sec_consttime_memeq(candidate, g_pin_verifier, sizeof(candidate))) {
            ctx->failed_pin_attempts = 0u;
            ctx->lockout_ticks_remaining = 0u;
            ctx->unlocked = true;
            ctx->state = DEVICE_UNLOCKED;
            ctx->inactivity_seconds = 0u;
            return true;
        }
    }

    ctx->failed_pin_attempts++;
    reset_unlock_session(ctx);

    if (ctx->failed_pin_attempts >= MAX_PIN_FAILURES_BEFORE_WIPE) {
        ctx->wiped = true;
        ctx->state = DEVICE_LOCKED_OUT;
        ctx->lockout_ticks_remaining = 0u;
        return false;
    }

    if (ctx->failed_pin_attempts >= MAX_PIN_FAILURES_BEFORE_LOCKOUT) {
        unsigned int overflow = ctx->failed_pin_attempts - MAX_PIN_FAILURES_BEFORE_LOCKOUT;
        ctx->state = DEVICE_LOCKED_OUT;
        ctx->lockout_ticks_remaining = LOCKOUT_TICKS_BASE + (overflow * LOCKOUT_TICKS_STEP);
    }
    return false;
}

bool state_machine_set_pin(device_context_t *ctx, const char *old_pin, const char *new_pin) {
    size_t old_len = 0u;
    size_t new_len = 0u;
    bool old_digits = true;
    bool new_digits = true;
    uint8_t old_hash[16] = {0};

    if (ctx == NULL || old_pin == NULL || new_pin == NULL || !ctx->unlocked || ctx->wiped) {
        return false;
    }
    for (old_len = 0u; old_pin[old_len] != '\0'; ++old_len) {
        if (old_pin[old_len] < '0' || old_pin[old_len] > '9') {
            old_digits = false;
        }
    }
    for (new_len = 0u; new_pin[new_len] != '\0'; ++new_len) {
        if (new_pin[new_len] < '0' || new_pin[new_len] > '9') {
            new_digits = false;
        }
    }
    if (old_len != PIN_DIGITS || new_len != PIN_DIGITS || !old_digits || !new_digits) {
        return false;
    }
    if (!g_pin_verifier_set) {
        crypto_stub_hash16((const uint8_t *)"12345", 5u, g_pin_verifier);
        g_pin_verifier_set = true;
    }
    crypto_stub_hash16((const uint8_t *)old_pin, old_len, old_hash);
    if (!sec_consttime_memeq(old_hash, g_pin_verifier, sizeof(old_hash))) {
        return false;
    }
    crypto_stub_hash16((const uint8_t *)new_pin, new_len, g_pin_verifier);
    g_pin_verifier_set = true;
    return true;
}

bool state_machine_request_fill(device_context_t *ctx,
                                const credential_record_t *record,
                                const char *origin) {
    BrowserCommand cmd;
    BrowserCommandResult result;
    bool same_origin;

    if (ctx == NULL || record == NULL || origin == NULL) {
        return false;
    }
    if (!ctx->unlocked || ctx->wiped || ctx->state == DEVICE_LOCKED_OUT) {
        return false;
    }

    memset(&cmd, 0, sizeof(cmd));
    cmd.type = BROWSER_CMD_REQUEST_FILL;
    (void)strncpy(cmd.origin, origin, sizeof(cmd.origin) - 1u);
    (void)strncpy(cmd.username, record->username, sizeof(cmd.username) - 1u);
    (void)strncpy(cmd.password, record->password, sizeof(cmd.password) - 1u);
    if (!browser_validate_command(&cmd, &result)) {
        return false;
    }

    same_origin = (strncmp(record->origin, origin, MAX_ORIGIN_LEN) == 0);
    if (!same_origin) {
        /* Phishing protection: never fill mismatched origins. */
        return false;
    }

    ctx->inactivity_seconds = 0u;
    if (g_settings.require_touch_for_fill || record->requires_touch) {
        ctx->state = DEVICE_PROMPT_FILL;
    } else {
        ctx->state = DEVICE_CONFIRM_TYPE;
    }
    return true;
}

bool state_machine_request_save(device_context_t *ctx, const credential_record_t *record) {
    password_policy_result_t policy;
    BrowserCommand cmd;
    BrowserCommandResult result;

    if (ctx == NULL || record == NULL || !ctx->unlocked || ctx->wiped || ctx->state == DEVICE_LOCKED_OUT) {
        return false;
    }

    policy = security_evaluate_password(record->password);
    if (!security_should_allow_save(&policy, false)) {
        /* Save remains blocked until explicit hold override is performed. */
        return false;
    }

    memset(&cmd, 0, sizeof(cmd));
    cmd.type = BROWSER_CMD_REQUEST_SAVE;
    (void)strncpy(cmd.origin, record->origin, sizeof(cmd.origin) - 1u);
    (void)strncpy(cmd.username, record->username, sizeof(cmd.username) - 1u);
    (void)strncpy(cmd.password, record->password, sizeof(cmd.password) - 1u);
    if (!browser_validate_command(&cmd, &result)) {
        return false;
    }

    ctx->state = DEVICE_PROMPT_SAVE;
    ctx->inactivity_seconds = 0u;
    return true;
}

bool state_machine_is_wiped(const device_context_t *ctx) {
    return ctx != NULL && ctx->wiped;
}

unsigned int state_machine_lockout_remaining(const device_context_t *ctx) {
    if (ctx == NULL) {
        return 0u;
    }
    return ctx->lockout_ticks_remaining;
}

void state_machine_apply_settings(const runtime_settings_t *settings) {
    if (settings == NULL) {
        return;
    }
    g_settings = *settings;
    if (g_settings.autolock_seconds == 0u) {
        g_settings.autolock_seconds = AUTO_LOCK_TIMEOUT_SECONDS_DEFAULT;
    }
}

void state_machine_get_settings(runtime_settings_t *out_settings) {
    if (out_settings == NULL) {
        return;
    }
    *out_settings = g_settings;
}

void state_machine_set_pin_verifier(const uint8_t verifier[16]) {
    if (verifier == NULL) {
        return;
    }
    memcpy(g_pin_verifier, verifier, 16u);
    g_pin_verifier_set = true;
}
