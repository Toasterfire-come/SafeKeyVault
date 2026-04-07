#include "state_machine.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "browser_protocol.h"
#include "password_store.h"

static runtime_settings_t g_settings = {
    .auto_popup_enabled = true,
    .manual_popup_requires_touch = true,
    .require_touch_for_fill = true,
    .hold_required_for_selection = true,
    .autolock_seconds = AUTO_LOCK_TIMEOUT_SECONDS_DEFAULT,
};

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
    if (!ctx->unlocked || ctx->state == DEVICE_LOCKED_OUT) {
        return;
    }
    ctx->inactivity_seconds++;
    if (ctx->inactivity_seconds >= g_settings.autolock_seconds) {
        ctx->unlocked = false;
        ctx->state = DEVICE_LOCKED;
        ctx->inactivity_seconds = 0u;
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
    if (ctx == NULL || pin == NULL) {
        return false;
    }

    if (ctx->state == DEVICE_LOCKED_OUT) {
        return false;
    }

    bool all_digits = true;
    for (size_t i = 0; pin[i] != '\0'; ++i) {
        if (pin[i] < '0' || pin[i] > '9') {
            all_digits = false;
            break;
        }
    }

    if (strlen(pin) != PIN_DIGITS || !all_digits || strncmp(pin, "12345", PIN_DIGITS) != 0) {
        ctx->failed_pin_attempts++;
    } else {
        ctx->failed_pin_attempts = 0u;
        ctx->unlocked = true;
        ctx->state = DEVICE_UNLOCKED;
        ctx->inactivity_seconds = 0u;
        return true;
    }

    if (ctx->failed_pin_attempts >= MAX_PIN_FAILURES_BEFORE_LOCKOUT) {
        ctx->state = DEVICE_LOCKED_OUT;
        ctx->unlocked = false;
    }
    return false;
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
    if (!ctx->unlocked) {
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
    if (g_settings.require_touch_for_fill) {
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

    if (ctx == NULL || record == NULL || !ctx->unlocked) {
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
