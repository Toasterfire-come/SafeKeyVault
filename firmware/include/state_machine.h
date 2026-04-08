#ifndef STATE_MACHINE_H
#define STATE_MACHINE_H

#include <stdbool.h>
#include "firmware_types.h"
#include "security_policy.h"

typedef struct {
    device_state_t state;
    bool unlocked;
    bool wiped;
    unsigned int failed_pin_attempts;
    unsigned int inactivity_seconds;
    unsigned int lockout_ticks_remaining;
    unsigned int selected_credential_idx;
} device_context_t;

void state_machine_init(device_context_t *ctx);
void state_machine_tick(device_context_t *ctx);
void state_machine_on_touch_tap(device_context_t *ctx);
void state_machine_on_touch_hold(device_context_t *ctx);
bool state_machine_try_unlock(device_context_t *ctx, const char *pin);
bool state_machine_set_pin(device_context_t *ctx, const char *old_pin, const char *new_pin);
bool state_machine_request_fill(
    device_context_t *ctx,
    const credential_record_t *record,
    const char *origin
);
bool state_machine_request_save(
    device_context_t *ctx,
    const credential_record_t *record
);
bool state_machine_is_wiped(const device_context_t *ctx);
unsigned int state_machine_lockout_remaining(const device_context_t *ctx);
void state_machine_apply_settings(const runtime_settings_t *settings);
void state_machine_get_settings(runtime_settings_t *out_settings);
void state_machine_set_pin_verifier(const uint8_t verifier[16]);

#endif
