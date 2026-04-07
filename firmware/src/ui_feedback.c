#include "ui_feedback.h"

#include <stdio.h>
#include <string.h>

static ui_led_pattern_t ui_led_for_state(device_state_t state, const ActionResult *action) {
  if (state == DEVICE_LOCKED_OUT) {
    return UI_LED_LOCKED_OUT;
  }
  if (action != NULL && strstr(action->message, "wiped") != NULL) {
    return UI_LED_WIPED;
  }
  if (state == DEVICE_LOCKED) {
    return UI_LED_LOCKED_PULSE;
  }
  if (state == DEVICE_PROMPT_FILL || state == DEVICE_PROMPT_SAVE || state == DEVICE_CONFIRM_TYPE) {
    return UI_LED_SAVE_PROMPT;
  }
  if (state == DEVICE_SELECT_CREDENTIAL) {
    return UI_LED_SELECTION_PENDING;
  }
  if (action != NULL && action->performed &&
      strstr(action->message, "typed credential") != NULL) {
    return UI_LED_TYPING_ACTIVE;
  }
  if (action != NULL && !action->allowed && !action->touch_required) {
    return UI_LED_ERROR_BLINK;
  }
  return UI_LED_UNLOCKED_SOLID;
}

void ui_feedback_from_state(const device_context_t *ctx,
                            const ActionResult *action,
                            ui_status_t *out_status) {
  if (out_status == NULL) {
    return;
  }
  memset(out_status, 0, sizeof(*out_status));
  out_status->led = UI_LED_OFF;

  if (ctx == NULL || action == NULL) {
    (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                   "status unavailable");
    return;
  }

  out_status->led = ui_led_for_state(ctx->state, action);
  out_status->show_touch_hint = action->touch_required;
  out_status->show_hold_hint = action->touch_required &&
                               (strstr(action->message, "hold") != NULL);

  if (action->performed) {
    (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                   "action complete: %s", action->message);
  } else if (action->touch_required) {
    (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                   "waiting for touch: %s", action->message);
  } else if (action->allowed) {
    (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                   "ready: %s", action->message);
  } else {
    (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                   "blocked: %s", action->message);
  }
}
