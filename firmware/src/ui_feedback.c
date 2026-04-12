#include "ui_feedback.h"

#include <stdio.h>
#include <string.h>

static ui_led_pattern_t ui_led_for_state(device_state_t state, const ActionResult *action) {
  // Priorities for LED patterns:
  // 1. Wiped (if indicated in action message)
  // 2. Locked Out
  // 3. Locked
  // 4. Error/Blocked (if action indicates failure)
  // 5. Typing Active (if action indicates credential typing)
  // 6. Prompt/Pending (Fill, Save, Select)
  // 7. Unlocked Solid (default when unlocked and no other explicit state)
  // 8. Off (otherwise, or uninitialized state)

  if (action != NULL && strnstr(action->message, "wiped", sizeof(action->message)) != NULL) {
    return UI_LED_WIPED;
  }
  if (state == DEVICE_LOCKED_OUT) {
    return UI_LED_LOCKED_OUT;
  }
  if (action != NULL && !action->allowed && !action->touch_required) {
    return UI_LED_ERROR_BLINK;
  }
  if (state == DEVICE_LOCKED) {
    return UI_LED_LOCKED_PULSE;
  }
  if (action != NULL && action->performed &&
      strnstr(action->message, "typed credential", sizeof(action->message)) != NULL) {
    return UI_LED_TYPING_ACTIVE;
  }
  if (state == DEVICE_PROMPT_FILL || state == DEVICE_PROMPT_SAVE || state == DEVICE_CONFIRM_TYPE) {
    return UI_LED_SAVE_PROMPT;
  }
  if (state == DEVICE_SELECT_CREDENTIAL) {
    return UI_LED_SELECTION_PENDING;
  }
  // Handle action == NULL gracefully for idle path
  if (state == DEVICE_UNLOCKED) { // This condition should ideally check for unlocked state without any pending UI action
      return UI_LED_UNLOCKED_SOLID;
  }

  // Default to OFF if no other pattern matches, or if context is uninitialized
  return UI_LED_OFF;
}

void ui_feedback_from_state(const device_context_t *ctx,
                            const ActionResult *action,
                            ui_status_t *out_status) {
  if (out_status == NULL) {
    return;
  }
  memset(out_status, 0, sizeof(*out_status));
  out_status->led = UI_LED_OFF;

  // Handle ctx == NULL gracefully
  if (ctx == NULL) {
    (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                   "status unavailable");
    return;
  }

  out_status->led = ui_led_for_state(ctx->state, action);
  out_status->show_touch_hint = action != NULL && action->touch_required;
  // Use strnstr for safety, specifying buffer length (action->message is char[96])
  out_status->show_hold_hint = action != NULL && action->touch_required &&
                               (strnstr(action->message, "hold", sizeof(action->message)) != NULL);

  if (action != NULL) {
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
  } else {
      // Idle path when action is NULL
      // Default messages for states without a specific action
      switch (ctx->state) {
          case DEVICE_UNLOCKED:
              (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                             "unlocked");
              break;
          case DEVICE_LOCKED:
              (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                             "locked");
              break;
          case DEVICE_LOCKED_OUT:
              (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                             "locked out");
              break;
          case DEVICE_PROMPT_FILL:
              (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                             "prompt to fill");
              break;
          case DEVICE_PROMPT_SAVE:
              (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                             "prompt to save");
              break;
          case DEVICE_CONFIRM_TYPE:
              (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                             "confirm typing");
              break;
          case DEVICE_SELECT_CREDENTIAL:
              (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                             "select credential");
              break;
          case DEVICE_EDIT_CREDENTIAL:
              (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                             "edit credential");
              break;
          case DEVICE_FIDO_PROMPT:
              (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                             "FIDO request");
              break;
          default:
              (void)snprintf(out_status->status_text, sizeof(out_status->status_text),
                             "unknown state");
              break;
      }
  }
}
