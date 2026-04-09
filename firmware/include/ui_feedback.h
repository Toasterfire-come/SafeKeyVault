#ifndef UI_FEEDBACK_H
#define UI_FEEDBACK_H

#include <stdbool.h>

#include "action_engine.h"
#include "state_machine.h"

typedef enum {
  UI_LED_OFF = 0,
  UI_LED_LOCKED_PULSE,
  UI_LED_UNLOCKED_SOLID,
  UI_LED_ERROR_BLINK,
  UI_LED_TYPING_ACTIVE,
  UI_LED_SAVE_PROMPT,
  UI_LED_SELECTION_PENDING,
  UI_LED_LOCKED_OUT,
  UI_LED_WIPED
} ui_led_pattern_t;

typedef struct {
  ui_led_pattern_t led;
  bool show_touch_hint;
  bool show_hold_hint;
  char status_text[96];
} ui_status_t;

void ui_feedback_from_state(const device_context_t *ctx,
                            const ActionResult *action,
                            ui_status_t *out_status);

#endif /* UI_FEEDBACK_H */
