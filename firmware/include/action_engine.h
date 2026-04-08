#ifndef ACTION_ENGINE_H
#define ACTION_ENGINE_H

#include <stdbool.h>
#include <stddef.h>

#include "browser_protocol.h"
#include "password_store.h"
#include "state_machine.h"

typedef enum {
  ACTION_NONE = 0,
  ACTION_PENDING_FILL,
  ACTION_PENDING_SAVE,
  ACTION_PENDING_GENERATE,
  ACTION_PENDING_SELECT
} pending_action_t;

typedef struct {
  bool allowed;
  bool touch_required;
  bool performed;
  bool save_prompt_recommended;
  bool weak_password_warning;
  bool common_password_warning;
  bool reused_password_warning;
  bool created_new_record;
  bool updated_existing_record;
  bool generated_password;
  bool selected_next;
  char typed_username[MAX_USERNAME_LEN];
  char typed_password[MAX_PASSWORD_LEN];
  char generated_value[MAX_PASSWORD_LEN];
  char message[96];
} ActionResult;

typedef struct {
  pending_action_t kind;
  credential_t credential;
  BrowserCommand command;
  bool override_with_hold;
  size_t pending_index;
} pending_request_t;

typedef struct {
  vault_t *vault;
  device_context_t *ctx;
  pending_request_t pending;
  credential_t last_selected;
  bool has_last_selected;
  bool manual_popup_armed;
} action_engine_t;

typedef enum {
  DEVICE_OP_FILL_SELECTED = 0,
  DEVICE_OP_SAVE_CURRENT,
  DEVICE_OP_GENERATE_FOR_CURRENT,
  DEVICE_OP_SELECT_NEXT
} device_action_t;

void action_engine_init(action_engine_t *engine, vault_t *vault, device_context_t *ctx);
bool action_engine_handle_command(action_engine_t *engine,
                                  const BrowserCommand *cmd,
                                  ActionResult *out);
bool action_engine_unlock_with_pin(action_engine_t *engine, const char *pin);
bool action_engine_try_change_pin(action_engine_t *engine,
                                  const char *old_pin,
                                  const char *new_pin);
bool action_engine_set_active_site(action_engine_t *engine,
                                   const char *origin,
                                   const char *username,
                                   const char *password_hint);
bool action_engine_device_request(action_engine_t *engine,
                                  device_action_t action,
                                  ActionResult *out);
void action_engine_arm_manual_popup(action_engine_t *engine);
bool action_engine_confirm_tap(action_engine_t *engine, ActionResult *out);
bool action_engine_confirm_hold(action_engine_t *engine, ActionResult *out);

#endif
