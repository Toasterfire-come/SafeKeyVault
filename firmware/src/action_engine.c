#include "action_engine.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "browser_protocol.h"
#include "command_codec.h"
#include "crypto_engine.h"
#include "password_generator.h"
#include "password_store.h"
#include "rate_limiter.h"
#include "security_policy.h"
#include "state_machine.h"

static uint32_t g_action_clock = 1u;
static rate_limiter_t g_command_limiter;
static uint8_t g_pin_verifier[16];
static bool g_pin_verifier_set = false;
static uint32_t g_last_nonce = 0u;

static void clear_pending(pending_request_t *pending) {
  if (pending == NULL) {
    return;
  }
  memset(pending, 0, sizeof(*pending));
  pending->kind = ACTION_NONE;
}

static bool is_engine_ready(const action_engine_t *engine) {
  return engine != NULL && engine->vault != NULL && engine->ctx != NULL;
}

static bool load_record_plaintext(const credential_t *entry, credential_record_t *out) {
  if (entry == NULL || out == NULL) {
    return false;
  }
  memset(out, 0, sizeof(*out));
  (void)strncpy(out->origin, entry->origin, sizeof(out->origin) - 1u);
  (void)strncpy(out->username, entry->username, sizeof(out->username) - 1u);
  if (!crypto_engine_decrypt_password(entry->password_ciphertext, out->password, sizeof(out->password))) {
    return false;
  }
  out->updated_at_epoch = entry->updated_at;
  out->requires_touch = true;
  return true;
}

static bool stash_record(const credential_record_t *record, credential_t *out_entry) {
  if (record == NULL || out_entry == NULL) {
    return false;
  }
  memset(out_entry, 0, sizeof(*out_entry));
  out_entry->valid = true;
  (void)strncpy(out_entry->origin, record->origin, sizeof(out_entry->origin) - 1u);
  (void)strncpy(out_entry->username, record->username, sizeof(out_entry->username) - 1u);
  if (!crypto_engine_encrypt_password(record->password, out_entry->password_ciphertext,
                                    sizeof(out_entry->password_ciphertext))) {
    return false;
  }
  out_entry->created_at = record->updated_at_epoch;
  out_entry->updated_at = record->updated_at_epoch;
  crypto_engine_password_fingerprint(record->password, out_entry->password_fingerprint, 16u);
  return true;
}

void action_engine_init(action_engine_t *engine, vault_t *vault, device_context_t *ctx) {
  if (engine == NULL) {
    return;
  }
  memset(engine, 0, sizeof(*engine));
  engine->vault = vault;
  engine->ctx = ctx;
  clear_pending(&engine->pending);
  rate_limiter_init(&g_command_limiter);
  if (!g_pin_verifier_set) {
    crypto_engine_hash16((const uint8_t *)"12345", 5u, g_pin_verifier);
    g_pin_verifier_set = true;
  }
  state_machine_set_pin_verifier(g_pin_verifier);
  g_last_nonce = 0u;
}

bool action_engine_handle_command(action_engine_t *engine,
                                  const BrowserCommand *cmd,
                                  ActionResult *out) {
  BrowserCommandResult browser_result;
  runtime_settings_t settings;
  credential_t entry;
  credential_record_t rec;
  password_policy_result_t policy;
  uint8_t seed[16];
  size_t generated_len;

  if (!is_engine_ready(engine) || cmd == NULL || out == NULL) {
    return false;
  }
  memset(out, 0, sizeof(*out));

  if (cmd->nonce != 0u) {
    if (cmd->nonce <= g_last_nonce) {
      (void)snprintf(out->message, sizeof(out->message), "replay blocked");
      return true;
    }
    g_last_nonce = cmd->nonce;
  }

  if (state_machine_is_wiped(engine->ctx)) {
    (void)snprintf(out->message, sizeof(out->message), "device wiped");
    return true;
  }
  {
    uint32_t retry_after = 0u;
    if (!rate_limiter_allow(&g_command_limiter,
                            cmd->origin[0] ? cmd->origin : "global",
                            g_action_clock++,
                            COMMAND_RATE_WINDOW_SECONDS_DEFAULT,
                            MAX_COMMANDS_PER_WINDOW_DEFAULT,
                            &retry_after)) {
      (void)snprintf(out->message, sizeof(out->message),
                     "rate limited (%u ticks)", retry_after);
      return true;
    }
  }
  if (!engine->ctx->unlocked || engine->ctx->state == DEVICE_LOCKED_OUT) {
    unsigned int wait_ticks = state_machine_lockout_remaining(engine->ctx);
    if (wait_ticks > 0u) {
      (void)snprintf(out->message, sizeof(out->message), "device locked (%u ticks)", wait_ticks);
    } else {
      (void)snprintf(out->message, sizeof(out->message), "device locked");
    }
    return true;
  }

  state_machine_get_settings(&settings);

  if (!browser_validate_command(cmd, &browser_result)) {
    (void)snprintf(out->message, sizeof(out->message), "%s", browser_result.message);
    return true;
  }

  switch (cmd->type) {
    case BROWSER_CMD_REQUEST_FILL:
      if (!password_store_find_by_origin(engine->vault, cmd->origin, &entry)) {
        (void)snprintf(out->message, sizeof(out->message), "no credential for origin");
        return true;
      }
      if (!load_record_plaintext(&entry, &rec)) {
        (void)snprintf(out->message, sizeof(out->message), "decrypt failed");
        return true;
      }
      if (!state_machine_request_fill(engine->ctx, &rec, cmd->origin)) {
        (void)snprintf(out->message, sizeof(out->message), "fill blocked");
        return true;
      }

      clear_pending(&engine->pending);
      engine->pending.kind = ACTION_PENDING_FILL;
      engine->pending.command = *cmd;
      engine->pending.credential = entry;
      engine->manual_popup_armed = false;

      out->allowed = true;
      out->touch_required = settings.manual_popup_requires_touch;
      out->save_prompt_recommended = settings.auto_popup_enabled;
      if (browser_result.high_risk_origin) {
        (void)snprintf(out->message, sizeof(out->message), "hold to confirm high-risk fill");
      } else {
        (void)snprintf(out->message, sizeof(out->message), "touch to confirm fill");
      }
      return true;

    case BROWSER_CMD_REQUEST_SAVE:
      memset(&rec, 0, sizeof(rec));
      (void)strncpy(rec.origin, cmd->origin, sizeof(rec.origin) - 1u);
      (void)strncpy(rec.username, cmd->username, sizeof(rec.username) - 1u);
      (void)strncpy(rec.password, cmd->password, sizeof(rec.password) - 1u);
      rec.updated_at_epoch = g_action_clock++;
      rec.requires_touch = true;

      policy = security_evaluate_password(rec.password);
      out->weak_password_warning = (policy.strength == PASSWORD_STRENGTH_WEAK);
      out->common_password_warning = policy.is_common;
      out->reused_password_warning = policy.is_reused;
      if (policy.too_short) {
        (void)snprintf(out->message, sizeof(out->message), "password too short");
        return true;
      }

      if (!stash_record(&rec, &entry)) {
        (void)snprintf(out->message, sizeof(out->message), "prepare save failed");
        return true;
      }
      entry.id = password_store_next_id(engine->vault);

      clear_pending(&engine->pending);
      engine->pending.kind = ACTION_PENDING_SAVE;
      engine->pending.command = *cmd;
      engine->pending.credential = entry;
      engine->pending.override_with_hold = (policy.is_common || policy.is_reused);
      engine->manual_popup_armed = false;

      out->allowed = true;
      out->touch_required = true;
      out->save_prompt_recommended = settings.auto_popup_enabled;
      if (engine->pending.override_with_hold) {
        (void)snprintf(out->message, sizeof(out->message), "hold required to override warning");
      } else {
        (void)snprintf(out->message, sizeof(out->message), "touch to save");
      }
      return true;

    case BROWSER_CMD_REQUEST_GENERATE:
      memset(seed, 0, sizeof(seed));
      for (size_t i = 0; i < sizeof(seed); ++i) {
        seed[i] = (uint8_t)(cmd->origin[i % sizeof(cmd->origin)] + (uint8_t)i + 31u);
      }
      memset(&rec, 0, sizeof(rec));
      (void)strncpy(rec.origin, cmd->origin, sizeof(rec.origin) - 1u);
      (void)strncpy(rec.username, cmd->username, sizeof(rec.username) - 1u);
      generated_len = password_generate(PASSWORD_PROFILE_STRONG, seed, sizeof(seed),
                                        rec.password, sizeof(rec.password));
      if (generated_len < PASSWORD_MIN_LENGTH) {
        (void)snprintf(out->message, sizeof(out->message), "generation failed");
        return true;
      }
      rec.updated_at_epoch = g_action_clock++;
      rec.requires_touch = true;

      if (!stash_record(&rec, &entry)) {
        (void)snprintf(out->message, sizeof(out->message), "prepare generated save failed");
        return true;
      }
      entry.id = password_store_next_id(engine->vault);

      clear_pending(&engine->pending);
      engine->pending.kind = ACTION_PENDING_GENERATE;
      engine->pending.command = *cmd;
      engine->pending.credential = entry;
      engine->manual_popup_armed = false;

      out->allowed = true;
      out->touch_required = true;
      out->generated_password = true;
      out->save_prompt_recommended = settings.auto_popup_enabled;
      (void)strncpy(out->generated_value, rec.password, sizeof(out->generated_value) - 1u);
      (void)snprintf(out->message, sizeof(out->message), "touch to save generated password");
      return true;

    case BROWSER_CMD_REQUEST_SELECT_NEXT:
      if (engine->vault->count == 0u) {
        (void)snprintf(out->message, sizeof(out->message), "no credentials");
        return true;
      }
      engine->pending.kind = ACTION_PENDING_SELECT;
      engine->pending.pending_index =
          (engine->ctx->selected_credential_idx + 1u) % engine->vault->count;
      engine->ctx->state = DEVICE_SELECT_CREDENTIAL;

      out->allowed = true;
      out->touch_required = true;
      out->selected_next = true;
      out->save_prompt_recommended = false;
      (void)snprintf(out->message, sizeof(out->message), "hold to confirm selection");
      return true;

    default:
      (void)snprintf(out->message, sizeof(out->message), "unsupported command");
      return true;
  }
}

bool action_engine_unlock_with_pin(action_engine_t *engine, const char *pin) {
  if (!is_engine_ready(engine) || pin == NULL) {
    return false;
  }
  return state_machine_try_unlock(engine->ctx, pin);
}

void action_engine_arm_manual_popup(action_engine_t *engine) {
  if (engine == NULL) {
    return;
  }
  engine->manual_popup_armed = true;
}

static bool commit_pending_save(action_engine_t *engine, ActionResult *out, bool hold) {
  bool existed;
  char plaintext[MAX_PASSWORD_LEN];

  if (engine == NULL || out == NULL) {
    return false;
  }

  plaintext[0] = '\0';
  if (!crypto_engine_decrypt_password(engine->pending.credential.password_ciphertext,
                                    plaintext, sizeof(plaintext))) {
    (void)snprintf(out->message, sizeof(out->message), "decrypt pending failed");
    return true;
  }
  if (engine->pending.override_with_hold && !hold) {
    out->touch_required = true;
    (void)snprintf(out->message, sizeof(out->message), "hold required to save");
    return true;
  }

  existed = password_store_exists(engine->vault,
                                  engine->pending.credential.origin,
                                  engine->pending.credential.username);
  if (!password_store_upsert(engine->vault, &engine->pending.credential)) {
    (void)snprintf(out->message, sizeof(out->message), "vault save failed");
    return true;
  }

  out->allowed = true;
  out->performed = true;
  out->updated_existing_record = existed;
  out->created_new_record = !existed;
  (void)snprintf(out->message, sizeof(out->message), "credential saved");
  engine->ctx->state = DEVICE_UNLOCKED;
  clear_pending(&engine->pending);
  return true;
}

bool action_engine_confirm_tap(action_engine_t *engine, ActionResult *out) {
  credential_record_t rec;
  if (!is_engine_ready(engine) || out == NULL) {
    return false;
  }
  memset(out, 0, sizeof(*out));

  if (engine->pending.kind == ACTION_NONE) {
    (void)snprintf(out->message, sizeof(out->message), "no pending action");
    return true;
  }

  state_machine_on_touch_tap(engine->ctx);

  if (engine->pending.kind == ACTION_PENDING_FILL) {
    if (engine->ctx->state == DEVICE_CONFIRM_TYPE) {
      out->allowed = true;
      out->touch_required = true;
      (void)snprintf(out->message, sizeof(out->message), "tap again to type");
      return true;
    }
    if (engine->ctx->state == DEVICE_UNLOCKED) {
      if (!load_record_plaintext(&engine->pending.credential, &rec)) {
        (void)snprintf(out->message, sizeof(out->message), "decrypt failed");
        clear_pending(&engine->pending);
        return true;
      }
      out->allowed = true;
      out->performed = true;
      (void)strncpy(out->typed_username, rec.username, sizeof(out->typed_username) - 1u);
      (void)strncpy(out->typed_password, rec.password, sizeof(out->typed_password) - 1u);
      (void)snprintf(out->message, sizeof(out->message), "typed credential");
      clear_pending(&engine->pending);
      return true;
    }
  } else if (engine->pending.kind == ACTION_PENDING_SAVE ||
             engine->pending.kind == ACTION_PENDING_GENERATE) {
    out->allowed = true;
    out->touch_required = true;
    (void)snprintf(out->message, sizeof(out->message), "hold required to save");
    return true;
  } else if (engine->pending.kind == ACTION_PENDING_SELECT) {
    out->allowed = true;
    out->touch_required = true;
    out->selected_next = true;
    (void)snprintf(out->message, sizeof(out->message), "hold to confirm selection");
    return true;
  }

  (void)snprintf(out->message, sizeof(out->message), "invalid transition");
  clear_pending(&engine->pending);
  return true;
}

bool action_engine_confirm_hold(action_engine_t *engine, ActionResult *out) {
  runtime_settings_t settings;
  if (!is_engine_ready(engine) || out == NULL) {
    return false;
  }
  memset(out, 0, sizeof(*out));

  if (engine->pending.kind == ACTION_NONE) {
    (void)snprintf(out->message, sizeof(out->message), "no pending action");
    return true;
  }

  state_machine_get_settings(&settings);
  state_machine_on_touch_hold(engine->ctx);

  if (engine->pending.kind == ACTION_PENDING_FILL) {
    if (!settings.auto_popup_enabled && settings.manual_popup_requires_touch) {
      if (!engine->manual_popup_armed) {
        out->touch_required = true;
        (void)snprintf(out->message, sizeof(out->message),
                       "auto popup disabled; press manual button first");
        return true;
      }
      engine->manual_popup_armed = false;
    }
    credential_record_t rec;
    if (!load_record_plaintext(&engine->pending.credential, &rec)) {
      (void)snprintf(out->message, sizeof(out->message), "decrypt failed");
      clear_pending(&engine->pending);
      return true;
    }
    out->allowed = true;
    out->performed = true;
    (void)strncpy(out->typed_username, rec.username, sizeof(out->typed_username) - 1u);
    (void)strncpy(out->typed_password, rec.password, sizeof(out->typed_password) - 1u);
    (void)snprintf(out->message, sizeof(out->message), "typed credential");
    engine->ctx->state = DEVICE_UNLOCKED;
    clear_pending(&engine->pending);
    return true;
  }

  if (engine->pending.kind == ACTION_PENDING_SAVE ||
      engine->pending.kind == ACTION_PENDING_GENERATE) {
    return commit_pending_save(engine, out, true);
  }

  if (engine->pending.kind == ACTION_PENDING_SELECT) {
    if (!password_store_get_by_index(engine->vault, engine->pending.pending_index,
                                     &engine->last_selected)) {
      (void)snprintf(out->message, sizeof(out->message), "selection failed");
      clear_pending(&engine->pending);
      return true;
    }
    engine->has_last_selected = true;
    engine->ctx->selected_credential_idx = (unsigned int)engine->pending.pending_index;
    engine->ctx->state = DEVICE_UNLOCKED;
    out->allowed = true;
    out->performed = true;
    out->selected_next = true;
    (void)snprintf(out->message, sizeof(out->message), "credential selected");
    clear_pending(&engine->pending);
    return true;
  }

  (void)snprintf(out->message, sizeof(out->message), "invalid transition");
  clear_pending(&engine->pending);
  return true;
}

bool action_engine_try_change_pin(action_engine_t *engine,
                                  const char *old_pin,
                                  const char *new_pin) {
  if (!is_engine_ready(engine)) {
    return false;
  }
  if (!state_machine_set_pin(engine->ctx, old_pin, new_pin)) {
    return false;
  }
  crypto_engine_hash16((const uint8_t *)new_pin, strlen(new_pin), g_pin_verifier);
  g_pin_verifier_set = true;
  state_machine_set_pin_verifier(g_pin_verifier);
  return true;
}

bool action_engine_device_save_credential(action_engine_t *engine,
                                          const char *origin,
                                          const char *username,
                                          const char *password,
                                          ActionResult *out) {
  BrowserCommand cmd;
  if (!is_engine_ready(engine) || origin == NULL || username == NULL || password == NULL || out == NULL) {
    return false;
  }
  memset(&cmd, 0, sizeof(cmd));
  cmd.type = BROWSER_CMD_REQUEST_SAVE;
  (void)strncpy(cmd.origin, origin, sizeof(cmd.origin) - 1u);
  (void)strncpy(cmd.username, username, sizeof(cmd.username) - 1u);
  (void)strncpy(cmd.password, password, sizeof(cmd.password) - 1u);
  cmd.nonce = 0u;
  if (!action_engine_handle_command(engine, &cmd, out)) {
    return false;
  }
  if (!out->allowed) {
    return true;
  }
  return action_engine_confirm_hold(engine, out);
}

bool action_engine_device_fill_current(action_engine_t *engine,
                                       const char *origin,
                                       ActionResult *out) {
  BrowserCommand cmd;
  if (!is_engine_ready(engine) || origin == NULL || out == NULL) {
    return false;
  }
  memset(&cmd, 0, sizeof(cmd));
  cmd.type = BROWSER_CMD_REQUEST_FILL;
  (void)strncpy(cmd.origin, origin, sizeof(cmd.origin) - 1u);
  cmd.nonce = 0u;
  if (!action_engine_handle_command(engine, &cmd, out)) {
    return false;
  }
  if (!out->allowed) {
    return true;
  }
  return action_engine_confirm_hold(engine, out);
}

bool action_engine_device_generate_for_origin(action_engine_t *engine,
                                              const char *origin,
                                              const char *username,
                                              ActionResult *out) {
  BrowserCommand cmd;
  if (!is_engine_ready(engine) || origin == NULL || out == NULL) {
    return false;
  }
  memset(&cmd, 0, sizeof(cmd));
  cmd.type = BROWSER_CMD_REQUEST_GENERATE;
  (void)strncpy(cmd.origin, origin, sizeof(cmd.origin) - 1u);
  if (username != NULL) {
    (void)strncpy(cmd.username, username, sizeof(cmd.username) - 1u);
  }
  cmd.nonce = 0u;
  if (!action_engine_handle_command(engine, &cmd, out)) {
    return false;
  }
  if (!out->allowed) {
    return true;
  }
  return action_engine_confirm_hold(engine, out);
}

bool action_engine_device_select_next(action_engine_t *engine, ActionResult *out) {
  BrowserCommand cmd;
  if (!is_engine_ready(engine) || out == NULL) {
    return false;
  }
  memset(&cmd, 0, sizeof(cmd));
  cmd.type = BROWSER_CMD_REQUEST_SELECT_NEXT;
  cmd.nonce = 0u;
  if (!action_engine_handle_command(engine, &cmd, out)) {
    return false;
  }
  if (!out->allowed) {
    return true;
  }
  return action_engine_confirm_hold(engine, out);
}

bool action_engine_popup_open(action_engine_t *engine, ActionResult *out) {
  runtime_settings_t settings;
  if (!is_engine_ready(engine) || out == NULL) {
    return false;
  }
  state_machine_get_settings(&settings);
  settings.auto_popup_enabled = true;
  settings.manual_popup_requires_touch = false;
  settings.require_touch_for_fill = false;
  settings.hold_required_for_selection = false;
  state_machine_apply_settings(&settings);

  memset(out, 0, sizeof(*out));
  out->allowed = true;
  out->touch_required = false;
  out->performed = true;
  (void)snprintf(out->message, sizeof(out->message),
                 "settings popup open");
  return true;
}

bool action_engine_device_open_settings(action_engine_t *engine, ActionResult *out) {
  return action_engine_popup_open(engine, out);
}

bool action_engine_device_apply_settings(action_engine_t *engine,
                                         const runtime_settings_t *settings,
                                         ActionResult *out) {
  runtime_settings_t applied;
  if (!is_engine_ready(engine) || settings == NULL || out == NULL) {
    return false;
  }
  if (!engine->ctx->unlocked || engine->ctx->state == DEVICE_LOCKED_OUT ||
      state_machine_is_wiped(engine->ctx)) {
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->message, sizeof(out->message), "device locked");
    return true;
  }

  applied = *settings;
  /* Enforce requested interaction model:
   * - single press triggers fill
   * - hold opens settings/modify mode
   * No extra gesture gates are permitted through runtime settings.
   */
  applied.auto_popup_enabled = true;
  applied.manual_popup_requires_touch = false;
  applied.require_touch_for_fill = false;
  applied.hold_required_for_selection = false;
  if (applied.autolock_seconds == 0u) {
    applied.autolock_seconds = AUTO_LOCK_TIMEOUT_SECONDS_DEFAULT;
  }
  state_machine_apply_settings(&applied);

  memset(out, 0, sizeof(*out));
  out->allowed = true;
  out->performed = true;
  (void)snprintf(out->message, sizeof(out->message), "settings updated");
  return true;
}

bool action_engine_device_modify_password(action_engine_t *engine,
                                          const char *origin,
                                          const char *username,
                                          const char *new_password,
                                          ActionResult *out) {
  if (!is_engine_ready(engine) || origin == NULL || username == NULL ||
      new_password == NULL || out == NULL) {
    return false;
  }
  return action_engine_device_save_credential(engine, origin, username, new_password, out);
}

bool action_engine_button_press(action_engine_t *engine, const char *origin, ActionResult *out) {
  credential_t ignored;
  if (!is_engine_ready(engine) || out == NULL) {
    return false;
  }
  if (origin == NULL || origin[0] == '\0' ||
      !password_store_find_by_origin(engine->vault, origin, &ignored)) {
    return action_engine_popup_open(engine, out);
  }
  return action_engine_device_fill_current(engine, origin, out);
}

bool action_engine_button_hold(action_engine_t *engine, ActionResult *out) {
  if (!is_engine_ready(engine) || out == NULL) {
    return false;
  }
  return action_engine_popup_open(engine, out);
}
