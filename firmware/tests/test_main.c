#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "browser_protocol.h"
#include "action_engine.h"
#include "password_generator.h"
#include "password_store.h"
#include "security_policy.h"
#include "state_machine.h"

static void test_state_machine_lockout_and_wipe(void) {
  device_context_t ctx;
  state_machine_init(&ctx);

  for (unsigned i = 0; i < MAX_PIN_FAILURES_BEFORE_LOCKOUT; ++i) {
    assert(!state_machine_try_unlock(&ctx, "00000"));
  }
  assert(ctx.state == DEVICE_LOCKED_OUT);
  assert(state_machine_lockout_remaining(&ctx) > 0u);
  assert(!state_machine_try_unlock(&ctx, "12345"));

  while (state_machine_lockout_remaining(&ctx) > 0u) {
    state_machine_tick(&ctx);
  }
  assert(ctx.state == DEVICE_LOCKED);
  assert(state_machine_try_unlock(&ctx, "12345"));
  assert(ctx.state == DEVICE_UNLOCKED);

  state_machine_init(&ctx);
  for (unsigned i = 0; i < MAX_PIN_FAILURES_BEFORE_WIPE; ++i) {
    assert(!state_machine_try_unlock(&ctx, "99999"));
    while (state_machine_lockout_remaining(&ctx) > 0u) {
      state_machine_tick(&ctx);
    }
  }
  assert(state_machine_is_wiped(&ctx));
  assert(!state_machine_try_unlock(&ctx, "12345"));
}

static void test_state_machine_settings_roundtrip(void) {
  runtime_settings_t in = {
      .auto_popup_enabled = false,
      .manual_popup_requires_touch = true,
      .require_touch_for_fill = true,
      .hold_required_for_selection = true,
      .autolock_seconds = 7u,
  };
  runtime_settings_t out = {0};
  state_machine_apply_settings(&in);
  state_machine_get_settings(&out);
  assert(out.auto_popup_enabled == in.auto_popup_enabled);
  assert(out.manual_popup_requires_touch == in.manual_popup_requires_touch);
  assert(out.require_touch_for_fill == in.require_touch_for_fill);
  assert(out.hold_required_for_selection == in.hold_required_for_selection);
  assert(out.autolock_seconds == in.autolock_seconds);
}

static void test_policy_min_len_and_common(void) {
  password_policy_result_t short_pw = security_evaluate_password("abcd123");
  assert(short_pw.too_short);
  assert(short_pw.strength == PASSWORD_STRENGTH_WEAK);

  password_policy_result_t common_pw = security_evaluate_password("password");
  assert(common_pw.is_common);
  assert(!common_pw.too_short);  // length 8 meets the new minimum
  assert(common_pw.strength != PASSWORD_STRENGTH_STRONG);
}

static void test_password_generator(void) {
  uint8_t seed[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                      0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x12, 0x34};
  char out[96] = {0};

  size_t n =
      password_generate(PASSWORD_PROFILE_STRONG, seed, sizeof(seed), out, sizeof(out));
  assert(n >= PASSWORD_MIN_LENGTH);
  assert(strlen(out) == n);
}

static void test_vault_and_reuse_detection(void) {
  vault_t vault;
  password_store_init(&vault);

  credential_t c1 = {0};
  c1.valid = true;
  c1.id = 1;
  strncpy(c1.origin, "https://example.com", sizeof(c1.origin) - 1);
  strncpy(c1.username, "alice", sizeof(c1.username) - 1);
  strncpy(c1.password_ciphertext, "cipher-blob", sizeof(c1.password_ciphertext) - 1);
  c1.password_fingerprint[0] = 0xAA;
  c1.password_fingerprint[1] = 0xBB;
  assert(password_store_upsert(&vault, &c1));

  credential_t found = {0};
  assert(password_store_find_by_origin(&vault, "https://example.com", &found));
  assert(found.id == 1);

  uint8_t fp[16] = {0};
  fp[0] = 0xAA;
  fp[1] = 0xBB;
  assert(password_store_fingerprint_exists(&vault, fp));
}

static void test_state_machine_touch_gate(void) {
  device_context_t ctx;
  state_machine_init(&ctx);

  assert(!state_machine_try_unlock(&ctx, "1111"));
  assert(ctx.state == DEVICE_LOCKED);
  assert(state_machine_try_unlock(&ctx, "12345"));
  assert(ctx.state == DEVICE_UNLOCKED);

  credential_record_t rec = {0};
  strncpy(rec.origin, "https://github.com", sizeof(rec.origin) - 1);
  strncpy(rec.username, "u", sizeof(rec.username) - 1);
  strncpy(rec.password, "strongpass123!", sizeof(rec.password) - 1);
  rec.requires_touch = true;

  assert(state_machine_request_fill(&ctx, &rec, "https://github.com"));
  assert(ctx.state == DEVICE_PROMPT_FILL);
  state_machine_on_touch_tap(&ctx);
  assert(ctx.state == DEVICE_CONFIRM_TYPE);
  state_machine_on_touch_tap(&ctx);
  assert(ctx.state == DEVICE_UNLOCKED);
}

static void test_browser_suspicious_origin(void) {
  BrowserCommand cmd = {0};
  cmd.type = BROWSER_CMD_REQUEST_FILL;
  strncpy(cmd.origin, "http://xn--googl-fsa.com", sizeof(cmd.origin) - 1);

  BrowserCommandResult res = {0};
  assert(!browser_validate_command(&cmd, &res));
  assert(res.high_risk_origin);
  assert(res.touch_required);
}

static void test_action_engine_fill_save_generate_select(void) {
  device_context_t ctx;
  vault_t vault;
  action_engine_t engine;
  ActionResult out;
  BrowserCommand cmd;

  state_machine_init(&ctx);
  password_store_init(&vault);
  action_engine_init(&engine, &vault, &ctx);
  assert(state_machine_try_unlock(&ctx, "12345"));

  memset(&cmd, 0, sizeof(cmd));
  cmd.type = BROWSER_CMD_REQUEST_SAVE;
  strncpy(cmd.origin, "https://example.com", sizeof(cmd.origin) - 1);
  strncpy(cmd.username, "alice", sizeof(cmd.username) - 1);
  strncpy(cmd.password, "Strong#Pass9", sizeof(cmd.password) - 1);
  assert(action_engine_handle_command(&engine, &cmd, &out));
  assert(out.allowed);
  assert(out.touch_required);
  assert(action_engine_confirm_hold(&engine, &out));
  assert(out.performed);
  assert(vault.count == 1);

  memset(&cmd, 0, sizeof(cmd));
  cmd.type = BROWSER_CMD_REQUEST_FILL;
  strncpy(cmd.origin, "https://example.com", sizeof(cmd.origin) - 1);
  assert(action_engine_handle_command(&engine, &cmd, &out));
  assert(out.allowed);
  assert(action_engine_confirm_tap(&engine, &out));
  assert(out.touch_required);
  assert(action_engine_confirm_tap(&engine, &out));
  assert(out.performed);
  assert(strcmp(out.typed_username, "alice") == 0);
  assert(strcmp(out.typed_password, "Strong#Pass9") == 0);

  memset(&cmd, 0, sizeof(cmd));
  cmd.type = BROWSER_CMD_REQUEST_GENERATE;
  strncpy(cmd.origin, "https://newsite.example", sizeof(cmd.origin) - 1);
  strncpy(cmd.username, "new_user", sizeof(cmd.username) - 1);
  assert(action_engine_handle_command(&engine, &cmd, &out));
  assert(out.allowed);
  assert(out.generated_password);
  assert(strlen(out.generated_value) >= PASSWORD_MIN_LENGTH);
  assert(action_engine_confirm_hold(&engine, &out));
  assert(out.performed);
  assert(vault.count == 2);

  memset(&cmd, 0, sizeof(cmd));
  cmd.type = BROWSER_CMD_REQUEST_SELECT_NEXT;
  assert(action_engine_handle_command(&engine, &cmd, &out));
  assert(out.allowed);
  assert(out.selected_next);
  assert(action_engine_confirm_hold(&engine, &out));
  assert(out.performed);
  assert(out.selected_next);
}

static void test_action_engine_auto_popup_modes(void) {
  device_context_t ctx;
  vault_t vault;
  action_engine_t engine;
  ActionResult out;
  BrowserCommand cmd;
  runtime_settings_t settings = {
      .auto_popup_enabled = false,
      .manual_popup_requires_touch = true,
      .require_touch_for_fill = true,
      .hold_required_for_selection = true,
      .autolock_seconds = 60u,
  };

  state_machine_apply_settings(&settings);
  state_machine_init(&ctx);
  password_store_init(&vault);
  action_engine_init(&engine, &vault, &ctx);
  assert(state_machine_try_unlock(&ctx, "12345"));

  memset(&cmd, 0, sizeof(cmd));
  cmd.type = BROWSER_CMD_REQUEST_SAVE;
  strncpy(cmd.origin, "https://manual.example", sizeof(cmd.origin) - 1);
  strncpy(cmd.username, "manual", sizeof(cmd.username) - 1);
  strncpy(cmd.password, "ManualPass9!", sizeof(cmd.password) - 1);
  assert(action_engine_handle_command(&engine, &cmd, &out));
  assert(out.allowed);
  assert(action_engine_confirm_hold(&engine, &out));
  assert(out.performed);

  memset(&cmd, 0, sizeof(cmd));
  cmd.type = BROWSER_CMD_REQUEST_FILL;
  strncpy(cmd.origin, "https://manual.example", sizeof(cmd.origin) - 1);
  assert(action_engine_handle_command(&engine, &cmd, &out));
  assert(out.allowed);
  assert(!out.save_prompt_recommended);
  assert(action_engine_confirm_hold(&engine, &out));
  assert(!out.performed);
  assert(out.touch_required);
  assert(strstr(out.message, "manual popup") != NULL);

  settings.auto_popup_enabled = true;
  state_machine_apply_settings(&settings);
  assert(action_engine_handle_command(&engine, &cmd, &out));
  assert(out.save_prompt_recommended);
  assert(action_engine_confirm_hold(&engine, &out));
  assert(out.performed);
}

int main(void) {
  test_state_machine_lockout_and_wipe();
  test_state_machine_settings_roundtrip();
  test_policy_min_len_and_common();
  test_password_generator();
  test_vault_and_reuse_detection();
  test_state_machine_touch_gate();
  test_browser_suspicious_origin();
  test_action_engine_fill_save_generate_select();
  test_action_engine_auto_popup_modes();

  puts("firmware tests: OK");
  return 0;
}
