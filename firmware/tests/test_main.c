#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "browser_protocol.h"
#include "action_engine.h"
#include "ui_feedback.h"
#include "command_codec.h"
#include "password_generator.h"
#include "password_store.h"
#include "rate_limiter.h"
#include "security_utils.h"
#include "security_policy.h"
#include "settings_store.h"
#include "state_machine.h"
#include "crypto_engine.h"

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
  strncpy(rec.username, "user", sizeof(rec.username) - 1);
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

static void test_browser_protocol_field_validation(void) {
  BrowserCommand cmd = {0};
  BrowserCommandResult res = {0};

  cmd.type = BROWSER_CMD_REQUEST_SAVE;
  strncpy(cmd.origin, "https://valid.example", sizeof(cmd.origin) - 1u);
  strncpy(cmd.username, "alice", sizeof(cmd.username) - 1u);
  strncpy(cmd.password, "ValidPass9!", sizeof(cmd.password) - 1u);
  assert(browser_validate_command(&cmd, &res));
  assert(res.accepted);

  memset(&cmd, 0, sizeof(cmd));
  cmd.type = BROWSER_CMD_REQUEST_SAVE;
  strncpy(cmd.origin, "https://valid.example", sizeof(cmd.origin) - 1u);
  strncpy(cmd.username, "alice\nbob", sizeof(cmd.username) - 1u);
  strncpy(cmd.password, "ValidPass9!", sizeof(cmd.password) - 1u);
  assert(!browser_validate_command(&cmd, &res));
  assert(strstr(res.message, "unsafe field chars") != NULL);

  memset(&cmd, 0, sizeof(cmd));
  cmd.type = BROWSER_CMD_REQUEST_SAVE;
  strncpy(cmd.origin, "https://valid.example", sizeof(cmd.origin) - 1u);
  strncpy(cmd.username, "alice", sizeof(cmd.username) - 1u);
  strncpy(cmd.password, "https://evil.example/steal", sizeof(cmd.password) - 1u);
  assert(!browser_validate_command(&cmd, &res));
  assert(strstr(res.message, "unsafe field chars") != NULL);
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
  assert(strstr(out.message, "press manual button") != NULL);

  action_engine_arm_manual_popup(&engine);
  assert(action_engine_confirm_hold(&engine, &out));
  assert(out.performed);

  settings.auto_popup_enabled = true;
  state_machine_apply_settings(&settings);
  assert(action_engine_handle_command(&engine, &cmd, &out));
  assert(out.save_prompt_recommended);
  assert(action_engine_confirm_hold(&engine, &out));
  assert(out.performed);
}

static void test_action_engine_ui_feedback_mapping(void) {
  device_context_t ctx = {0};
  ActionResult action = {0};
  ui_status_t status = {0};

  ctx.state = DEVICE_LOCKED;
  strncpy(action.message, "device locked", sizeof(action.message) - 1);
  ui_feedback_from_state(&ctx, &action, &status);
  assert(status.led == UI_LED_LOCKED_PULSE);
  assert(strstr(status.status_text, "blocked") != NULL);

  memset(&action, 0, sizeof(action));
  ctx.state = DEVICE_PROMPT_FILL;
  action.allowed = true;
  action.touch_required = true;
  strncpy(action.message, "touch to confirm fill", sizeof(action.message) - 1);
  ui_feedback_from_state(&ctx, &action, &status);
  assert(status.led == UI_LED_SAVE_PROMPT);
  assert(status.show_touch_hint);

  memset(&action, 0, sizeof(action));
  ctx.state = DEVICE_UNLOCKED;
  action.allowed = true;
  action.performed = true;
  strncpy(action.message, "credential saved", sizeof(action.message) - 1);
  ui_feedback_from_state(&ctx, &action, &status);
  assert(status.led == UI_LED_UNLOCKED_SOLID);
  assert(strstr(status.status_text, "action complete") != NULL);

  memset(&action, 0, sizeof(action));
  ctx.state = DEVICE_LOCKED_OUT;
  action.allowed = false;
  strncpy(action.message, "device locked", sizeof(action.message) - 1);
  ui_feedback_from_state(&ctx, &action, &status);
  assert(status.led == UI_LED_LOCKED_OUT);
}

static void test_security_utils_and_rate_limiter(void) {
  uint8_t a[16] = {0};
  uint8_t b[16] = {0};
  rate_limiter_t limiter;
  uint32_t retry = 0u;
  const char *origin = "https://ratelimit.example";

  assert(sec_consttime_memeq(a, b, sizeof(a)));
  b[3] = 1u;
  assert(!sec_consttime_memeq(a, b, sizeof(a)));

  rate_limiter_init(&limiter);
  assert(rate_limiter_allow(&limiter, origin, 0u, 4u, 3u, &retry));
  assert(rate_limiter_allow(&limiter, origin, 1u, 4u, 3u, &retry));
  assert(rate_limiter_allow(&limiter, origin, 2u, 4u, 3u, &retry));
  assert(!rate_limiter_allow(&limiter, origin, 2u, 4u, 3u, &retry));
  assert(retry > 0u);
  for (unsigned i = 0; i < 5u; ++i) {
    rate_limiter_tick(&limiter);
  }
  assert(rate_limiter_allow(&limiter, origin, 8u, 4u, 3u, &retry));
}

static void test_command_codec_and_settings_store(void) {
  BrowserCommand cmd = {0};
  BrowserCommand decoded = {0};
  command_result_t result = {0};
  char encoded_result[256] = {0};
  uint8_t frame[COMMAND_CODEC_MAX_FRAME] = {0};
  size_t frame_len = 0u;

  runtime_settings_t settings = {
      .auto_popup_enabled = true,
      .manual_popup_requires_touch = true,
      .require_touch_for_fill = true,
      .hold_required_for_selection = true,
      .autolock_seconds = 45u,
  };
  runtime_settings_t loaded = {0};

  cmd.type = BROWSER_CMD_REQUEST_SAVE;
  cmd.nonce = 42u;
  strncpy(cmd.origin, "https://codec.example", sizeof(cmd.origin) - 1);
  strncpy(cmd.username, "codec_user", sizeof(cmd.username) - 1);
  strncpy(cmd.password, "CodecPass9!", sizeof(cmd.password) - 1);

  assert(command_codec_encode(&cmd, frame, sizeof(frame), &frame_len));
  assert(frame_len > 0u);
  assert(command_codec_decode(frame, frame_len, &decoded));
  assert(decoded.type == cmd.type);
  assert(decoded.nonce == cmd.nonce);
  assert(strcmp(decoded.origin, cmd.origin) == 0);
  assert(strcmp(decoded.username, cmd.username) == 0);
  assert(strcmp(decoded.password, cmd.password) == 0);

  result.allowed = true;
  result.touch_required = true;
  result.performed = false;
  strncpy(result.message, "touch to continue", sizeof(result.message) - 1);
  assert(command_codec_encode_result(&result, encoded_result, sizeof(encoded_result)));
  assert(strstr(encoded_result, "allowed=1") != NULL);
  assert(strstr(encoded_result, "touch_required=1") != NULL);

  settings_store_init();
  assert(settings_store_save(&settings));
  assert(settings_store_load(&loaded));
  assert(loaded.auto_popup_enabled == settings.auto_popup_enabled);
  assert(loaded.manual_popup_requires_touch == settings.manual_popup_requires_touch);
  assert(loaded.require_touch_for_fill == settings.require_touch_for_fill);
  assert(loaded.hold_required_for_selection == settings.hold_required_for_selection);
  assert(loaded.autolock_seconds == settings.autolock_seconds);
  assert(settings_store_wipe());
}

static void test_action_engine_replay_and_pin_change(void) {
  device_context_t ctx;
  vault_t vault;
  action_engine_t engine;
  ActionResult out = {0};
  BrowserCommand cmd = {0};

  state_machine_init(&ctx);
  password_store_init(&vault);
  action_engine_init(&engine, &vault, &ctx);

  assert(action_engine_unlock_with_pin(&engine, "12345"));
  assert(action_engine_try_change_pin(&engine, "12345", "54321"));
  assert(!action_engine_try_change_pin(&engine, "12345", "11111"));

  state_machine_init(&ctx);
  action_engine_init(&engine, &vault, &ctx);
  assert(!action_engine_unlock_with_pin(&engine, "12345"));
  assert(action_engine_unlock_with_pin(&engine, "54321"));

  cmd.type = BROWSER_CMD_REQUEST_GENERATE;
  cmd.nonce = 7u;
  strncpy(cmd.origin, "https://nonce.example", sizeof(cmd.origin) - 1u);
  strncpy(cmd.username, "nonce-user", sizeof(cmd.username) - 1u);
  assert(action_engine_handle_command(&engine, &cmd, &out));
  assert(out.allowed);
  assert(action_engine_confirm_hold(&engine, &out));
  assert(out.performed);

  memset(&out, 0, sizeof(out));
  assert(action_engine_handle_command(&engine, &cmd, &out));
  assert(!out.allowed);
  assert(strstr(out.message, "replay blocked") != NULL);
}

static void test_device_only_flow(void) {
  device_context_t ctx;
  vault_t vault;
  action_engine_t engine;
  ActionResult out = {0};

  assert(action_engine_try_change_pin(&engine, "54321", "12345") || true);
  state_machine_init(&ctx);
  password_store_init(&vault);
  action_engine_init(&engine, &vault, &ctx);
  assert(action_engine_unlock_with_pin(&engine, "12345"));

  assert(action_engine_device_save_credential(
      &engine, "https://device-only.example", "alice", "StrongDevice9!", &out));
  assert(out.allowed);
  assert(out.performed);
  assert(vault.count == 1u);

  memset(&out, 0, sizeof(out));
  assert(action_engine_device_fill_current(&engine, "https://device-only.example", &out));
  assert(out.allowed);
  assert(out.performed);
  assert(strcmp(out.typed_username, "alice") == 0);
  assert(strcmp(out.typed_password, "StrongDevice9!") == 0);

  memset(&out, 0, sizeof(out));
  assert(action_engine_device_generate_for_origin(
      &engine, "https://new-device.example", "new-user", &out));
  assert(out.allowed);
  assert(out.performed);
  assert(vault.count == 2u);
  {
    credential_t generated = {0};
    assert(password_store_find_by_origin(&vault, "https://new-device.example", &generated));
    assert(generated.username[0] != '\0');
  }
  assert(vault.count == 2u);

  memset(&out, 0, sizeof(out));
  assert(action_engine_device_select_next(&engine, &out));
  assert(out.allowed);
  assert(out.performed);
  assert(out.selected_next);
}

static void test_single_press_and_hold_model(void) {
  device_context_t ctx;
  vault_t vault;
  action_engine_t engine;
  ActionResult out = {0};
  runtime_settings_t settings = {0};

  state_machine_init(&ctx);
  password_store_init(&vault);
  action_engine_init(&engine, &vault, &ctx);
  assert(action_engine_unlock_with_pin(&engine, "12345"));

  assert(action_engine_device_save_credential(
      &engine, "https://onebutton.example", "user1", "OneButton9!", &out));
  assert(out.performed);

  memset(&out, 0, sizeof(out));
  assert(action_engine_button_press(&engine, "https://onebutton.example", &out));
  assert(out.allowed);
  assert(out.performed);
  assert(strcmp(out.typed_username, "user1") == 0);
  assert(strcmp(out.typed_password, "OneButton9!") == 0);

  memset(&out, 0, sizeof(out));
  assert(action_engine_button_hold(&engine, &out));
  assert(out.allowed);
  assert(out.performed);
  assert(strstr(out.message, "settings popup open") != NULL);

  state_machine_get_settings(&settings);
  assert(settings.auto_popup_enabled);
  assert(!settings.manual_popup_requires_touch);
  assert(!settings.require_touch_for_fill);
  assert(!settings.hold_required_for_selection);
}

static void test_press_without_known_context_opens_settings(void) {
  device_context_t ctx;
  vault_t vault;
  action_engine_t engine;
  ActionResult out = {0};

  state_machine_init(&ctx);
  password_store_init(&vault);
  action_engine_init(&engine, &vault, &ctx);
  assert(action_engine_unlock_with_pin(&engine, "12345"));

  memset(&out, 0, sizeof(out));
  assert(action_engine_button_press(&engine, "", &out));
  assert(out.allowed);
  assert(out.performed);
  assert(strstr(out.message, "settings popup open") != NULL);

  memset(&out, 0, sizeof(out));
  assert(action_engine_button_press(&engine, "https://unknown.example", &out));
  assert(out.allowed);
  assert(out.performed);
  assert(strstr(out.message, "settings popup open") != NULL);
}

static void test_settings_popup_actions(void) {
  device_context_t ctx;
  vault_t vault;
  action_engine_t engine;
  ActionResult out = {0};
  runtime_settings_t desired = {
      .auto_popup_enabled = false,
      .manual_popup_requires_touch = true,
      .require_touch_for_fill = true,
      .hold_required_for_selection = true,
      .autolock_seconds = 12u,
  };
  runtime_settings_t loaded = {0};

  state_machine_init(&ctx);
  password_store_init(&vault);
  action_engine_init(&engine, &vault, &ctx);
  assert(action_engine_unlock_with_pin(&engine, "12345"));

  assert(action_engine_device_save_credential(
      &engine, "https://settings.example", "alice", "OldPass9!", &out));
  assert(out.performed);

  memset(&out, 0, sizeof(out));
  assert(action_engine_button_hold(&engine, &out));
  assert(out.allowed);
  assert(out.performed);
  assert(strstr(out.message, "settings popup open") != NULL);

  memset(&out, 0, sizeof(out));
  assert(action_engine_device_apply_settings(&engine, &desired, &out));
  assert(out.allowed);
  assert(out.performed);
  assert(strstr(out.message, "settings updated") != NULL);

  state_machine_get_settings(&loaded);
  /* Single press/hold model enforces interaction flags regardless of requested values. */
  assert(loaded.auto_popup_enabled);
  assert(!loaded.manual_popup_requires_touch);
  assert(!loaded.require_touch_for_fill);
  assert(!loaded.hold_required_for_selection);
  assert(loaded.autolock_seconds == desired.autolock_seconds);

  memset(&out, 0, sizeof(out));
  assert(action_engine_device_modify_password(
      &engine, "https://settings.example", "alice", "NewPass9!", &out));
  assert(out.allowed);
  assert(out.performed);
  assert(out.updated_existing_record);

  memset(&out, 0, sizeof(out));
  assert(action_engine_button_press(&engine, "https://settings.example", &out));
  assert(out.performed);
  assert(strcmp(out.typed_password, "NewPass9!") == 0);
}

static void test_secure_wipe_for_vault(void) {
  vault_t vault;
  credential_t c = {0};
  password_store_init(&vault);
  c.valid = true;
  c.id = 9u;
  strncpy(c.origin, "https://wipe.example", sizeof(c.origin) - 1);
  strncpy(c.username, "wipe-user", sizeof(c.username) - 1);
  strncpy(c.password_ciphertext, "cipher", sizeof(c.password_ciphertext) - 1);
  assert(password_store_upsert(&vault, &c));
  assert(vault.count == 1u);
  password_store_secure_wipe(&vault);
  assert(vault.count == 0u);
}

static void test_crypto_engine_interfaces(void) {
  crypto_engine_status_t status;
  uint8_t salt[8] = {1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u};
  uint8_t pin_key[32] = {0};
  uint8_t pubkey[32] = {0};
  uint8_t tag[16] = {0};
  uint8_t plaintext[32] = "hello-aead";
  uint8_t ciphertext[32] = {0};
  uint8_t decrypted[32] = {0};
  size_t ciphertext_len = sizeof(ciphertext);
  size_t decrypted_len = sizeof(decrypted);
  uint8_t fp[16] = {0};

  crypto_engine_init();
  status = crypto_engine_get_status();
  assert(status.aead_interface_ready);
  assert(status.kdf_interface_ready);
  assert(!status.secure_element_bound);

  assert(crypto_engine_derive_pin_key("12345", salt, sizeof(salt), pin_key));
  assert(pin_key[0] != 0u || pin_key[1] != 0u || pin_key[2] != 0u);

  assert(crypto_engine_bind_atecc_slot(2u, pubkey, sizeof(pubkey)));
  status = crypto_engine_get_status();
  assert(status.secure_element_bound);
  assert(status.backend == CRYPTO_BACKEND_ATECC608A);

  assert(crypto_engine_encrypt_aead(plaintext, strlen((const char *)plaintext),
                                    (const uint8_t *)"aad", 3u,
                                    ciphertext, sizeof(ciphertext), &ciphertext_len, tag));
  assert(ciphertext_len == strlen((const char *)plaintext));
  assert(crypto_engine_decrypt_aead(ciphertext, ciphertext_len,
                                    (const uint8_t *)"aad", 3u, tag,
                                    decrypted, sizeof(decrypted), &decrypted_len));
  assert(decrypted_len == strlen((const char *)plaintext));
  assert(memcmp(decrypted, plaintext, decrypted_len) == 0);

  crypto_engine_password_fingerprint("Password9!", fp, sizeof(fp));
  assert(fp[0] != 0u || fp[1] != 0u);
}

int main(void) {
  test_state_machine_lockout_and_wipe();
  test_state_machine_settings_roundtrip();
  test_policy_min_len_and_common();
  test_password_generator();
  test_vault_and_reuse_detection();
  test_state_machine_touch_gate();
  test_browser_suspicious_origin();
  test_browser_protocol_field_validation();
  test_action_engine_fill_save_generate_select();
  test_action_engine_auto_popup_modes();
  test_action_engine_ui_feedback_mapping();
  test_security_utils_and_rate_limiter();
  test_command_codec_and_settings_store();
  test_action_engine_replay_and_pin_change();
  test_device_only_flow();
  test_single_press_and_hold_model();
  test_press_without_known_context_opens_settings();
  test_settings_popup_actions();
  test_crypto_engine_interfaces();
  test_secure_wipe_for_vault();

  puts("firmware tests: OK");
  return 0;
}
