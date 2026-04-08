#include "settings_store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h"
#include "security_utils.h"
#include "security_policy.h"

typedef struct {
  bool initialized;
  settings_blob_t blob;
  char encrypted_payload[128];
} settings_store_state_t;

static settings_store_state_t g_settings_store;

static uint32_t settings_crc(const runtime_settings_t *settings) {
  return security_fnv1a32((const uint8_t *)settings, sizeof(*settings));
}

static bool build_blob(runtime_settings_t settings, settings_blob_t *out) {
  if (out == NULL) {
    return false;
  }
  if (settings.autolock_seconds == 0u) {
    settings.autolock_seconds = AUTO_LOCK_TIMEOUT_SECONDS_DEFAULT;
  }
  memset(out, 0, sizeof(*out));
  out->version = SETTINGS_VERSION;
  out->settings = settings;
  out->crc32 = settings_crc(&settings);
  return true;
}

void settings_store_init(void) {
  memset(&g_settings_store, 0, sizeof(g_settings_store));
  g_settings_store.initialized = true;
}

bool settings_store_save(const runtime_settings_t *settings) {
  settings_blob_t blob;
  if (!g_settings_store.initialized || settings == NULL) {
    return false;
  }
  if (!build_blob(*settings, &blob)) {
    return false;
  }
  memcpy(blob.hmac_tag, &blob.crc32, sizeof(blob.crc32));
  g_settings_store.blob = blob;
  return true;
}

bool settings_store_load(runtime_settings_t *settings) {
  settings_blob_t blob;
  uint32_t expected_crc;
  uint32_t stored_crc_from_tag = 0u;

  if (!g_settings_store.initialized || settings == NULL) {
    return false;
  }
  blob = g_settings_store.blob;

  if (blob.version != SETTINGS_VERSION) {
    return false;
  }

  expected_crc = settings_crc(&blob.settings);
  if (expected_crc != blob.crc32) {
    return false;
  }
  memcpy(&stored_crc_from_tag, blob.hmac_tag, sizeof(stored_crc_from_tag));
  if (stored_crc_from_tag != blob.crc32) {
    return false;
  }

  *settings = blob.settings;
  if (settings->autolock_seconds == 0u) {
    settings->autolock_seconds = AUTO_LOCK_TIMEOUT_SECONDS_DEFAULT;
  }
  return true;
}

bool settings_store_wipe(void) {
  if (!g_settings_store.initialized) {
    return false;
  }
  security_secure_zero(&g_settings_store, sizeof(g_settings_store));
  g_settings_store.initialized = true;
  return true;
}

void settings_store_factory_reset(void) {
  runtime_settings_t defaults = {
      .auto_popup_enabled = true,
      .manual_popup_requires_touch = true,
      .require_touch_for_fill = true,
      .hold_required_for_selection = true,
      .autolock_seconds = AUTO_LOCK_TIMEOUT_SECONDS_DEFAULT,
  };
  (void)settings_store_save(&defaults);
}

