#include "settings_store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h"
#include "security_utils.h"
#include "security_policy.h"
#include "storage_backend.h"

typedef struct {
  bool initialized;
  settings_blob_t blob;
  uint8_t encrypted_payload[128];
  size_t encrypted_payload_len;
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

static void settings_store_nonce(const settings_blob_t *blob, uint8_t out_nonce[12]) {
  uint8_t seed[16];
  if (out_nonce == NULL) {
    return;
  }
  memset(seed, 0, sizeof(seed));
  if (blob != NULL) {
    memcpy(seed, &blob->version, sizeof(blob->version));
    memcpy(seed + 4u, &blob->crc32, sizeof(blob->crc32));
    memcpy(seed + 8u, &blob->settings.autolock_seconds, sizeof(blob->settings.autolock_seconds));
  }
  crypto_engine_hash16(seed, sizeof(seed), seed);
  memcpy(out_nonce, seed, 12u);
  security_secure_zero(seed, sizeof(seed));
}

void settings_store_init(void) {
  memset(&g_settings_store, 0, sizeof(g_settings_store));
  storage_backend_init();
  storage_backend_wipe();
  crypto_engine_init();
  {
    const uint8_t default_key[] = {
        0x31u, 0x52u, 0xA4u, 0x18u, 0x09u, 0x7Fu, 0xC3u, 0x44u,
        0x8Eu, 0x20u, 0xB7u, 0x5Du, 0x11u, 0xE2u, 0x66u, 0x90u,
    };
    crypto_engine_set_master_key(default_key, sizeof(default_key));
  }
  g_settings_store.initialized = true;
}

bool settings_store_save(const runtime_settings_t *settings) {
  settings_blob_t blob;
  uint8_t plaintext[sizeof(settings_blob_t)];
  uint8_t nonce[12];
  uint8_t tag[16];
  size_t ciphertext_len = sizeof(g_settings_store.encrypted_payload);
  uint8_t record[4u + sizeof(settings_blob_t) + sizeof(g_settings_store.encrypted_payload)];
  size_t record_len = 0u;
  if (!g_settings_store.initialized || settings == NULL) {
    return false;
  }
  if (!build_blob(*settings, &blob)) {
    return false;
  }
  memset(blob.hmac_tag, 0, sizeof(blob.hmac_tag));
  memcpy(plaintext, &blob, sizeof(blob));
  settings_store_nonce(&blob, nonce);

  if (!crypto_engine_encrypt_aead(plaintext, sizeof(plaintext),
                                  nonce, sizeof(nonce),
                                  g_settings_store.encrypted_payload,
                                  sizeof(g_settings_store.encrypted_payload),
                                  &ciphertext_len,
                                  tag)) {
    security_secure_zero(plaintext, sizeof(plaintext));
    return false;
  }
  g_settings_store.encrypted_payload_len = ciphertext_len;
  memcpy(blob.hmac_tag, tag, sizeof(blob.hmac_tag));
  g_settings_store.blob = blob;

  memset(record, 0, sizeof(record));
  memcpy(record, &g_settings_store.encrypted_payload_len, sizeof(uint32_t));
  memcpy(record + 4u, &g_settings_store.blob, sizeof(settings_blob_t));
  memcpy(record + 4u + sizeof(settings_blob_t),
         g_settings_store.encrypted_payload,
         g_settings_store.encrypted_payload_len);
  record_len = 4u + sizeof(settings_blob_t) + g_settings_store.encrypted_payload_len;
  if (!storage_backend_write_atomic(record, record_len, SETTINGS_VERSION)) {
    security_secure_zero(record, sizeof(record));
    security_secure_zero(plaintext, sizeof(plaintext));
    security_secure_zero(tag, sizeof(tag));
    security_secure_zero(nonce, sizeof(nonce));
    return false;
  }
  security_secure_zero(record, sizeof(record));
  security_secure_zero(plaintext, sizeof(plaintext));
  security_secure_zero(tag, sizeof(tag));
  security_secure_zero(nonce, sizeof(nonce));
  return true;
}

bool settings_store_load(runtime_settings_t *settings) {
  settings_blob_t blob;
  uint32_t expected_crc;
  uint8_t plaintext[sizeof(settings_blob_t)];
  uint8_t nonce[12];
  size_t plaintext_len = sizeof(plaintext);

  if (!g_settings_store.initialized || settings == NULL) {
    return false;
  }
  if (g_settings_store.encrypted_payload_len == 0u) {
    uint8_t record[4u + sizeof(settings_blob_t) + sizeof(g_settings_store.encrypted_payload)];
    size_t record_len = sizeof(record);
    uint32_t schema_version = 0u;
    uint32_t stored_payload_len = 0u;
    if (!storage_backend_read_latest(record, sizeof(record), &record_len, &schema_version)) {
      return false;
    }
    if (schema_version != SETTINGS_VERSION) {
      return false;
    }
    if (record_len < (4u + sizeof(settings_blob_t))) {
      return false;
    }
    memcpy(&stored_payload_len, record, sizeof(stored_payload_len));
    if (stored_payload_len == 0u || stored_payload_len > sizeof(g_settings_store.encrypted_payload)) {
      return false;
    }
    if (record_len != (4u + sizeof(settings_blob_t) + stored_payload_len)) {
      return false;
    }
    memcpy(&g_settings_store.blob, record + 4u, sizeof(settings_blob_t));
    memcpy(g_settings_store.encrypted_payload,
           record + 4u + sizeof(settings_blob_t),
           stored_payload_len);
    g_settings_store.encrypted_payload_len = stored_payload_len;
  }
  blob = g_settings_store.blob;

  if (blob.version != SETTINGS_VERSION) {
    return false;
  }
  settings_store_nonce(&blob, nonce);
  if (!crypto_engine_decrypt_aead(g_settings_store.encrypted_payload,
                                  g_settings_store.encrypted_payload_len,
                                  nonce, sizeof(nonce),
                                  blob.hmac_tag,
                                  plaintext, sizeof(plaintext),
                                  &plaintext_len)) {
    security_secure_zero(plaintext, sizeof(plaintext));
    security_secure_zero(nonce, sizeof(nonce));
    return false;
  }
  if (plaintext_len != sizeof(settings_blob_t)) {
    security_secure_zero(plaintext, sizeof(plaintext));
    security_secure_zero(nonce, sizeof(nonce));
    return false;
  }
  memcpy(&blob, plaintext, sizeof(blob));
  security_secure_zero(plaintext, sizeof(plaintext));
  security_secure_zero(nonce, sizeof(nonce));

  expected_crc = settings_crc(&blob.settings);
  if (expected_crc != blob.crc32) {
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
  storage_backend_wipe();
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

bool settings_store_debug_snapshot(settings_blob_t *out_blob,
                                   uint8_t *out_payload,
                                   size_t out_payload_capacity,
                                   size_t *out_payload_len) {
  if (!g_settings_store.initialized || out_blob == NULL ||
      out_payload == NULL || out_payload_len == NULL) {
    return false;
  }
  if (g_settings_store.encrypted_payload_len == 0u ||
      g_settings_store.encrypted_payload_len > out_payload_capacity) {
    return false;
  }
  *out_blob = g_settings_store.blob;
  memcpy(out_payload, g_settings_store.encrypted_payload, g_settings_store.encrypted_payload_len);
  *out_payload_len = g_settings_store.encrypted_payload_len;
  return true;
}

bool settings_store_debug_restore(const settings_blob_t *blob,
                                  const uint8_t *payload,
                                  size_t payload_len) {
  if (!g_settings_store.initialized || blob == NULL || payload == NULL) {
    return false;
  }
  if (payload_len == 0u || payload_len > sizeof(g_settings_store.encrypted_payload)) {
    return false;
  }
  g_settings_store.blob = *blob;
  memcpy(g_settings_store.encrypted_payload, payload, payload_len);
  g_settings_store.encrypted_payload_len = payload_len;
  return true;
}

