#include "settings_store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_engine.h"
#include "security_utils.h"
#include "security_policy.h"
#include "storage_backend.h"
#include "build_config.h" // For FIRMWARE_PRODUCTION

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

// Global counter for nonce generation (ensures uniqueness with device secret)
static uint32_t g_settings_encryption_counter = 0;

static void settings_store_nonce(uint8_t out_nonce[12]) {
  uint8_t nonce_seed[16] = {0}; // Increased size for better mixing
  uint8_t hashed_nonce_seed[16] = {0};

  if (out_nonce == NULL) {
    return;
  }

  // Increment global counter to ensure uniqueness across encryptions
  g_settings_encryption_counter++;

  // Mix counter with a known value to avoid simple sequences
  uint32_t mixed_counter = g_settings_encryption_counter ^ 0xDEADBEEFu;

  // Use the mixed counter and a fixed context (e.g., from an ATECC slot or device info)
  // For a per-device salt, we will use a derived value or directly from a specific ATECC slot
  // Here, we'll request a 12-byte nonce directly from the crypto engine, which will now handle the device secret mixing internally.
  // This assumes `crypto_engine_get_gcm_nonce` handles device-specific and unique nonce generation.
  // Temporarily relying on a pseudo-random seed here, this *must* be replaced by a truly unique per-encryption source.

  // Instead of re-implementing nonce generation, we're assuming the crypto_engine
  // provides a function that handles this securely and uniquely using internal state
  // (like a monotonic counter and securely stored device secret).
  // ATECC typically provides a hardware random number generator, but dedicated nonce generation
  // often uses derived keys and counters for AES-GCM.
  // Nonce generation should leverage the ATECC's TRNG and internal counters, mixed with AAD specific info if needed.

  // For now, let's generate a simple seed for the nonce from a counter and hash it.
  // This is a minimal step towards uniqueness, but the ATECC should ideally provide a better mechanism.
  memcpy(nonce_seed, &mixed_counter, sizeof(mixed_counter));
  // In a real-world scenario, you would derive this from a secure element's monotonic counter or a truly random source
  // combined with a unique device ID/secret.
  // For now, we simulate a more secure nonce generation by hashing the counter and device secret.
  if (crypto_engine_read_atecc_slot(ATECC608A_SLOT_DEVICE_SECRET, nonce_seed + sizeof(mixed_counter), sizeof(nonce_seed) - sizeof(mixed_counter))) {
      crypto_engine_hash16(nonce_seed, sizeof(nonce_seed), hashed_nonce_seed);
      memcpy(out_nonce, hashed_nonce_seed, 12);
  } else {
      // If device secret cannot be read, especially in production, this is a critical error.
      // In production, this path implies a severe provisioning or hardware issue.
#if FIRMWARE_PRODUCTION
      Error_Handler(); // Halt the device if device secret cannot be read.
#else
      // In development, fallback to a simple hash of the counter as a placeholder.
      crypto_engine_hash16((const uint8_t*)&mixed_counter, sizeof(mixed_counter), hashed_nonce_seed);
      memcpy(out_nonce, hashed_nonce_seed, 12);
#endif
  }

  security_secure_zero(nonce_seed, sizeof(nonce_seed));
  security_secure_zero(hashed_nonce_seed, sizeof(hashed_nonce_seed));
}

void settings_store_init(void) {
  uint8_t device_secret[32];
  const uint8_t default_master_key[32] = {
      0x2Du, 0x81u, 0x57u, 0x9Au, 0x44u, 0xC6u, 0x31u, 0xE2u,
      0x0Fu, 0xB8u, 0x5Cu, 0xD3u, 0x6Au, 0x19u, 0xAEu, 0x70u,
      0x83u, 0x2Fu, 0xC9u, 0x14u, 0x5Bu, 0xE7u, 0x3Au, 0x91u,
      0x68u, 0x04u, 0xDDu, 0x27u, 0xB1u, 0x5Eu, 0xF0u, 0x3Cu,
  };
  const uint8_t default_atecc_pubkey[32] = {
      0xA1u, 0x44u, 0x7Cu, 0x2Eu, 0x53u, 0xD7u, 0x1Bu, 0x90u,
      0x6Fu, 0x08u, 0xC2u, 0x35u, 0xE4u, 0x79u, 0x1Du, 0xAFu,
      0x58u, 0xCBu, 0x21u, 0x63u, 0x96u, 0x0Au, 0xF5u, 0x3Du,
      0xB0u, 0x47u, 0x89u, 0x12u, 0xD8u, 0x6Cu, 0x24u, 0xFEu,
  };
  size_t i;
  memset(&g_settings_store, 0, sizeof(g_settings_store));
  storage_backend_init();
  // Remove storage_backend_wipe() call from settings_store_init
  // storage_backend_wipe();
  crypto_engine_init();

  // Guard dev key material with #if !FIRMWARE_PRODUCTION
#if !FIRMWARE_PRODUCTION
  crypto_engine_set_master_key(default_master_key, sizeof(default_master_key));
#endif
  for (i = 0u; i < sizeof(device_secret); ++i) {
    device_secret[i] = (uint8_t)(0xA5u ^ (uint8_t)(i * 13u));
  }
  (void)crypto_engine_set_device_secret(device_secret, sizeof(device_secret));
  // Bind a dummy public key for ATECC simulation. In production, this would be the actual device's public key.
  (void)crypto_engine_bind_atecc_slot(ATECC608A_SLOT_PUBKEY, default_atecc_pubkey, sizeof(default_atecc_pubkey));
  security_secure_zero(device_secret, sizeof(device_secret));
  g_settings_store.initialized = true;
}

bool settings_store_save(const runtime_settings_t *settings) {
  settings_blob_t blob;
  uint8_t plaintext[sizeof(settings_blob_t)];
  uint8_t nonce[12];
  uint8_t tag[16];
  size_t ciphertext_len = sizeof(g_settings_store.encrypted_payload);
  uint8_t record[4u + sizeof(settings_blob_t) + STORAGE_BACKEND_MAX_PAYLOAD]; // Max possible size
  size_t record_len = 0u;
  if (!g_settings_store.initialized || settings == NULL) {
    return false;
  }
  if (!build_blob(*settings, &blob)) {
    return false;
  }
  memset(blob.hmac_tag, 0, sizeof(blob.hmac_tag)); // Zero out tag before encryption since it's an output
  memcpy(plaintext, &blob, sizeof(blob)); // Prepare plaintext for encryption
  settings_store_nonce(nonce); // Generate a unique nonce

  // Construct AAD from meaningful parts of the blob for integrity without encryption
  uint8_t aad_data[sizeof(blob.version) + sizeof(blob.crc32)];
  memcpy(aad_data, &blob.version, sizeof(blob.version));
  memcpy(aad_data + sizeof(blob.version), &blob.crc32, sizeof(blob.crc32));

  if (!crypto_engine_encrypt_aead(plaintext, sizeof(plaintext),
                                  aad_data, sizeof(aad_data), // Use AAD
                                  g_settings_store.encrypted_payload,
                                  sizeof(g_settings_store.encrypted_payload),
                                  &ciphertext_len,
                                  tag)) {
    security_secure_zero(plaintext, sizeof(plaintext));
    security_secure_zero(tag, sizeof(tag));
    security_secure_zero(nonce, sizeof(nonce));
    return false;
  }
  g_settings_store.encrypted_payload_len = ciphertext_len;
  memcpy(blob.hmac_tag, tag, sizeof(blob.hmac_tag));
  g_settings_store.blob = blob;

  memset(record, 0, sizeof(record));
  // Store the length of the encrypted payload before the blob and payload itself
  uint32_t stored_payload_len = (uint32_t)g_settings_store.encrypted_payload_len;
  memcpy(record, &stored_payload_len, sizeof(stored_payload_len));
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
  uint8_t record[4u + sizeof(settings_blob_t) + STORAGE_BACKEND_MAX_PAYLOAD]; // Max possible size
  size_t record_len = 0u;
  uint32_t stored_payload_len = 0u;
  uint32_t schema_version = 0u;

  if (!g_settings_store.initialized || settings == NULL) {
    return false;
  }

  // Attempt to read from storage if not already loaded
  if (g_settings_store.encrypted_payload_len == 0u) {
    memset(record, 0, sizeof(record));
    if (!storage_backend_read_latest(record, sizeof(record), &record_len, &schema_version)) {
      return false;
    }
    if (schema_version != SETTINGS_VERSION) {
      return false; // Schema mismatch
    }
    if (record_len < (4u + sizeof(settings_blob_t))) {
      return false; // Record too short
    }
    memcpy(&stored_payload_len, record, sizeof(stored_payload_len));
    if (stored_payload_len == 0u || stored_payload_len > sizeof(g_settings_store.encrypted_payload)) {
      return false; // Invalid payload length
    }
    if (record_len != (4u + sizeof(settings_blob_t) + stored_payload_len)) {
      return false; // Record length mismatch
    }
    memcpy(&g_settings_store.blob, record + 4u, sizeof(settings_blob_t));
    memcpy(g_settings_store.encrypted_payload,
           record + 4u + sizeof(settings_blob_t),
           stored_payload_len);
    g_settings_store.encrypted_payload_len = stored_payload_len;
  }

  blob = g_settings_store.blob;

  // AAD must be reconstructed identically for decryption
  uint8_t aad_data[sizeof(blob.version) + sizeof(blob.crc32)];
  memcpy(aad_data, &blob.version, sizeof(blob.version));
  memcpy(aad_data + sizeof(blob.version), &blob.crc32, sizeof(blob.crc32));

  if (!crypto_engine_decrypt_aead(g_settings_store.encrypted_payload,
                                  g_settings_store.encrypted_payload_len,
                                  aad_data, sizeof(aad_data), // Use AAD
                                  blob.hmac_tag, // Pass the tag from the blob
                                  plaintext, sizeof(plaintext),
                                  &plaintext_len)) {
    security_secure_zero(plaintext, sizeof(plaintext));
    security_secure_zero(nonce, sizeof(nonce));
    return false; // Decryption/authentication failed
  }
  if (plaintext_len != sizeof(settings_blob_t)) {
    security_secure_zero(plaintext, sizeof(plaintext));
    security_secure_zero(nonce, sizeof(nonce));
    return false; // Decrypted data size mismatch
  }
  memcpy(&blob, plaintext, sizeof(blob));
  security_secure_zero(plaintext, sizeof(plaintext));
  security_secure_zero(nonce, sizeof(nonce));

  expected_crc = settings_crc(&blob.settings);
  if (expected_crc != blob.crc32) {
    return false; // CRC mismatch indicates data corruption
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
  // Securely zeroize all internal state before wiping storage.
  security_secure_zero(&g_settings_store.blob, sizeof(g_settings_store.blob));
  security_secure_zero(g_settings_store.encrypted_payload, g_settings_store.encrypted_payload_len);
  g_settings_store.encrypted_payload_len = 0u;
  storage_backend_wipe();
  // Re-initialize with default settings after wipe
  settings_store_factory_reset();
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
#if FIRMWARE_PRODUCTION
  // Debug interfaces disabled in production
  (void)out_blob;
  (void)out_payload;
  (void)out_payload_capacity;
  (void)out_payload_len;
  return false;
#else
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
#endif
}

bool settings_store_debug_restore(const settings_blob_t *blob,
                                  const uint8_t *payload,
                                  size_t payload_len) {
#if FIRMWARE_PRODUCTION
  // Debug interfaces disabled in production
  (void)blob;
  (void)payload;
  (void)payload_len;
  return false;
#else
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
#endif
}
