#ifndef SETTINGS_STORE_H
#define SETTINGS_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "firmware_types.h"

typedef struct {
  uint32_t version;
  runtime_settings_t settings;
  uint32_t crc32;
  uint8_t hmac_tag[16];
} settings_blob_t;

#define SETTINGS_VERSION 1u

void settings_store_init(void);
bool settings_store_load(runtime_settings_t *out_settings);
bool settings_store_save(const runtime_settings_t *settings);
bool settings_store_wipe(void);
void settings_store_factory_reset(void);
bool settings_store_debug_snapshot(settings_blob_t *out_blob,
                                   uint8_t *out_payload,
                                   size_t payload_capacity,
                                   size_t *out_payload_len);
bool settings_store_debug_restore(const settings_blob_t *blob,
                                  const uint8_t *payload,
                                  size_t payload_len);

#endif
