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

#endif
