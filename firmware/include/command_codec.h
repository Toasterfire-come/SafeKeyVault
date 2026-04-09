#ifndef COMMAND_CODEC_H
#define COMMAND_CODEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "browser_protocol.h"

/* ASCII key=value framing for optional host control channel. */
#define COMMAND_CODEC_MAX_FRAME 512u

typedef struct {
  bool allowed;
  bool touch_required;
  bool performed;
  char message[96];
} command_result_t;

bool command_codec_encode(const BrowserCommand *cmd,
                          uint8_t *out_buf,
                          size_t out_len,
                          size_t *written);
bool command_codec_decode(const uint8_t *buf, size_t len, BrowserCommand *out_cmd);
bool command_codec_decode_line(const char *line, BrowserCommand *out_cmd);
bool command_codec_encode_result(const command_result_t *result, char *out, size_t out_len);

#endif /* COMMAND_CODEC_H */
