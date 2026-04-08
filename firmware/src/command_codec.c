#include "command_codec.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static void trim_newline(char *s) {
  if (s == NULL) {
    return;
  }
  size_t len = strlen(s);
  while (len > 0u && (s[len - 1u] == '\n' || s[len - 1u] == '\r')) {
    s[len - 1u] = '\0';
    len--;
  }
}

static bool parse_type(const char *value, BrowserCommandType *out) {
  if (value == NULL || out == NULL) {
    return false;
  }
  if (strcmp(value, "REQUEST_FILL") == 0) {
    *out = BROWSER_CMD_REQUEST_FILL;
    return true;
  }
  if (strcmp(value, "REQUEST_SAVE") == 0) {
    *out = BROWSER_CMD_REQUEST_SAVE;
    return true;
  }
  if (strcmp(value, "REQUEST_GENERATE") == 0) {
    *out = BROWSER_CMD_REQUEST_GENERATE;
    return true;
  }
  if (strcmp(value, "REQUEST_SELECT_NEXT") == 0) {
    *out = BROWSER_CMD_REQUEST_SELECT_NEXT;
    return true;
  }
  return false;
}

bool command_codec_decode_line(const char *line, BrowserCommand *out_cmd) {
  char buf[512];
  char *token;
  BrowserCommand cmd = {0};
  bool seen_type = false;

  if (line == NULL || out_cmd == NULL) {
    return false;
  }
  if (strlen(line) >= sizeof(buf)) {
    return false;
  }

  (void)strncpy(buf, line, sizeof(buf) - 1u);
  buf[sizeof(buf) - 1u] = '\0';
  trim_newline(buf);

  token = strtok(buf, ";");
  while (token != NULL) {
    char *eq = strchr(token, '=');
    if (eq == NULL) {
      return false;
    }
    *eq = '\0';
    const char *key = token;
    const char *value = eq + 1;

    if (strcmp(key, "type") == 0) {
      if (!parse_type(value, &cmd.type)) {
        return false;
      }
      seen_type = true;
    } else if (strcmp(key, "origin") == 0) {
      (void)strncpy(cmd.origin, value, sizeof(cmd.origin) - 1u);
    } else if (strcmp(key, "username") == 0) {
      (void)strncpy(cmd.username, value, sizeof(cmd.username) - 1u);
    } else if (strcmp(key, "password") == 0) {
      (void)strncpy(cmd.password, value, sizeof(cmd.password) - 1u);
    } else {
      return false;
    }

    token = strtok(NULL, ";");
  }

  if (!seen_type) {
    return false;
  }
  *out_cmd = cmd;
  return true;
}

bool command_codec_encode_result(const command_result_t *result, char *out, size_t out_len) {
  const char *allowed = "0";
  const char *touch = "0";
  const char *performed = "0";
  if (result == NULL || out == NULL || out_len == 0u) {
    return false;
  }
  allowed = result->allowed ? "1" : "0";
  touch = result->touch_required ? "1" : "0";
  performed = result->performed ? "1" : "0";
  int n = snprintf(out, out_len,
                   "allowed=%s;touch_required=%s;performed=%s;message=%s",
                   allowed, touch, performed, result->message);
  return n > 0 && (size_t)n < out_len;
}

bool command_codec_encode(const BrowserCommand *cmd,
                          uint8_t *out_buf,
                          size_t out_len,
                          size_t *written) {
  int n;
  const char *type = "NONE";
  if (written != NULL) {
    *written = 0u;
  }
  if (cmd == NULL || out_buf == NULL || out_len == 0u) {
    return false;
  }
  switch (cmd->type) {
    case BROWSER_CMD_REQUEST_FILL: type = "REQUEST_FILL"; break;
    case BROWSER_CMD_REQUEST_SAVE: type = "REQUEST_SAVE"; break;
    case BROWSER_CMD_REQUEST_GENERATE: type = "REQUEST_GENERATE"; break;
    case BROWSER_CMD_REQUEST_SELECT_NEXT: type = "REQUEST_SELECT_NEXT"; break;
    default: return false;
  }
  n = snprintf((char *)out_buf, out_len,
               "type=%s;origin=%s;username=%s;password=%s",
               type, cmd->origin, cmd->username, cmd->password);
  if (n <= 0 || (size_t)n >= out_len) {
    return false;
  }
  if (written != NULL) {
    *written = (size_t)n;
  }
  return true;
}

bool command_codec_decode(const uint8_t *buf, size_t len, BrowserCommand *out_cmd) {
  char line[COMMAND_CODEC_MAX_FRAME];
  if (buf == NULL || out_cmd == NULL || len == 0u || len >= sizeof(line)) {
    return false;
  }
  memcpy(line, buf, len);
  line[len] = '\0';
  return command_codec_decode_line(line, out_cmd);
}

