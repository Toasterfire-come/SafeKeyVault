#include "browser_protocol.h"

#include <stdio.h>
#include <string.h>

static size_t bounded_strlen(const char *s, size_t max_len) {
  size_t i = 0u;
  if (s == NULL) {
    return 0u;
  }
  while (i < max_len && s[i] != '\0') {
    i++;
  }
  return i;
}

static bool has_scheme(const char *origin) {
  return strstr(origin, "://") != NULL;
}

static bool is_https(const char *origin) {
  return strncmp(origin, "https://", 8) == 0;
}

static bool is_safe_ascii_text(const char *value, size_t max_len) {
  size_t len = bounded_strlen(value, max_len);
  for (size_t i = 0; i < len; ++i) {
    unsigned char c = (unsigned char)value[i];
    if (c < 32u || c == 127u) {
      return false;
    }
  }
  return true;
}

static bool has_url_like_value(const char *value) {
  if (value == NULL || value[0] == '\0') {
    return false;
  }
  if (strstr(value, "://") != NULL) {
    return true;
  }
  if (strncmp(value, "www.", 4u) == 0) {
    return true;
  }
  return false;
}

bool browser_origin_is_suspicious(const char *origin) {
  if (origin == NULL || origin[0] == '\0') {
    return true;
  }
  if (!has_scheme(origin)) {
    return true;
  }
  if (!is_https(origin)) {
    return true;
  }

  size_t len = strlen(origin);
  for (size_t i = 0; i < len; ++i) {
    unsigned char c = (unsigned char) origin[i];
    if (c > 127u) {
      return true;
    }
  }

  if (strstr(origin, "@") != NULL) {
    return true;
  }

  return false;
}

static bool command_has_required_fields(const BrowserCommand *cmd) {
  if (cmd->type == BROWSER_CMD_REQUEST_FILL || cmd->type == BROWSER_CMD_REQUEST_GENERATE) {
    return cmd->origin[0] != '\0';
  }
  if (cmd->type == BROWSER_CMD_REQUEST_SAVE) {
    return cmd->origin[0] != '\0' && cmd->username[0] != '\0' && cmd->password[0] != '\0';
  }
  if (cmd->type == BROWSER_CMD_REQUEST_SELECT_NEXT) {
    return true;
  }
  return false;
}

bool browser_validate_command(const BrowserCommand *cmd, BrowserCommandResult *result) {
  size_t origin_len;
  size_t username_len;
  size_t password_len;

  if (cmd == NULL || result == NULL) {
    return false;
  }

  memset(result, 0, sizeof(*result));
  result->touch_required = true;

  if (!command_has_required_fields(cmd)) {
    (void) snprintf(result->message, sizeof(result->message),
                    "missing required fields");
    return false;
  }

  origin_len = bounded_strlen(cmd->origin, sizeof(cmd->origin));
  username_len = bounded_strlen(cmd->username, sizeof(cmd->username));
  password_len = bounded_strlen(cmd->password, sizeof(cmd->password));

  /* Reject non-terminated/oversized field payloads early to reduce parser abuse surface. */
  if (origin_len >= sizeof(cmd->origin) ||
      username_len >= sizeof(cmd->username) ||
      password_len >= sizeof(cmd->password)) {
    (void) snprintf(result->message, sizeof(result->message), "field too long");
    return false;
  }

  if (!is_safe_ascii_text(cmd->origin, sizeof(cmd->origin)) ||
      !is_safe_ascii_text(cmd->username, sizeof(cmd->username)) ||
      !is_safe_ascii_text(cmd->password, sizeof(cmd->password))) {
    (void) snprintf(result->message, sizeof(result->message), "unsafe field chars");
    return false;
  }

  if (has_url_like_value(cmd->username) || has_url_like_value(cmd->password)) {
    (void) snprintf(result->message, sizeof(result->message), "unsafe field chars");
    return false;
  }

  if (username_len > 0u && username_len < 2u) {
    (void) snprintf(result->message, sizeof(result->message), "username too short");
    return false;
  }

  if (cmd->type != BROWSER_CMD_REQUEST_SELECT_NEXT) {
    result->high_risk_origin = browser_origin_is_suspicious(cmd->origin);
    if (result->high_risk_origin) {
      (void) snprintf(result->message, sizeof(result->message),
                      "origin is high risk");
      result->accepted = false;
      return false;
    }
  }

  (void) snprintf(result->message, sizeof(result->message), "touch required");
  result->accepted = true;
  return true;
}
