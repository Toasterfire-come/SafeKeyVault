#include "browser_protocol.h"

#include <ctype.h>
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

  /* Reject oversized field payloads early to reduce parser abuse surface. */
  if (bounded_strlen(cmd->origin, sizeof(cmd->origin)) >= sizeof(cmd->origin) ||
      bounded_strlen(cmd->username, sizeof(cmd->username)) >= sizeof(cmd->username) ||
      bounded_strlen(cmd->password, sizeof(cmd->password)) >= sizeof(cmd->password)) {
    (void) snprintf(result->message, sizeof(result->message), "field too long");
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
