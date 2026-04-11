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
    // Allow printable ASCII characters, excluding control characters and DEL.
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
  // Basic check for URL-like patterns that could be used for injection.
  if (strstr(value, "://") != NULL) {
    return true;
  }
  if (strncmp(value, "www.", 4u) == 0) {
    return true;
  }
  // Check for common injection patterns like javascript:
  if (strstr(value, "javascript:") != NULL) {
      return true;
  }
  return false;
}

bool browser_origin_is_suspicious(const char *origin) {
  if (origin == NULL || origin[0] == '\0') {
    return true; // Empty origin is suspicious
  }
  if (!has_scheme(origin)) {
    return true; // Missing scheme (e.g., http, https)
  }
  if (!is_https(origin)) {
    return true; // Only HTTPS is allowed for security
  }

  size_t len = strlen(origin);
  for (size_t i = 0; i < len; ++i) {
    unsigned char c = (unsigned char) origin[i];
    // Reject non-ASCII characters
    if (c > 127u) {
      return true;
    }
  }

  // Reject origins containing '@' which might indicate email addresses or other injection vectors.
  if (strstr(origin, "@") != NULL) {
    return true;
  }

  // Further checks could include:
  // - Punycoded domain checks (homograph attacks)
  // - IP address literals (if not explicitly allowed)
  // - Excessive subdomains

  return false; // Origin appears to be safe based on current checks
}

static bool command_has_required_fields(const BrowserCommand *cmd) {
  if (cmd->type == BROWSER_CMD_REQUEST_FILL || cmd->type == BROWSER_CMD_REQUEST_GENERATE) {
    return cmd->origin[0] != '\0';
  }
  if (cmd->type == BROWSER_CMD_REQUEST_SAVE) {
    return cmd->origin[0] != '\0' && cmd->username[0] != '\0' && cmd->password[0] != '\0';
  }
  if (cmd->type == BROWSER_CMD_REQUEST_SELECT_NEXT) {
    return true; // No specific fields required for select next
  }
  return false; // Unknown command type
}

bool browser_validate_command(const BrowserCommand *cmd, BrowserCommandResult *result) {
  size_t origin_len;
  size_t username_len;
  size_t password_len;

  if (cmd == NULL || result == NULL) {
    return false;
  }

  memset(result, 0, sizeof(*result));
  result->touch_required = true; // Default to requiring touch for most actions

  if (!command_has_required_fields(cmd)) {
    (void) snprintf(result->message, sizeof(result->message),
                    "missing required fields for command type");
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

  // Validate that all fields contain only safe ASCII characters.
  if (!is_safe_ascii_text(cmd->origin, sizeof(cmd->origin)) ||
      !is_safe_ascii_text(cmd->username, sizeof(cmd->username)) ||
      !is_safe_ascii_text(cmd->password, sizeof(cmd->password))) {
    (void) snprintf(result->message, sizeof(result->message), "unsafe field characters");
    return false;
  }

  // Reject values that look like URLs or scripts, which could be injection attempts.
  if (has_url_like_value(cmd->username) || has_url_like_value(cmd->password)) {
    (void) snprintf(result->message, sizeof(result->message), "unsafe field content");
    return false;
  }

  // Basic validation for username length.
  if (username_len > 0u && username_len < 2u) {
    (void) snprintf(result->message, sizeof(result->message), "username too short");
    return false;
  }

  // High-risk origin check applies to fill, save, and generate commands.
  if (cmd->type != BROWSER_CMD_REQUEST_SELECT_NEXT) {
    result->high_risk_origin = browser_origin_is_suspicious(cmd->origin);
    if (result->high_risk_origin) {
      (void) snprintf(result->message, sizeof(result->message),
                      "origin is high risk");
      result->accepted = false; // Explicitly reject high-risk origins
      return false;
    }
  }

  // If all checks pass, the command is accepted.
  (void) snprintf(result->message, sizeof(result->message), "command accepted");
  result->accepted = true;
  return true;
}
