#include "command_codec.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void trim_newline(char *s) {
  if (s == NULL) {
    return;
  }
  // Use strnlen and ensure operation within bounds
  size_t len = strnlen(s, COMMAND_CODEC_MAX_FRAME -1); // Max length for buffer of COMMAND_CODEC_MAX_FRAME chars with null term
  while (len > 0u && (s[len - 1u] == '\n' || s[len - 1u] == '\r')) {
    s[len - 1u] = '\0';
    len--;
  }
}

static bool parse_type(const char *value, BrowserCommandType *out) {
  if (value == NULL || out == NULL) {
    return false;
  }
  // Use strncmp for safety as value comes from parsed input
  if (strncmp(value, "REQUEST_FILL", 16) == 0) { // Max length of string literal
    *out = BROWSER_CMD_REQUEST_FILL;
    return true;
  }
  if (strncmp(value, "REQUEST_SAVE", 16) == 0) {
    *out = BROWSER_CMD_REQUEST_SAVE;
    return true;
  }
  if (strncmp(value, "REQUEST_GENERATE", 16) == 0) {
    *out = BROWSER_CMD_REQUEST_GENERATE;
    return true;
  }
  if (strncmp(value, "REQUEST_SELECT_NEXT", 16) == 0) {
    *out = BROWSER_CMD_REQUEST_SELECT_NEXT;
    return true;
  }
  return false;
}

bool command_codec_decode_line(const char *line, BrowserCommand *out_cmd) {
  char buf[COMMAND_CODEC_MAX_FRAME]; // Use defined max frame size
  char *token;
  BrowserCommand cmd = {0}; // Initialize command structure for safety
  bool seen_type = false;
  bool success = false; // Track overall success

  if (line == NULL || out_cmd == NULL) {
    return false;
  }
  if (strnlen(line, sizeof(buf)) >= sizeof(buf)) { // Check line length against buffer size
    return false; // Line too long
  }

  // Use strncpy to copy line into buffer safely
  (void)strncpy(buf, line, sizeof(buf) - 1u);
  buf[sizeof(buf) - 1u] = '\0'; // Ensure null-termination
  trim_newline(buf);

  // strtok modifies the buffer, so operate on buf.
  token = strtok(buf, ";");
  while (token != NULL) {
    char *eq = strchr(token, '=');
    if (eq == NULL) {
      // Malformed token, fail decoding
      goto end;
    }
    *eq = '\0'; // Split key and value
    const char *key = token;
    const char *value = eq + 1;

    if (strncmp(key, "type", 5) == 0) { // Use strncmp for key comparison
      if (!parse_type(value, &cmd.type)) {
        goto end;
      }
      seen_type = true;
    } else if (strncmp(key, "nonce", 6) == 0) {
      // Validate conversion from string to unsigned long (nonce must be non-negative)
      char *endptr;
      unsigned long ul_nonce = strtoul(value, &endptr, 10);
      if (*endptr != '\0' || value == endptr || ul_nonce > UINT32_MAX) { // Check for invalid chars or overflow
          goto end;
      }
      cmd.nonce = (uint32_t)ul_nonce;
    } else if (strncmp(key, "origin", 7) == 0) {
      (void)strncpy(cmd.origin, value, sizeof(cmd.origin) - 1u);
      cmd.origin[sizeof(cmd.origin) - 1u] = '\0'; // Ensure null-termination
    } else if (strncmp(key, "username", 9) == 0) {
      (void)strncpy(cmd.username, value, sizeof(cmd.username) - 1u);
      cmd.username[sizeof(cmd.username) - 1u] = '\0'; // Ensure null-termination
    } else if (strncmp(key, "password", 9) == 0) {
      (void)strncpy(cmd.password, value, sizeof(cmd.password) - 1u);
      cmd.password[sizeof(cmd.password) - 1u] = '\0'; // Ensure null-termination
    } else {
      // Unknown key, reject command
      goto end;
    }

    token = strtok(NULL, ";");
  }

  if (!seen_type) {
    goto end;
  }
  *out_cmd = cmd;
  success = true;

end:
  security_secure_zero(buf, sizeof(buf)); // Zeroize buffer containing parsed data
  // cmd might contain sensitive info before copying or if parsing fails in parts, zeroize locally
  if (!success) {
      security_secure_zero(&cmd, sizeof(cmd)); // Zeroize if not successfully copied to out_cmd
  }
  return success;
}

bool command_codec_encode_result(const command_result_t *result, char *out, size_t out_len) {
  const char *allowed_str = "0";
  const char *touch_str = "0";
  const char *performed_str = "0";
  int n;

  if (result == NULL || out == NULL || out_len == 0u) {
    return false;
  }
  // Use meaningful variable names
  allowed_str = result->allowed ? "1" : "0";
  touch_str = result->touch_required ? "1" : "0";
  performed_str = result->performed ? "1" : "0";

  // Use snprintf to prevent buffer overflow
  n = snprintf(out, out_len,
                   "allowed=%s;touch_required=%s;performed=%s;message=%s",
                   allowed_str, touch_str, performed_str, result->message);

  return n > 0 && (size_t)n < out_len;
}

bool command_codec_encode(const BrowserCommand *cmd,
                          uint8_t *out_buf,
                          size_t out_len,
                          size_t *written) {
  int n;
  const char *type_str = "NONE"; // Renamed to avoid confusion with type member
  bool success = false;

  if (written != NULL) {
    *written = 0u;
  }
  if (cmd == NULL || out_buf == NULL || out_len == 0u) {
    return false;
  }
  // Initialize out_buf to all zeros for security before writing
  memset(out_buf, 0, out_len);

  switch (cmd->type) {
    case BROWSER_CMD_REQUEST_FILL: type_str = "REQUEST_FILL"; break;
    case BROWSER_CMD_REQUEST_SAVE: type_str = "REQUEST_SAVE"; break;
    case BROWSER_CMD_REQUEST_GENERATE: type_str = "REQUEST_GENERATE"; break;
    case BROWSER_CMD_REQUEST_SELECT_NEXT: type_str = "REQUEST_SELECT_NEXT"; break;
    default:
        // Unknown or invalid command type, zeroize output buffer and return false
        security_secure_zero(out_buf, out_len);
        return false;
  }

  // Use snprintf to safely write to out_buf, preventing overflow.
  // Cast out_buf to char* for snprintf.
  n = snprintf((char *)out_buf, out_len,
               "type=%s;nonce=%u;origin=%s;username=%s;password=%s",
               type_str, (unsigned)cmd->nonce, cmd->origin, cmd->username, cmd->password);

  // Check for snprintf errors or truncation
  if (n <= 0 || (size_t)n >= out_len) {
    // Error or truncation, zeroize output buffer
    security_secure_zero(out_buf, out_len);
    return false;
  }

  if (written != NULL) {
    *written = (size_t)n;
  }
  success = true;

  return success;
}

bool command_codec_decode(const uint8_t *buf, size_t len, BrowserCommand *out_cmd) {
  char line_buffer[COMMAND_CODEC_MAX_FRAME]; // Use a clearly named local buffer
  bool success = false;

  // Validate inputs strictly
  if (buf == NULL || out_cmd == NULL || len == 0u) {
    return false;
  }
  // Check for potential buffer overflow when copying to line_buffer
  if (len >= sizeof(line_buffer)) {
    return false; // Input data too large for buffer
  }

  // Copy data from buf to line_buffer and ensure null-termination
  memcpy(line_buffer, buf, len);
  line_buffer[len] = '\0'; // Manually null-terminate

  // Call the line decoding function
  success = command_codec_decode_line(line_buffer, out_cmd);

  // Securely zeroize the line_buffer after use, as it may contain sensitive information
  security_secure_zero(line_buffer, sizeof(line_buffer));
  return success;
}

