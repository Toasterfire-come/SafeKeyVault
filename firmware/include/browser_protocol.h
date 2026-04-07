#ifndef BROWSER_PROTOCOL_H
#define BROWSER_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>

#include "firmware_types.h"

typedef enum {
    BROWSER_CMD_NONE = 0,
    BROWSER_CMD_REQUEST_FILL,
    BROWSER_CMD_REQUEST_SAVE,
    BROWSER_CMD_REQUEST_GENERATE,
    BROWSER_CMD_REQUEST_SELECT_NEXT,
} BrowserCommandType;

typedef struct {
    BrowserCommandType type;
    char origin[96];
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
} BrowserCommand;

typedef struct {
    bool accepted;
    bool touch_required;
    bool high_risk_origin;
    char message[96];
} BrowserCommandResult;

bool browser_origin_is_suspicious(const char *origin);
bool browser_validate_command(const BrowserCommand *cmd, BrowserCommandResult *result);

#endif
