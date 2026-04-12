#ifndef SECURITY_POLICY_H
#define SECURITY_POLICY_H

#include <stdbool.h>
#include <stdint.h>

// Constants for PIN and password policies
#define PIN_DIGITS 5u
#define PASSWORD_MIN_LENGTH 8u
#define PASSWORD_MAX_LENGTH 64u
#define PASSWORD_GENERATED_DEFAULT_LENGTH 20u

// Lockout and wipe thresholds
#define MAX_PIN_FAILURES_BEFORE_WIPE 10u
#define MAX_PIN_FAILURES_BEFORE_LOCKOUT 5u

// Default timeouts and rate limiting parameters
#define AUTO_LOCK_TIMEOUT_SECONDS_DEFAULT 60u
#define MAX_COMMANDS_PER_WINDOW_DEFAULT 30u
#define COMMAND_RATE_WINDOW_SECONDS_DEFAULT 60u

// Enum for password strength classification
typedef enum {
  PASSWORD_STRENGTH_WEAK = 0,
  PASSWORD_STRENGTH_OK = 1,
  PASSWORD_STRENGTH_STRONG = 2
} password_strength_t;

// Structure to hold the result of password policy evaluation
typedef struct {
  bool too_short;
  bool is_common;
  bool is_reused;
  password_strength_t strength;
} password_policy_result_t;

// Function declarations for password policy evaluation
password_policy_result_t security_evaluate_password(const char *candidate);
bool security_should_allow_save(const password_policy_result_t *result, bool override_with_hold);
void security_set_reuse_checker(bool (*checker)(const char *candidate));
void security_set_common_password_list(const char *const *list, uint32_t count);

#endif /* SECURITY_POLICY_H */
