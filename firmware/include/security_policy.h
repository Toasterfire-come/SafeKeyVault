#ifndef SECURITY_POLICY_H
#define SECURITY_POLICY_H

#include <stdbool.h>
#include <stdint.h>

#define PIN_DIGITS 5u
#define PASSWORD_MIN_LENGTH 8u
#define PASSWORD_MAX_LENGTH 64u
#define PASSWORD_GENERATED_DEFAULT_LENGTH 20u

#define MAX_PIN_FAILURES_BEFORE_WIPE 10u
#define MAX_PIN_FAILURES_BEFORE_LOCKOUT 5u

#define AUTO_LOCK_TIMEOUT_SECONDS_DEFAULT 60u

typedef enum {
  PASSWORD_STRENGTH_WEAK = 0,
  PASSWORD_STRENGTH_OK = 1,
  PASSWORD_STRENGTH_STRONG = 2
} password_strength_t;

typedef struct {
  bool too_short;
  bool is_common;
  bool is_reused;
  password_strength_t strength;
} password_policy_result_t;

password_policy_result_t security_evaluate_password(const char *candidate);
bool security_should_allow_save(const password_policy_result_t *result, bool override_with_hold);
void security_set_reuse_checker(bool (*checker)(const char *candidate));

void security_set_common_password_list(const char *const *list, uint32_t count);

#endif
