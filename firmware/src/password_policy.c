#include "security_policy.h"

#include <ctype.h>
#include <stddef.h>
#include <string.h>

#include "common_passwords.h"

static bool (*g_reuse_checker)(const char *candidate) = NULL;
static const char *const *g_common_list = NULL;
static uint32_t g_common_count = 0;

static bool contains_common_password(const char *candidate) {
  const char *const *list = g_common_list ? g_common_list : k_common_passwords;
  uint32_t count = g_common_list ? g_common_count : (uint32_t)k_common_passwords_count;

  for (uint32_t i = 0; i < count; ++i) {
    if (strcmp(candidate, list[i]) == 0) {
      return true;
    }
  }
  return false;
}

static password_strength_t classify_strength(const char *candidate) {
  bool has_upper = false;
  bool has_lower = false;
  bool has_digit = false;
  bool has_symbol = false;
  size_t len = strlen(candidate);

  for (size_t i = 0; i < len; ++i) {
    unsigned char ch = (unsigned char)candidate[i];
    if (isupper(ch)) {
      has_upper = true;
    } else if (islower(ch)) {
      has_lower = true;
    } else if (isdigit(ch)) {
      has_digit = true;
    } else {
      has_symbol = true;
    }
  }

  unsigned score = 0;
  score += has_upper ? 1u : 0u;
  score += has_lower ? 1u : 0u;
  score += has_digit ? 1u : 0u;
  score += has_symbol ? 1u : 0u;
  score += len >= 12u ? 1u : 0u;
  score += len >= 20u ? 1u : 0u;

  if (score >= 5u) {
    return PASSWORD_STRENGTH_STRONG;
  }
  if (score >= 3u) {
    return PASSWORD_STRENGTH_OK;
  }
  return PASSWORD_STRENGTH_WEAK;
}

password_policy_result_t security_evaluate_password(const char *candidate) {
  password_policy_result_t result = {0};
  if (!candidate) {
    result.too_short = true;
    result.strength = PASSWORD_STRENGTH_WEAK;
    return result;
  }

  size_t len = strlen(candidate);
  result.too_short = (len < PASSWORD_MIN_LENGTH);
  result.is_common = contains_common_password(candidate);
  result.is_reused = g_reuse_checker ? g_reuse_checker(candidate) : false;
  result.strength = classify_strength(candidate);
  return result;
}

bool security_should_allow_save(const password_policy_result_t *result, bool override_with_hold) {
  if (!result) {
    return false;
  }

  if (result->too_short) {
    return false;
  }

  if ((result->is_common || result->is_reused) && !override_with_hold) {
    return false;
  }

  return true;
}

void security_set_reuse_checker(bool (*checker)(const char *candidate)) {
  g_reuse_checker = checker;
}

void security_set_common_password_list(const char *const *list, uint32_t count) {
  g_common_list = list;
  g_common_count = count;
}
