#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RATE_LIMIT_MAX_ORIGINS 16u

typedef struct {
  bool used;
  char origin[96];
  uint32_t window_start_tick;
  uint32_t attempt_count;
} rate_limit_entry_t;

typedef struct {
  rate_limit_entry_t entries[RATE_LIMIT_MAX_ORIGINS];
} rate_limiter_t;

void rate_limiter_init(rate_limiter_t *limiter);
bool rate_limiter_allow(rate_limiter_t *limiter,
                        const char *origin,
                        uint32_t now_tick,
                        uint32_t window_ticks,
                        uint32_t max_attempts,
                        uint32_t *retry_after_ticks);
void rate_limiter_tick(rate_limiter_t *limiter);
uint32_t rate_limiter_ticks_remaining(const rate_limiter_t *limiter);

#endif /* RATE_LIMITER_H */
