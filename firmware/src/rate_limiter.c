#include "rate_limiter.h"

#include <string.h>

static rate_limit_entry_t *find_slot(rate_limiter_t *limiter, const char *origin) {
  size_t i;
  rate_limit_entry_t *free_slot = NULL;
  if (limiter == NULL || origin == NULL) {
    return NULL;
  }
  for (i = 0u; i < RATE_LIMIT_MAX_ORIGINS; ++i) {
    rate_limit_entry_t *e = &limiter->entries[i];
    if (!e->used) {
      if (free_slot == NULL) {
        free_slot = e;
      }
      continue;
    }
    if (strncmp(e->origin, origin, sizeof(e->origin)) == 0) {
      return e;
    }
  }
  return free_slot;
}

void rate_limiter_init(rate_limiter_t *limiter) {
  if (limiter == NULL) {
    return;
  }
  memset(limiter, 0, sizeof(*limiter));
}

bool rate_limiter_allow(rate_limiter_t *limiter,
                        const char *origin,
                        uint32_t now_tick,
                        uint32_t window_ticks,
                        uint32_t max_attempts,
                        uint32_t *retry_after_ticks) {
  rate_limit_entry_t *slot;
  if (retry_after_ticks != NULL) {
    *retry_after_ticks = 0u;
  }
  if (limiter == NULL || origin == NULL || window_ticks == 0u || max_attempts == 0u) {
    return false;
  }
  slot = find_slot(limiter, origin);
  if (slot == NULL) {
    return false;
  }
  if (!slot->used) {
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    (void)strncpy(slot->origin, origin, sizeof(slot->origin) - 1u);
    slot->window_start_tick = now_tick;
  }
  if (now_tick - slot->window_start_tick >= window_ticks) {
    slot->window_start_tick = now_tick;
    slot->attempt_count = 0u;
  }
  if (slot->attempt_count >= max_attempts) {
    if (retry_after_ticks != NULL) {
      uint32_t elapsed = now_tick - slot->window_start_tick;
      *retry_after_ticks = (elapsed >= window_ticks) ? 0u : (window_ticks - elapsed);
    }
    return false;
  }
  slot->attempt_count++;
  return true;
}

void rate_limiter_tick(rate_limiter_t *limiter) {
  if (limiter == NULL) {
    return;
  }
  for (size_t i = 0u; i < RATE_LIMIT_MAX_ORIGINS; ++i) {
    rate_limit_entry_t *e = &limiter->entries[i];
    if (!e->used) {
      continue;
    }
    if (e->window_start_tick > 0u) {
      e->window_start_tick--;
    }
  }
}

uint32_t rate_limiter_ticks_remaining(const rate_limiter_t *limiter) {
  uint32_t max_remaining = 0u;
  if (limiter == NULL) {
    return 0u;
  }
  for (size_t i = 0u; i < RATE_LIMIT_MAX_ORIGINS; ++i) {
    const rate_limit_entry_t *e = &limiter->entries[i];
    if (!e->used) {
      continue;
    }
    if (e->attempt_count > max_remaining) {
      max_remaining = e->attempt_count;
    }
  }
  return max_remaining;
}
