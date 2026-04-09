#ifndef PASSWORD_GENERATOR_H
#define PASSWORD_GENERATOR_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  PASSWORD_PROFILE_STRONG = 0,
  PASSWORD_PROFILE_MEMORABLE = 1
} password_profile_t;

/* Generate a password into out_buf. Returns generated length, 0 on failure. */
size_t password_generate(password_profile_t profile,
                         uint8_t *rng_seed,
                         size_t seed_len,
                         char *out_buf,
                         size_t out_buf_len);

#endif /* PASSWORD_GENERATOR_H */
