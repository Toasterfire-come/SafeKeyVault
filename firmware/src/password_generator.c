#include "password_generator.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "security_policy.h"

static const char k_charset_strong[] =
    "ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghijkmnopqrstuvwxyz"
    "23456789"
    "!@#$%^&*()-_=+[]{}:;,.?";

static const char *k_wordlist[] = {
    "amber", "river", "orbit", "forest", "cipher", "maple", "north", "saffron",
    "velvet", "summit", "cobalt", "harbor", "lunar", "prairie", "thunder", "atlas"
};

static uint32_t rng_step(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static uint32_t seed_from_bytes(const uint8_t *seed, size_t seed_len) {
    uint32_t state = 0xA5F01D3Fu;
    size_t i;
    for (i = 0; i < seed_len; ++i) {
        state ^= (uint32_t)seed[i] << (i % 24u);
        state = (state << 7) | (state >> 25);
        state *= 0x9E3779B1u;
    }
    if (state == 0u) {
        state = 0x6D2B79F5u;
    }
    return state;
}

static size_t generate_strong(uint32_t *state, char *out_buf, size_t out_buf_len) {
    size_t i;
    const size_t chars = sizeof(k_charset_strong) - 1u;
    const size_t target_len =
        (PASSWORD_GENERATED_DEFAULT_LENGTH < out_buf_len - 1u)
            ? PASSWORD_GENERATED_DEFAULT_LENGTH
            : (out_buf_len - 1u);

    if (out_buf_len < PASSWORD_MIN_LENGTH + 1u) {
        return 0u;
    }

    for (i = 0; i < target_len; ++i) {
        out_buf[i] = k_charset_strong[rng_step(state) % chars];
    }
    out_buf[target_len] = '\0';
    return target_len;
}

static size_t generate_memorable(uint32_t *state, char *out_buf, size_t out_buf_len) {
    const size_t word_count = sizeof(k_wordlist) / sizeof(k_wordlist[0]);
    size_t used = 0u;
    size_t words = 0u;

    if (out_buf_len < PASSWORD_MIN_LENGTH + 1u) {
        return 0u;
    }

    while (words < 3u && used + 2u < out_buf_len) {
        const char *word = k_wordlist[rng_step(state) % word_count];
        const size_t word_len = strlen(word);
        if (used + word_len + 2u >= out_buf_len) {
            break;
        }
        memcpy(out_buf + used, word, word_len);
        used += word_len;
        out_buf[used++] = '-';
        words++;
    }

    if (used + 2u >= out_buf_len) {
        return 0u;
    }

    out_buf[used++] = (char)('0' + (rng_step(state) % 10u));
    out_buf[used++] = (char)('0' + (rng_step(state) % 10u));
    out_buf[used] = '\0';

    if (used < PASSWORD_MIN_LENGTH) {
        return 0u;
    }
    return used;
}

size_t password_generate(password_profile_t profile,
                         uint8_t *rng_seed,
                         size_t seed_len,
                         char *out_buf,
                         size_t out_buf_len) {
    uint32_t state;
    if (out_buf == NULL || out_buf_len == 0u || rng_seed == NULL || seed_len == 0u) {
        return 0u;
    }

    state = seed_from_bytes(rng_seed, seed_len);
    if (profile == PASSWORD_PROFILE_MEMORABLE) {
        return generate_memorable(&state, out_buf, out_buf_len);
    }
    return generate_strong(&state, out_buf, out_buf_len);
}
