#ifndef FORGEBIT_CRYPTO_H
#define FORGEBIT_CRYPTO_H

#include "forgebit/forgebit.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "internal.h"

/* Safe to call repeatedly; returns false if libsodium initialization fails. */
bool fb_crypto_ensure_initialized(void);

/* Returns true for a valid Ed25519 signature. */
bool fb_crypto_ed25519_verify(
    const uint8_t public_key[FORGEBIT_PUBLIC_KEY_BYTES],
    const uint8_t signature[FB_ED25519_SIGNATURE_BYTES],
    const uint8_t *signing_input,
    size_t signing_input_len
);

#endif /* FORGEBIT_CRYPTO_H */
