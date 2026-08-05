#include "crypto.h"

#include <sodium.h>

bool fb_crypto_ensure_initialized(void) {
    /* sodium_init() returns 0 on first successful init, 1 if already
     * initialized, -1 on failure. Both 0 and 1 are success. */
    return sodium_init() >= 0;
}

bool fb_crypto_ed25519_verify(
    const uint8_t public_key[FB_ED25519_PUBLIC_KEY_BYTES],
    const uint8_t signature[FB_ED25519_SIGNATURE_BYTES],
    const uint8_t *signing_input,
    size_t signing_input_len
) {
    if (public_key == NULL || signature == NULL) return false;
    if (signing_input_len > 0 && signing_input == NULL) return false;

    return crypto_sign_verify_detached(signature, signing_input, signing_input_len, public_key) ==
           0;
}
