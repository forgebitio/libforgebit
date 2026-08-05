#ifndef FORGEBIT_TEST_SIGN_FIXTURE_H
#define FORGEBIT_TEST_SIGN_FIXTURE_H

/* Test-only Ed25519 signer for fixture licenses. */

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t pk[32];
    uint8_t sk[64];
} fb_test_keypair;

/* Deterministic keypair derivation so fixtures are reproducible. */
void fbtest_keypair_from_seed(fb_test_keypair *kp, const uint8_t seed[32]);

/* Signs the supplied JSON without rewriting it, allowing malformed JSON in
 * negative fixtures. Returns a heap-allocated compact JWS or NULL. */
char *fbtest_sign_compact(
    const fb_test_keypair *kp,
    const char *header_json,
    const char *payload_json
);

/* Signs with the standard EdDSA/JWT header and the supplied kid. */
char *fbtest_sign_compact_default_header(
    const fb_test_keypair *kp,
    const char *kid,
    const char *payload_json
);

/* Signs an arbitrary byte string for tampering tests. Returns 0 on success. */
int fbtest_sign_raw(
    const fb_test_keypair *kp,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t sig_out[64]
);

#endif /* FORGEBIT_TEST_SIGN_FIXTURE_H */
