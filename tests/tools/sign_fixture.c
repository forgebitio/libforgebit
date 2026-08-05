#include "sign_fixture.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64url.h"

void fbtest_keypair_from_seed(fb_test_keypair *kp, const uint8_t seed[32]) {
    (void)sodium_init();
    crypto_sign_seed_keypair(kp->pk, kp->sk, seed);
}

char *fbtest_sign_compact(
    const fb_test_keypair *kp,
    const char *header_json,
    const char *payload_json
) {
    if (sodium_init() < 0) return NULL;

    char *header_b64 = NULL;
    size_t header_b64_len = 0;
    char *payload_b64 = NULL;
    size_t payload_b64_len = 0;
    char *sig_b64 = NULL;
    size_t sig_b64_len = 0;
    uint8_t *signing_input = NULL;
    char *out = NULL;

    if (fb_base64url_encode(
            (const uint8_t *)header_json,
            strlen(header_json),
            &header_b64,
            &header_b64_len
        ) != FB_B64_OK) {
        goto done;
    }
    if (fb_base64url_encode(
            (const uint8_t *)payload_json,
            strlen(payload_json),
            &payload_b64,
            &payload_b64_len
        ) != FB_B64_OK) {
        goto done;
    }

    size_t signing_input_len = header_b64_len + 1 + payload_b64_len;
    signing_input = (uint8_t *)malloc(signing_input_len);
    if (signing_input == NULL) goto done;
    memcpy(signing_input, header_b64, header_b64_len);
    signing_input[header_b64_len] = '.';
    memcpy(signing_input + header_b64_len + 1, payload_b64, payload_b64_len);

    uint8_t sig[64];
    if (crypto_sign_detached(sig, NULL, signing_input, signing_input_len, kp->sk) != 0) {
        goto done;
    }

    if (fb_base64url_encode(sig, sizeof(sig), &sig_b64, &sig_b64_len) != FB_B64_OK) {
        goto done;
    }

    size_t total_len = header_b64_len + 1 + payload_b64_len + 1 + sig_b64_len;
    out = (char *)malloc(total_len + 1);
    if (out == NULL) goto done;

    size_t pos = 0;
    memcpy(out + pos, header_b64, header_b64_len);
    pos += header_b64_len;
    out[pos++] = '.';
    memcpy(out + pos, payload_b64, payload_b64_len);
    pos += payload_b64_len;
    out[pos++] = '.';
    memcpy(out + pos, sig_b64, sig_b64_len);
    pos += sig_b64_len;
    out[pos] = '\0';

done:
    free(header_b64);
    free(payload_b64);
    free(sig_b64);
    free(signing_input);
    return out;
}

int fbtest_sign_raw(
    const fb_test_keypair *kp,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t sig_out[64]
) {
    if (sodium_init() < 0) return -1;
    return crypto_sign_detached(sig_out, NULL, msg, msg_len, kp->sk);
}

char *fbtest_sign_compact_default_header(
    const fb_test_keypair *kp,
    const char *kid,
    const char *payload_json
) {
    char header[256];
    int n =
        snprintf(header, sizeof(header), "{\"alg\":\"EdDSA\",\"kid\":\"%s\",\"typ\":\"JWT\"}", kid);
    if (n < 0 || (size_t)n >= sizeof(header)) return NULL;
    return fbtest_sign_compact(kp, header, payload_json);
}
