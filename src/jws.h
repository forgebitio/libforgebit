#ifndef FORGEBIT_JWS_H
#define FORGEBIT_JWS_H

#include <stddef.h>
#include <stdint.h>

/* All pointers here are borrows into the original license buffer passed
 * to fb_jws_split -- nothing is copied or reallocated. signing_input
 * points at header_b64 and spans through payload_b64 inclusive of the
 * separating '.', exactly matching the JWS signing-input definition, so
 * it can be handed directly to Ed25519 verification with no
 * reserialization step. */
typedef struct {
    const uint8_t *header_b64;
    size_t header_b64_len;
    const uint8_t *payload_b64;
    size_t payload_b64_len;
    const uint8_t *sig_b64;
    size_t sig_b64_len;
    const uint8_t *signing_input;
    size_t signing_input_len;
} fb_jws_segments;

typedef enum { FB_JWS_OK = 0, FB_JWS_WRONG_SEGMENT_COUNT, FB_JWS_EMPTY_SEGMENT } fb_jws_status;

/* Trims only outer leading/trailing ASCII whitespace from `license`, then
 * requires exactly three non-empty, dot-separated segments. Never
 * tolerates whitespace or other stray bytes inside a segment -- those
 * are rejected later as invalid base64url alphabet. */
fb_jws_status fb_jws_split(const uint8_t *license, size_t len, fb_jws_segments *out);

#endif /* FORGEBIT_JWS_H */
