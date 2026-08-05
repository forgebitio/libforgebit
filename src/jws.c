#include "jws.h"

#include <stdbool.h>

static bool is_outer_ws(uint8_t c) {
    return c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D;
}

fb_jws_status fb_jws_split(const uint8_t *license, size_t len, fb_jws_segments *out) {
    size_t start = 0;
    size_t end = len;

    while (start < end && is_outer_ws(license[start]))
        start++;
    while (end > start && is_outer_ws(license[end - 1]))
        end--;

    if (start >= end) {
        return FB_JWS_EMPTY_SEGMENT;
    }

    size_t first_dot = (size_t)-1;
    size_t second_dot = (size_t)-1;
    size_t dot_count = 0;

    for (size_t i = start; i < end; i++) {
        if (license[i] == '.') {
            dot_count++;
            if (dot_count == 1)
                first_dot = i;
            else if (dot_count == 2)
                second_dot = i;
        }
    }

    if (dot_count != 2) {
        return FB_JWS_WRONG_SEGMENT_COUNT;
    }

    const uint8_t *header = license + start;
    size_t header_len = first_dot - start;

    const uint8_t *payload = license + first_dot + 1;
    size_t payload_len = second_dot - (first_dot + 1);

    const uint8_t *sig = license + second_dot + 1;
    size_t sig_len = end - (second_dot + 1);

    if (header_len == 0 || payload_len == 0 || sig_len == 0) {
        return FB_JWS_EMPTY_SEGMENT;
    }

    out->header_b64 = header;
    out->header_b64_len = header_len;
    out->payload_b64 = payload;
    out->payload_b64_len = payload_len;
    out->sig_b64 = sig;
    out->sig_b64_len = sig_len;
    out->signing_input = header;
    out->signing_input_len = (size_t)((payload + payload_len) - header);

    return FB_JWS_OK;
}
