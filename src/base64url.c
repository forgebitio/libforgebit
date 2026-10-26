#include "base64url.h"

#include <stdlib.h>

static const char encode_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* -1 = invalid character, -2 = '=' (padding, rejected by policy). */
static int8_t decode_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return (int8_t)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int8_t)(c - 'a' + 26);
    if (c >= '0' && c <= '9') return (int8_t)(c - '0' + 52);
    if (c == '-') return 62;
    if (c == '_') return 63;
    if (c == '=') return -2;
    return -1;
}

fb_b64_status fb_base64url_decode(const char *in, size_t in_len, uint8_t **out, size_t *out_len) {
    if (out == NULL || out_len == NULL) {
        return FB_B64_INVALID_LENGTH;
    }
    *out = NULL;
    *out_len = 0;

    if (in_len > 0 && in == NULL) {
        return FB_B64_INVALID_LENGTH;
    }

    size_t remainder = in_len % 4;
    if (remainder == 1) {
        return FB_B64_INVALID_LENGTH;
    }

    size_t full_groups = in_len / 4;
    size_t decoded_len = full_groups * 3;
    if (remainder == 2) {
        decoded_len += 1;
    } else if (remainder == 3) {
        decoded_len += 2;
    }

    uint8_t *buf = (uint8_t *)malloc(decoded_len + 1);
    if (buf == NULL) {
        return FB_B64_ALLOC_FAILED;
    }

    size_t out_pos = 0;
    size_t i = 0;
    while (i < in_len) {
        size_t chunk = in_len - i;
        if (chunk > 4) chunk = 4;

        int8_t vals[4] = { 0, 0, 0, 0 };
        for (size_t j = 0; j < chunk; j++) {
            int8_t v = decode_value((unsigned char)in[i + j]);
            if (v == -2) {
                free(buf);
                return FB_B64_PADDING_REJECTED;
            }
            if (v == -1) {
                free(buf);
                return FB_B64_INVALID_CHAR;
            }
            vals[j] = v;
        }
        if ((chunk == 2 && (vals[1] & 0x0F) != 0) || (chunk == 3 && (vals[2] & 0x03) != 0)) {
            free(buf);
            return FB_B64_NONCANONICAL;
        }

        uint32_t triple = ((uint32_t)vals[0] << 18) | ((uint32_t)vals[1] << 12) |
                          ((uint32_t)vals[2] << 6) | (uint32_t)vals[3];

        if (chunk >= 2) buf[out_pos++] = (uint8_t)((triple >> 16) & 0xFF);
        if (chunk >= 3) buf[out_pos++] = (uint8_t)((triple >> 8) & 0xFF);
        if (chunk == 4) buf[out_pos++] = (uint8_t)(triple & 0xFF);

        i += chunk;
    }

    buf[decoded_len] = '\0';
    *out = buf;
    *out_len = decoded_len;
    return FB_B64_OK;
}

fb_b64_status fb_base64url_encode(const uint8_t *in, size_t in_len, char **out, size_t *out_len) {
    if (out == NULL || out_len == NULL) {
        return FB_B64_INVALID_LENGTH;
    }
    *out = NULL;
    *out_len = 0;

    if (in_len > 0 && in == NULL) {
        return FB_B64_INVALID_LENGTH;
    }

    size_t full_groups = in_len / 3;
    size_t remainder = in_len % 3;
    size_t encoded_len = full_groups * 4;
    if (remainder == 1)
        encoded_len += 2;
    else if (remainder == 2)
        encoded_len += 3;

    char *buf = (char *)malloc(encoded_len + 1);
    if (buf == NULL) {
        return FB_B64_ALLOC_FAILED;
    }

    size_t out_pos = 0;
    size_t i = 0;
    while (i + 3 <= in_len) {
        uint32_t triple =
            ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | (uint32_t)in[i + 2];
        buf[out_pos++] = encode_alphabet[(triple >> 18) & 0x3F];
        buf[out_pos++] = encode_alphabet[(triple >> 12) & 0x3F];
        buf[out_pos++] = encode_alphabet[(triple >> 6) & 0x3F];
        buf[out_pos++] = encode_alphabet[triple & 0x3F];
        i += 3;
    }

    if (remainder == 1) {
        uint32_t triple = (uint32_t)in[i] << 16;
        buf[out_pos++] = encode_alphabet[(triple >> 18) & 0x3F];
        buf[out_pos++] = encode_alphabet[(triple >> 12) & 0x3F];
    } else if (remainder == 2) {
        uint32_t triple = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        buf[out_pos++] = encode_alphabet[(triple >> 18) & 0x3F];
        buf[out_pos++] = encode_alphabet[(triple >> 12) & 0x3F];
        buf[out_pos++] = encode_alphabet[(triple >> 6) & 0x3F];
    }

    buf[encoded_len] = '\0';
    *out = buf;
    *out_len = encoded_len;
    return FB_B64_OK;
}
