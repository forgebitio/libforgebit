#ifndef FORGEBIT_BASE64URL_H
#define FORGEBIT_BASE64URL_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    FB_B64_OK = 0,
    FB_B64_INVALID_CHAR,
    FB_B64_INVALID_LENGTH,
    FB_B64_PADDING_REJECTED,
    FB_B64_NONCANONICAL,
    FB_B64_ALLOC_FAILED
} fb_b64_status;

/* Strict unpadded base64url decode. Alphabet is exactly
 * [A-Za-z0-9-_]; any '=' present is rejected rather than tolerated, as
 * are non-zero unused bits in the final character, so every byte string
 * has exactly one accepted encoding.
 * On FB_B64_OK, *out is a malloc'd buffer of *out_len bytes that the
 * caller must free(); it is NUL-terminated as a convenience (the extra
 * byte is not counted in *out_len) but callers must use the explicit
 * length, since decoded content may itself contain embedded NUL bytes. */
fb_b64_status fb_base64url_decode(const char *in, size_t in_len, uint8_t **out, size_t *out_len);

/* Strict unpadded base64url encode. On FB_B64_OK, *out is a malloc'd,
 * NUL-terminated buffer; *out_len excludes the terminator. */
fb_b64_status fb_base64url_encode(const uint8_t *in, size_t in_len, char **out, size_t *out_len);

#endif /* FORGEBIT_BASE64URL_H */
