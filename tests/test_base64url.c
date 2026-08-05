#include <stdlib.h>
#include <string.h>

#include "base64url.h"
#include "test_assert.h"

FB_TEST_CASE(decode_empty) {
    uint8_t *out = NULL;
    size_t out_len = 999;
    FB_ASSERT_EQ_INT(fb_base64url_decode("", 0, &out, &out_len), FB_B64_OK);
    FB_ASSERT_EQ_INT(out_len, 0);
    free(out);
}

FB_TEST_CASE(decode_roundtrip) {
    const uint8_t data[] = { 0x00, 0x01, 0x02, 0xFF, 0xFE, 'h', 'i', '!' };
    char *encoded = NULL;
    size_t encoded_len = 0;
    FB_ASSERT_EQ_INT(fb_base64url_encode(data, sizeof(data), &encoded, &encoded_len), FB_B64_OK);

    uint8_t *decoded = NULL;
    size_t decoded_len = 0;
    FB_ASSERT_EQ_INT(fb_base64url_decode(encoded, encoded_len, &decoded, &decoded_len), FB_B64_OK);
    FB_ASSERT_EQ_INT(decoded_len, sizeof(data));
    FB_ASSERT_TRUE(memcmp(decoded, data, sizeof(data)) == 0);

    free(encoded);
    free(decoded);
}

FB_TEST_CASE(decode_rejects_padding) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    FB_ASSERT_EQ_INT(fb_base64url_decode("aGVsbG8=", 8, &out, &out_len), FB_B64_PADDING_REJECTED);
    free(out);
}

FB_TEST_CASE(decode_rejects_invalid_char) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    FB_ASSERT_EQ_INT(fb_base64url_decode("abc+", 4, &out, &out_len), FB_B64_INVALID_CHAR);
    free(out);
    FB_ASSERT_EQ_INT(fb_base64url_decode("abc/", 4, &out, &out_len), FB_B64_INVALID_CHAR);
    free(out);
}

FB_TEST_CASE(decode_rejects_bad_length) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    FB_ASSERT_EQ_INT(fb_base64url_decode("a", 1, &out, &out_len), FB_B64_INVALID_LENGTH);
    free(out);
}

FB_TEST_CASE(decode_accepts_unpadded_tail) {
    /* "hi" -> "aGk" (3 chars, remainder 3) */
    uint8_t *out = NULL;
    size_t out_len = 0;
    FB_ASSERT_EQ_INT(fb_base64url_decode("aGk", 3, &out, &out_len), FB_B64_OK);
    FB_ASSERT_EQ_INT(out_len, 2);
    FB_ASSERT_TRUE(memcmp(out, "hi", 2) == 0);
    free(out);
}

int main(void) {
    printf("test_base64url\n");
    FB_RUN_TEST(decode_empty);
    FB_RUN_TEST(decode_roundtrip);
    FB_RUN_TEST(decode_rejects_padding);
    FB_RUN_TEST(decode_rejects_invalid_char);
    FB_RUN_TEST(decode_rejects_bad_length);
    FB_RUN_TEST(decode_accepts_unpadded_tail);
    FB_TEST_EXIT();
}
