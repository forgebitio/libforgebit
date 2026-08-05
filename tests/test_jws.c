#include <string.h>

#include "jws.h"
#include "test_assert.h"

FB_TEST_CASE(splits_three_segments) {
    const char *license = "aGVhZGVy.cGF5bG9hZA.c2ln";
    fb_jws_segments segs;
    FB_ASSERT_EQ_INT(fb_jws_split((const uint8_t *)license, strlen(license), &segs), FB_JWS_OK);
    FB_ASSERT_EQ_INT(segs.header_b64_len, 8);
    FB_ASSERT_TRUE(memcmp(segs.header_b64, "aGVhZGVy", 8) == 0);
    FB_ASSERT_EQ_INT(segs.payload_b64_len, 10);
    FB_ASSERT_TRUE(memcmp(segs.payload_b64, "cGF5bG9hZA", 10) == 0);
    FB_ASSERT_EQ_INT(segs.sig_b64_len, 4);
    FB_ASSERT_TRUE(memcmp(segs.sig_b64, "c2ln", 4) == 0);

    /* signing_input == header_b64 "." payload_b64, contiguous slice */
    FB_ASSERT_EQ_INT(segs.signing_input_len, 8 + 1 + 10);
    FB_ASSERT_TRUE(memcmp(segs.signing_input, "aGVhZGVy.cGF5bG9hZA", 19) == 0);
}

FB_TEST_CASE(trims_outer_whitespace_only) {
    const char *license = "  \n aGVhZGVy.cGF5bG9hZA.c2ln \t ";
    fb_jws_segments segs;
    FB_ASSERT_EQ_INT(fb_jws_split((const uint8_t *)license, strlen(license), &segs), FB_JWS_OK);
    FB_ASSERT_EQ_INT(segs.header_b64_len, 8);
}

FB_TEST_CASE(rejects_wrong_segment_count) {
    const char *too_few = "aGVhZGVy.cGF5bG9hZA";
    fb_jws_segments segs;
    FB_ASSERT_EQ_INT(fb_jws_split((const uint8_t *)too_few, strlen(too_few), &segs), FB_JWS_WRONG_SEGMENT_COUNT);

    const char *too_many = "a.b.c.d";
    FB_ASSERT_EQ_INT(fb_jws_split((const uint8_t *)too_many, strlen(too_many), &segs), FB_JWS_WRONG_SEGMENT_COUNT);
}

FB_TEST_CASE(rejects_empty_segment) {
    const char *unsigned_token = "aGVhZGVy.cGF5bG9hZA.";
    fb_jws_segments segs;
    FB_ASSERT_EQ_INT(fb_jws_split((const uint8_t *)unsigned_token, strlen(unsigned_token), &segs), FB_JWS_EMPTY_SEGMENT);

    const char *empty_header = ".cGF5bG9hZA.c2ln";
    FB_ASSERT_EQ_INT(fb_jws_split((const uint8_t *)empty_header, strlen(empty_header), &segs), FB_JWS_EMPTY_SEGMENT);
}

FB_TEST_CASE(rejects_all_empty_input) {
    fb_jws_segments segs;
    FB_ASSERT_EQ_INT(fb_jws_split((const uint8_t *)"", 0, &segs), FB_JWS_EMPTY_SEGMENT);
    FB_ASSERT_EQ_INT(fb_jws_split(NULL, 0, &segs), FB_JWS_EMPTY_SEGMENT);
}

int main(void) {
    printf("test_jws\n");
    FB_RUN_TEST(splits_three_segments);
    FB_RUN_TEST(trims_outer_whitespace_only);
    FB_RUN_TEST(rejects_wrong_segment_count);
    FB_RUN_TEST(rejects_empty_segment);
    FB_RUN_TEST(rejects_all_empty_input);
    FB_TEST_EXIT();
}
