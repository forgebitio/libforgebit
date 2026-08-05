#include "forgebit/forgebit.h"

#include <string.h>

#include "json.h"
#include "test_assert.h"

static fb_json_parse_options default_opts(void) {
    fb_json_parse_options o = { 64, 768 * 1024, true };
    return o;
}

FB_TEST_CASE(parse_simple_object) {
    const char *text = "{\"a\":1,\"b\":true,\"c\":null,\"d\":\"hi\",\"e\":[1,2,3]}";
    fb_json_parse_options o = default_opts();
    fb_json_value *root = NULL;
    FB_ASSERT_EQ_INT(fb_json_parse((const uint8_t *)text, strlen(text), &o, &root), FB_JSON_OK);
    FB_ASSERT_TRUE(fb_json_is_object(root));
    FB_ASSERT_EQ_INT(forgebit_json_object_size(root), 5);

    const fb_json_value *a = fb_json_object_find(root, "a");
    FB_ASSERT_TRUE(fb_json_is_int(a));
    FB_ASSERT_EQ_INT(a->as.i, 1);

    const fb_json_value *e = fb_json_object_find(root, "e");
    FB_ASSERT_TRUE(fb_json_is_array(e));
    FB_ASSERT_EQ_INT(e->as.arr.count, 3);

    fb_json_free(root);
}

FB_TEST_CASE(integer_lexical_form_is_int) {
    const char *text = "{\"iat\":100}";
    fb_json_parse_options o = default_opts();
    fb_json_value *root = NULL;
    FB_ASSERT_EQ_INT(fb_json_parse((const uint8_t *)text, strlen(text), &o, &root), FB_JSON_OK);
    const fb_json_value *iat = fb_json_object_find(root, "iat");
    FB_ASSERT_TRUE(fb_json_is_int(iat));
    fb_json_free(root);
}

FB_TEST_CASE(float_lexical_form_is_double_even_if_integral) {
    const char *text = "{\"iat\":100.0}";
    fb_json_parse_options o = default_opts();
    fb_json_value *root = NULL;
    FB_ASSERT_EQ_INT(fb_json_parse((const uint8_t *)text, strlen(text), &o, &root), FB_JSON_OK);
    const fb_json_value *iat = fb_json_object_find(root, "iat");
    FB_ASSERT_FALSE(fb_json_is_int(iat));
    FB_ASSERT_EQ_INT(iat->tag, FB_JSON_TAG_DOUBLE);
    fb_json_free(root);
}

FB_TEST_CASE(exponent_form_is_double) {
    const char *text = "{\"n\":1e2}";
    fb_json_parse_options o = default_opts();
    fb_json_value *root = NULL;
    FB_ASSERT_EQ_INT(fb_json_parse((const uint8_t *)text, strlen(text), &o, &root), FB_JSON_OK);
    const fb_json_value *n = fb_json_object_find(root, "n");
    FB_ASSERT_EQ_INT(n->tag, FB_JSON_TAG_DOUBLE);
    fb_json_free(root);
}

FB_TEST_CASE(rejects_duplicate_keys) {
    const char *text = "{\"a\":1,\"a\":2}";
    fb_json_parse_options o = default_opts();
    fb_json_value *root = NULL;
    FB_ASSERT_EQ_INT(fb_json_parse((const uint8_t *)text, strlen(text), &o, &root), FB_JSON_ERR_DUPLICATE_KEY);
}

FB_TEST_CASE(rejects_trailing_data) {
    const char *text = "{}garbage";
    fb_json_parse_options o = default_opts();
    fb_json_value *root = NULL;
    FB_ASSERT_EQ_INT(fb_json_parse((const uint8_t *)text, strlen(text), &o, &root), FB_JSON_ERR_TRAILING_DATA);
}

FB_TEST_CASE(rejects_non_object_root_when_required) {
    const char *text = "[1,2,3]";
    fb_json_parse_options o = default_opts();
    fb_json_value *root = NULL;
    FB_ASSERT_EQ_INT(fb_json_parse((const uint8_t *)text, strlen(text), &o, &root), FB_JSON_ERR_NOT_OBJECT);
}

FB_TEST_CASE(rejects_excess_depth) {
    /* depth limit of 2: {"a":{"b":{}}} nests three objects deep */
    const char *text = "{\"a\":{\"b\":{}}}";
    fb_json_parse_options o = { 2, 768 * 1024, true };
    fb_json_value *root = NULL;
    FB_ASSERT_EQ_INT(fb_json_parse((const uint8_t *)text, strlen(text), &o, &root), FB_JSON_ERR_DEPTH);
}

FB_TEST_CASE(rejects_oversized_input) {
    const char *text = "{\"a\":1}";
    fb_json_parse_options o = { 64, 3, true };
    fb_json_value *root = NULL;
    FB_ASSERT_EQ_INT(fb_json_parse((const uint8_t *)text, strlen(text), &o, &root), FB_JSON_ERR_TOO_LARGE);
}

FB_TEST_CASE(handles_embedded_nul_via_unicode_escape) {
    const char *text = "{\"s\":\"ab\\u0000cd\"}";
    fb_json_parse_options o = default_opts();
    fb_json_value *root = NULL;
    FB_ASSERT_EQ_INT(fb_json_parse((const uint8_t *)text, strlen(text), &o, &root), FB_JSON_OK);
    const fb_json_value *s = fb_json_object_find(root, "s");
    FB_ASSERT_TRUE(fb_json_is_string(s));
    FB_ASSERT_EQ_INT(s->as.str.len, 5);
    FB_ASSERT_TRUE(memcmp(s->as.str.ptr, "ab\0cd", 5) == 0);
    fb_json_free(root);
}

FB_TEST_CASE(rejects_invalid_utf8) {
    const uint8_t text[] = { '{', '"', 'a', '"', ':', '"', 0xC0, 0x80, '"', '}' };
    fb_json_parse_options o = default_opts();
    fb_json_value *root = NULL;
    FB_ASSERT_EQ_INT(fb_json_parse(text, sizeof(text), &o, &root), FB_JSON_ERR_UTF8);
}

int main(void) {
    printf("test_json\n");
    FB_RUN_TEST(parse_simple_object);
    FB_RUN_TEST(integer_lexical_form_is_int);
    FB_RUN_TEST(float_lexical_form_is_double_even_if_integral);
    FB_RUN_TEST(exponent_form_is_double);
    FB_RUN_TEST(rejects_duplicate_keys);
    FB_RUN_TEST(rejects_trailing_data);
    FB_RUN_TEST(rejects_non_object_root_when_required);
    FB_RUN_TEST(rejects_excess_depth);
    FB_RUN_TEST(rejects_oversized_input);
    FB_RUN_TEST(handles_embedded_nul_via_unicode_escape);
    FB_RUN_TEST(rejects_invalid_utf8);
    FB_TEST_EXIT();
}
