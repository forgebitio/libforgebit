#include <string.h>

#include "claims.h"
#include "json.h"
#include "test_assert.h"

static fb_json_value *parse_payload(const char *text) {
    fb_json_parse_options o = { 64, 768 * 1024, true };
    fb_json_value *root = NULL;
    fb_json_status st = fb_json_parse((const uint8_t *)text, strlen(text), &o, &root);
    if (st != FB_JSON_OK) return NULL;
    return root;
}

FB_TEST_CASE(no_hwid_in_payload_is_noop) {
    fb_json_value *p = parse_payload("{}");
    FB_ASSERT_EQ_INT(fb_claims_validate_hardware(p, NULL), FORGEBIT_VALID);
    FB_ASSERT_EQ_INT(fb_claims_validate_hardware(p, "machine-1"), FORGEBIT_VALID);
    fb_json_free(p);
}

FB_TEST_CASE(string_hwid_requires_caller_value) {
    fb_json_value *p = parse_payload("{\"hwid\":\"machine-1\"}");
    FB_ASSERT_EQ_INT(fb_claims_validate_hardware(p, NULL), FORGEBIT_HARDWARE_ID_REQUIRED);
    fb_json_free(p);
}

FB_TEST_CASE(string_hwid_exact_match) {
    fb_json_value *p = parse_payload("{\"hwid\":\"machine-1\"}");
    FB_ASSERT_EQ_INT(fb_claims_validate_hardware(p, "machine-1"), FORGEBIT_VALID);
    FB_ASSERT_EQ_INT(fb_claims_validate_hardware(p, "Machine-1"), FORGEBIT_HARDWARE_MISMATCH);
    FB_ASSERT_EQ_INT(fb_claims_validate_hardware(p, "machine-2"), FORGEBIT_HARDWARE_MISMATCH);
    fb_json_free(p);
}

FB_TEST_CASE(array_hwid_any_match_succeeds) {
    fb_json_value *p = parse_payload("{\"hwid\":[\"a\",\"b\",\"c\"]}");
    FB_ASSERT_EQ_INT(fb_claims_validate_hardware(p, "b"), FORGEBIT_VALID);
    FB_ASSERT_EQ_INT(fb_claims_validate_hardware(p, "z"), FORGEBIT_HARDWARE_MISMATCH);
    fb_json_free(p);
}

int main(void) {
    printf("test_hwid\n");
    FB_RUN_TEST(no_hwid_in_payload_is_noop);
    FB_RUN_TEST(string_hwid_requires_caller_value);
    FB_RUN_TEST(string_hwid_exact_match);
    FB_RUN_TEST(array_hwid_any_match_succeeds);
    FB_TEST_EXIT();
}
