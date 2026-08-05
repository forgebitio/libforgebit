#include <stdint.h>
#include <string.h>

#include "claims.h"
#include "json.h"
#include "result.h"
#include "test_assert.h"

static fb_json_value *parse_payload(const char *text) {
    fb_json_parse_options o = { 64, 768 * 1024, true };
    fb_json_value *root = NULL;
    fb_json_status st = fb_json_parse((const uint8_t *)text, strlen(text), &o, &root);
    if (st != FB_JSON_OK) return NULL;
    return root;
}

FB_TEST_CASE(required_claims_accepts_minimal_valid_payload) {
    fb_json_value *p = parse_payload(
        "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-1\",\"iat\":100,"
        "\"offline\":true,\"features\":{}}"
    );
    forgebit_verify_result *r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_required(p, r), FORGEBIT_VALID);
    fb_json_free(p);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(required_claims_rejects_missing_claim) {
    fb_json_value *p = parse_payload(
        "{\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-1\",\"iat\":100,\"offline\":true,"
        "\"features\":{}}"
    );
    forgebit_verify_result *r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_required(p, r), FORGEBIT_MALFORMED_PAYLOAD);
    fb_json_free(p);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(required_claims_rejects_wrong_type) {
    fb_json_value *p = parse_payload(
        "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-1\",\"iat\":\"100\","
        "\"offline\":true,\"features\":{}}"
    );
    forgebit_verify_result *r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_required(p, r), FORGEBIT_MALFORMED_PAYLOAD);
    fb_json_free(p);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(required_claims_rejects_float_iat) {
    fb_json_value *p = parse_payload(
        "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-1\",\"iat\":100.0,"
        "\"offline\":true,\"features\":{}}"
    );
    forgebit_verify_result *r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_required(p, r), FORGEBIT_MALFORMED_PAYLOAD);
    fb_json_free(p);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(required_claims_warns_on_unknown_claim) {
    fb_json_value *p = parse_payload(
        "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-1\",\"iat\":100,"
        "\"offline\":true,\"features\":{},\"mystery\":1}"
    );
    forgebit_verify_result *r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_required(p, r), FORGEBIT_VALID);
    FB_ASSERT_EQ_INT(forgebit_result_warning_count(r), 1);
    FB_ASSERT_EQ_INT(forgebit_result_warning_at(r, 0), FORGEBIT_WARNING_UNRECOGNIZED_CLAIMS);
    fb_json_free(p);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(time_rejects_issued_in_future) {
    fb_json_value *p = parse_payload("{\"iat\":1000}");
    forgebit_verify_result *r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_time(p, 500, 0, false, r), FORGEBIT_LICENSE_ISSUED_IN_FUTURE);
    fb_json_free(p);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(time_allows_iat_within_skew) {
    fb_json_value *p = parse_payload("{\"iat\":1010}");
    forgebit_verify_result *r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_time(p, 1000, 20, false, r), FORGEBIT_VALID);
    fb_json_free(p);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(time_rejects_exp_leq_iat) {
    /* now must be >= iat so the earlier issued-in-future check doesn't
     * pre-empt the exp<=iat malformed check being exercised here. */
    fb_json_value *p = parse_payload("{\"iat\":1000,\"exp\":1000}");
    forgebit_verify_result *r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_time(p, 1500, 0, false, r), FORGEBIT_MALFORMED_PAYLOAD);
    fb_json_free(p);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(time_rejects_nbf_geq_exp) {
    fb_json_value *p = parse_payload("{\"iat\":1000,\"nbf\":2000,\"exp\":2000}");
    forgebit_verify_result *r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_time(p, 1500, 0, false, r), FORGEBIT_MALFORMED_PAYLOAD);
    fb_json_free(p);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(time_rejects_not_yet_valid) {
    fb_json_value *p = parse_payload("{\"iat\":1000,\"nbf\":5000,\"exp\":6000}");
    forgebit_verify_result *r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_time(p, 2000, 0, false, r), FORGEBIT_LICENSE_NOT_YET_VALID);
    fb_json_free(p);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(time_expiration_boundary_is_inclusive) {
    forgebit_verify_result *r;

    fb_json_value *p1 = parse_payload("{\"iat\":1000,\"exp\":5000}");
    r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_time(p1, 5000, 0, false, r), FORGEBIT_LICENSE_EXPIRED);
    fb_json_free(p1);
    forgebit_verify_result_destroy(r);

    fb_json_value *p2 = parse_payload("{\"iat\":1000,\"exp\":5000}");
    r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_time(p2, 4999, 0, false, r), FORGEBIT_VALID);
    fb_json_free(p2);
    forgebit_verify_result_destroy(r);

    fb_json_value *p3 = parse_payload("{\"iat\":1000,\"exp\":5000}");
    r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_time(p3, 5001, 0, false, r), FORGEBIT_LICENSE_EXPIRED);
    fb_json_free(p3);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(time_requires_expiration_when_option_set) {
    fb_json_value *p = parse_payload("{\"iat\":1000}");
    forgebit_verify_result *r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_time(p, 2000, 0, true, r), FORGEBIT_EXPIRATION_REQUIRED);
    fb_json_free(p);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(time_warns_no_expiration_when_not_required) {
    fb_json_value *p = parse_payload("{\"iat\":1000}");
    forgebit_verify_result *r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_time(p, 2000, 0, false, r), FORGEBIT_VALID);
    FB_ASSERT_EQ_INT(forgebit_result_warning_count(r), 1);
    FB_ASSERT_EQ_INT(forgebit_result_warning_at(r, 0), FORGEBIT_WARNING_NO_EXPIRATION);
    fb_json_free(p);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(time_saturates_skew_near_int64_max) {
    /* now + skew would overflow; saturating upper is INT64_MAX so iat ==
     * INT64_MAX is still within the allowed window. */
    fb_json_value *p = parse_payload("{\"iat\":9223372036854775807}");
    forgebit_verify_result *r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_time(p, INT64_MAX - 10, 100, false, r), FORGEBIT_VALID);
    fb_json_free(p);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(time_saturates_skew_near_int64_min) {
    /* now - skew would underflow; saturating lower is INT64_MIN so an
     * exp just above INT64_MIN is not treated as expired. */
    fb_json_value *p = parse_payload("{\"iat\":-9223372036854775807,\"exp\":-9223372036854775806}");
    forgebit_verify_result *r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_time(p, INT64_MIN + 10, 100, false, r), FORGEBIT_VALID);
    fb_json_free(p);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(time_future_iat_still_rejected_with_skew) {
    /* Sanity: saturation helpers must not weaken ordinary skew checks. */
    fb_json_value *p = parse_payload("{\"iat\":2000}");
    forgebit_verify_result *r = fb_result_create();
    FB_ASSERT_EQ_INT(fb_claims_validate_time(p, 1000, 50, false, r), FORGEBIT_LICENSE_ISSUED_IN_FUTURE);
    fb_json_free(p);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(crit_absent_is_valid) {
    FB_ASSERT_EQ_INT(fb_header_validate_crit(NULL), FORGEBIT_VALID);
}

FB_TEST_CASE(crit_rejects_non_array) {
    fb_json_value *root = parse_payload("{\"crit\":\"b64\"}");
    FB_ASSERT_EQ_INT(fb_header_validate_crit(fb_json_object_find(root, "crit")), FORGEBIT_MALFORMED_HEADER);
    fb_json_free(root);
}

FB_TEST_CASE(crit_rejects_empty_array) {
    fb_json_value *root = parse_payload("{\"crit\":[]}");
    FB_ASSERT_EQ_INT(fb_header_validate_crit(fb_json_object_find(root, "crit")), FORGEBIT_MALFORMED_HEADER);
    fb_json_free(root);
}

FB_TEST_CASE(crit_rejects_unsupported_parameter) {
    fb_json_value *root = parse_payload("{\"crit\":[\"b64\"]}");
    FB_ASSERT_EQ_INT(fb_header_validate_crit(fb_json_object_find(root, "crit")), FORGEBIT_MALFORMED_HEADER);
    fb_json_free(root);
}

FB_TEST_CASE(crit_rejects_non_string_element) {
    fb_json_value *root = parse_payload("{\"crit\":[1]}");
    FB_ASSERT_EQ_INT(fb_header_validate_crit(fb_json_object_find(root, "crit")), FORGEBIT_MALFORMED_HEADER);
    fb_json_free(root);
}

FB_TEST_CASE(vendor_product_exact_match_required) {
    fb_json_value *p = parse_payload("{\"iss\":\"acme\",\"aud\":\"widget\"}");
    FB_ASSERT_EQ_INT(fb_claims_validate_vendor_product(p, "acme", "widget"), FORGEBIT_VALID);
    FB_ASSERT_EQ_INT(fb_claims_validate_vendor_product(p, "other", NULL), FORGEBIT_WRONG_VENDOR);
    FB_ASSERT_EQ_INT(fb_claims_validate_vendor_product(p, NULL, "other"), FORGEBIT_WRONG_PRODUCT);
    FB_ASSERT_EQ_INT(fb_claims_validate_vendor_product(p, NULL, NULL), FORGEBIT_VALID);
    fb_json_free(p);
}

int main(void) {
    printf("test_claims_time\n");
    FB_RUN_TEST(required_claims_accepts_minimal_valid_payload);
    FB_RUN_TEST(required_claims_rejects_missing_claim);
    FB_RUN_TEST(required_claims_rejects_wrong_type);
    FB_RUN_TEST(required_claims_rejects_float_iat);
    FB_RUN_TEST(required_claims_warns_on_unknown_claim);
    FB_RUN_TEST(time_rejects_issued_in_future);
    FB_RUN_TEST(time_allows_iat_within_skew);
    FB_RUN_TEST(time_rejects_exp_leq_iat);
    FB_RUN_TEST(time_rejects_nbf_geq_exp);
    FB_RUN_TEST(time_rejects_not_yet_valid);
    FB_RUN_TEST(time_expiration_boundary_is_inclusive);
    FB_RUN_TEST(time_requires_expiration_when_option_set);
    FB_RUN_TEST(time_warns_no_expiration_when_not_required);
    FB_RUN_TEST(time_saturates_skew_near_int64_max);
    FB_RUN_TEST(time_saturates_skew_near_int64_min);
    FB_RUN_TEST(time_future_iat_still_rejected_with_skew);
    FB_RUN_TEST(crit_absent_is_valid);
    FB_RUN_TEST(crit_rejects_non_array);
    FB_RUN_TEST(crit_rejects_empty_array);
    FB_RUN_TEST(crit_rejects_unsupported_parameter);
    FB_RUN_TEST(crit_rejects_non_string_element);
    FB_RUN_TEST(vendor_product_exact_match_required);
    FB_TEST_EXIT();
}
