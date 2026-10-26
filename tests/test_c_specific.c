/* C-specific coverage for invalid arguments, embedded NUL bytes, and
 * repeated create/destroy cycles. Run these under ASan to catch leaks and
 * use-after-free errors. */

#include "forgebit/forgebit.h"

#include <stdlib.h>
#include <string.h>

#include "sign_fixture.h"
#include "test_assert.h"

FB_TEST_CASE(null_result_out_param_is_invalid_call) {
    forgebit_verifier *v = forgebit_verifier_create();
    forgebit_status st = forgebit_verify(v, (const uint8_t *)"a.b.c", 5, NULL, NULL);
    FB_ASSERT_EQ_INT(st, FORGEBIT_STATUS_INVALID_CALL);
    forgebit_verifier_destroy(v);
}

FB_TEST_CASE(null_verifier_yields_invalid_argument_result) {
    forgebit_verify_result *r = NULL;
    forgebit_status st = forgebit_verify(NULL, (const uint8_t *)"a.b.c", 5, NULL, &r);
    FB_ASSERT_EQ_INT(st, FORGEBIT_STATUS_OK);
    FB_ASSERT_TRUE(r != NULL);
    FB_ASSERT_FALSE(forgebit_result_is_valid(r));
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_INVALID_ARGUMENT);
    forgebit_verify_result_destroy(r);
}

FB_TEST_CASE(null_license_with_zero_length_is_malformed_not_crash) {
    forgebit_verifier *v = forgebit_verifier_create();
    forgebit_verify_result *r = NULL;
    forgebit_status st = forgebit_verify(v, NULL, 0, NULL, &r);
    FB_ASSERT_EQ_INT(st, FORGEBIT_STATUS_OK);
    FB_ASSERT_FALSE(forgebit_result_is_valid(r));
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_MALFORMED_LICENSE);
    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
}

FB_TEST_CASE(null_license_with_nonzero_length_is_invalid_argument) {
    forgebit_verifier *v = forgebit_verifier_create();
    forgebit_verify_result *r = NULL;
    forgebit_status st = forgebit_verify(v, NULL, 10, NULL, &r);
    FB_ASSERT_EQ_INT(st, FORGEBIT_STATUS_OK);
    FB_ASSERT_FALSE(forgebit_result_is_valid(r));
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_INVALID_ARGUMENT);
    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
}

FB_TEST_CASE(null_options_uses_defaults) {
    forgebit_verifier *v = forgebit_verifier_create();
    forgebit_verify_result *r = NULL;
    forgebit_status st = forgebit_verify(v, (const uint8_t *)"a.b.c", 5, NULL, &r);
    FB_ASSERT_EQ_INT(st, FORGEBIT_STATUS_OK);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_MALFORMED_LICENSE);
    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
}

FB_TEST_CASE(embedded_nul_in_payload_string_survives_round_trip) {
    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);

    forgebit_verifier *v = forgebit_verifier_create();
    forgebit_public_key pk = FORGEBIT_PUBLIC_KEY_INIT;
    memcpy(pk.bytes, kp.pk, 32);
    forgebit_verifier_add_key(v, "key_01", &pk);

    /* \0 escape decodes to a real NUL byte inside the "jti" string;
     * the JSON layer stores strings as {ptr,len}, not NUL-terminated
     * C strings, so this must round-trip correctly rather than
     * silently truncating. */
    const char *payload = "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":"
                          "\"ab\\u0000cd\",\"iat\":1000,\"exp\":9999999999,"
                          "\"offline\":true,\"features\":{}}";
    char *license = fbtest_sign_compact_default_header(&kp, "key_01", payload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_TRUE(forgebit_result_is_valid(r));

    const forgebit_json_value *claims = forgebit_result_claims(r);
    const forgebit_json_value *jti = forgebit_json_object_get(claims, "jti");
    const char *jti_bytes = NULL;
    size_t jti_len = 0;
    FB_ASSERT_TRUE(forgebit_json_get_string(jti, &jti_bytes, &jti_len));
    FB_ASSERT_EQ_INT(jti_len, 5);
    FB_ASSERT_TRUE(memcmp(jti_bytes, "ab\0cd", 5) == 0);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

FB_TEST_CASE(repeated_create_destroy_cycles) {
    uint8_t seed[32];
    memset(seed, 0x99, sizeof(seed));
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);

    const char *payload = "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-loop\","
                          "\"iat\":1000,\"exp\":9999999999,"
                          "\"offline\":true,\"features\":{\"a\":1}}";
    char *license = fbtest_sign_compact_default_header(&kp, "key_01", payload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.has_current_time = true;
    opts.current_time = 2000;

    for (int i = 0; i < 1000; i++) {
        forgebit_verifier *v = forgebit_verifier_create();
        forgebit_public_key pk = FORGEBIT_PUBLIC_KEY_INIT;
        memcpy(pk.bytes, kp.pk, 32);
        forgebit_verifier_add_key(v, "key_01", &pk);

        forgebit_verify_result *r = NULL;
        forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
        if (i == 0) {
            FB_ASSERT_TRUE(forgebit_result_is_valid(r));
        }
        forgebit_verify_result_destroy(r);
        forgebit_verifier_destroy(v);
    }

    free(license);
}

int main(void) {
    printf("test_c_specific\n");
    FB_RUN_TEST(null_result_out_param_is_invalid_call);
    FB_RUN_TEST(null_verifier_yields_invalid_argument_result);
    FB_RUN_TEST(null_license_with_zero_length_is_malformed_not_crash);
    FB_RUN_TEST(null_license_with_nonzero_length_is_invalid_argument);
    FB_RUN_TEST(null_options_uses_defaults);
    FB_RUN_TEST(embedded_nul_in_payload_string_survives_round_trip);
    FB_RUN_TEST(repeated_create_destroy_cycles);
    FB_TEST_EXIT();
}
