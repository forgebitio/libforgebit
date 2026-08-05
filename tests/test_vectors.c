/* Required protocol test vectors from section 19. */

#include "forgebit/forgebit.h"

#include <stdlib.h>
#include <string.h>

#include "base64url.h"
#include "sign_fixture.h"
#include "test_assert.h"

/* Shared helpers */

static void seed_fill(uint8_t seed[32], uint8_t fill) {
    memset(seed, fill, 32);
}

static forgebit_verifier *verifier_with_key(const fb_test_keypair *kp, const char *kid) {
    forgebit_verifier *v = forgebit_verifier_create();
    forgebit_public_key pk = FORGEBIT_PUBLIC_KEY_INIT;
    memcpy(pk.bytes, kp->pk, 32);
    forgebit_verifier_add_key(v, kid, &pk);
    return v;
}

static char *b64_of(const char *s) {
    char *out = NULL;
    size_t out_len = 0;
    fb_base64url_encode((const uint8_t *)s, strlen(s), &out, &out_len);
    return out;
}

static char *join3(const char *a, const char *b, const char *c) {
    size_t la = strlen(a), lb = strlen(b), lc = strlen(c);
    char *out = (char *)malloc(la + 1 + lb + 1 + lc + 1);
    memcpy(out, a, la);
    out[la] = '.';
    memcpy(out + la + 1, b, lb);
    out[la + 1 + lb] = '.';
    memcpy(out + la + 1 + lb + 1, c, lc);
    out[la + 1 + lb + 1 + lc] = '\0';
    return out;
}

#define DEFAULT_KID    "key_01"
#define DEFAULT_HEADER "{\"alg\":\"EdDSA\",\"kid\":\"" DEFAULT_KID "\",\"typ\":\"JWT\"}"

/* 1. Valid license */

FB_TEST_CASE(v01_valid_license) {
    uint8_t seed[32];
    seed_fill(seed, 0x01);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *payload = "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-1\","
                          "\"iat\":1000,\"exp\":9999999999,"
                          "\"offline\":true,\"features\":{\"seats\":5}}";
    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    FB_ASSERT_EQ_INT(forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r), FORGEBIT_STATUS_OK);
    FB_ASSERT_TRUE(forgebit_result_is_valid(r));
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_VALID);
    FB_ASSERT_STR_EQ(forgebit_result_vendor(r), "acme");
    FB_ASSERT_STR_EQ(forgebit_result_product(r), "widget");
    FB_ASSERT_STR_EQ(forgebit_result_license_id(r), "lic-1");

    const forgebit_json_value *features = forgebit_result_features(r);
    FB_ASSERT_TRUE(features != NULL);
    const forgebit_json_value *seats = forgebit_json_object_get(features, "seats");
    int64_t seats_val = 0;
    FB_ASSERT_TRUE(forgebit_json_get_integer(seats, &seats_val));
    FB_ASSERT_EQ_INT(seats_val, 5);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

/* 2. Valid non-expiring license */

FB_TEST_CASE(v02_valid_non_expiring) {
    uint8_t seed[32];
    seed_fill(seed, 0x02);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *payload =
        "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-2\",\"iat\":1000,"
        "\"offline\":true,\"features\":{}}";
    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_TRUE(forgebit_result_is_valid(r));
    FB_ASSERT_EQ_INT(forgebit_result_warning_count(r), 1);
    FB_ASSERT_EQ_INT(forgebit_result_warning_at(r, 0), FORGEBIT_WARNING_NO_EXPIRATION);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

/* 3. Valid license with nested features */

FB_TEST_CASE(v03_valid_nested_features) {
    uint8_t seed[32];
    seed_fill(seed, 0x03);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *payload =
        "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-3\",\"iat\":1000,\"exp\":"
        "9999999999,"
        "\"offline\":true,\"features\":{\"limits\":{\"max_users\":10,\"tiers\":[\"a\",\"b\"]}}}";
    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_TRUE(forgebit_result_is_valid(r));

    const forgebit_json_value *features = forgebit_result_features(r);
    const forgebit_json_value *limits = forgebit_json_object_get(features, "limits");
    FB_ASSERT_EQ_INT(forgebit_json_type_of(limits), FORGEBIT_JSON_OBJECT);
    const forgebit_json_value *tiers = forgebit_json_object_get(limits, "tiers");
    FB_ASSERT_EQ_INT(forgebit_json_type_of(tiers), FORGEBIT_JSON_ARRAY);
    FB_ASSERT_EQ_INT(forgebit_json_array_length(tiers), 2);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

/* 4. Valid license signed by an older trusted rotation key */

FB_TEST_CASE(v04_valid_rotation_key) {
    uint8_t seed_old[32], seed_new[32];
    seed_fill(seed_old, 0x04);
    seed_fill(seed_new, 0x14);
    fb_test_keypair kp_old, kp_new;
    fbtest_keypair_from_seed(&kp_old, seed_old);
    fbtest_keypair_from_seed(&kp_new, seed_new);

    forgebit_verifier *v = forgebit_verifier_create();
    forgebit_public_key pk_old = FORGEBIT_PUBLIC_KEY_INIT;
    memcpy(pk_old.bytes, kp_old.pk, 32);
    forgebit_public_key pk_new = FORGEBIT_PUBLIC_KEY_INIT;
    memcpy(pk_new.bytes, kp_new.pk, 32);
    forgebit_verifier_add_key(v, "key_old", &pk_old);
    forgebit_verifier_add_key(v, "key_new", &pk_new);

    const char *payload = "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-4\","
                          "\"iat\":1000,\"exp\":9999999999,"
                          "\"offline\":true,\"features\":{}}";
    char *license = fbtest_sign_compact_default_header(&kp_old, "key_old", payload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_TRUE(forgebit_result_is_valid(r));
    FB_ASSERT_STR_EQ(forgebit_result_key_id(r), "key_old");

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

/* 5-7. Tampered header, payload, and signature */

static const char *kTamperPayload = "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":"
                                    "\"lic-tamper\",\"iat\":1000,\"exp\":9999999999,"
                                    "\"offline\":true,\"features\":{}}";

FB_TEST_CASE(v05_tampered_header) {
    uint8_t seed[32];
    seed_fill(seed, 0x05);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    char *h1b64 = b64_of(DEFAULT_HEADER);
    const char *h2_text =
        "{\"alg\":\"EdDSA\",\"kid\":\"" DEFAULT_KID "\",\"typ\":\"FORGEBIT-LICENSE\"}";
    char *h2b64 = b64_of(h2_text);
    char *pb64 = b64_of(kTamperPayload);

    char signing_input[1024];
    int n = snprintf(signing_input, sizeof(signing_input), "%s.%s", h1b64, pb64);
    uint8_t sig[64];
    fbtest_sign_raw(&kp, (const uint8_t *)signing_input, (size_t)n, sig);
    char *sigb64 = NULL;
    size_t sigb64_len = 0;
    fb_base64url_encode(sig, sizeof(sig), &sigb64, &sigb64_len);

    char *license = join3(h2b64, pb64, sigb64); /* signature was over h1, not h2 */

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_FALSE(forgebit_result_is_valid(r));
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_INVALID_SIGNATURE);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(h1b64);
    free(h2b64);
    free(pb64);
    free(sigb64);
    free(license);
}

FB_TEST_CASE(v06_tampered_payload) {
    uint8_t seed[32];
    seed_fill(seed, 0x06);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    char *hb64 = b64_of(DEFAULT_HEADER);
    char *p1b64 = b64_of(kTamperPayload);
    const char *p2_text = "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-tamper-"
                          "2\",\"iat\":1000,\"exp\":9999999999,"
                          "\"offline\":true,\"features\":{}}";
    char *p2b64 = b64_of(p2_text);

    char signing_input[1024];
    int n = snprintf(signing_input, sizeof(signing_input), "%s.%s", hb64, p1b64);
    uint8_t sig[64];
    fbtest_sign_raw(&kp, (const uint8_t *)signing_input, (size_t)n, sig);
    char *sigb64 = NULL;
    size_t sigb64_len = 0;
    fb_base64url_encode(sig, sizeof(sig), &sigb64, &sigb64_len);

    char *license = join3(hb64, p2b64, sigb64); /* signature was over p1, not p2 */

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_FALSE(forgebit_result_is_valid(r));
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_INVALID_SIGNATURE);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(hb64);
    free(p1b64);
    free(p2b64);
    free(sigb64);
    free(license);
}

FB_TEST_CASE(v07_tampered_signature) {
    uint8_t seed[32];
    seed_fill(seed, 0x07);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, kTamperPayload);

    /* Flip one base64url-alphabet character within the signature segment. */
    char *last_dot = strrchr(license, '.');
    FB_ASSERT_TRUE(last_dot != NULL);
    char *sig_start = last_dot + 1;
    sig_start[0] = (sig_start[0] == 'A') ? 'B' : 'A';

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_FALSE(forgebit_result_is_valid(r));
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_INVALID_SIGNATURE);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

/* 8. Unknown kid */

FB_TEST_CASE(v08_unknown_kid) {
    uint8_t seed[32];
    seed_fill(seed, 0x08);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    char *license = fbtest_sign_compact_default_header(&kp, "key_does_not_exist", kTamperPayload);

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), NULL, &r);
    FB_ASSERT_FALSE(forgebit_result_is_valid(r));
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_UNKNOWN_KEY);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

/* 9. Malformed public key */

FB_TEST_CASE(v09_malformed_public_key) {
    forgebit_verifier *v = forgebit_verifier_create();
    FB_ASSERT_EQ_INT(forgebit_verifier_add_key_base64url(v, "k1", "not-valid-base64url!!"), FORGEBIT_STATUS_INVALID_PUBLIC_KEY);
    FB_ASSERT_EQ_INT(forgebit_verifier_add_key_base64url(v, "k1", "aGVsbG8"), FORGEBIT_STATUS_INVALID_PUBLIC_KEY); /* wrong length */
    forgebit_verifier_destroy(v);
}

/* 10-11. Wrong vendor and product */

FB_TEST_CASE(v10_wrong_vendor) {
    uint8_t seed[32];
    seed_fill(seed, 0x0A);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);
    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, kTamperPayload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.expected_vendor = "not-acme";
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_WRONG_VENDOR);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

FB_TEST_CASE(v11_wrong_product) {
    uint8_t seed[32];
    seed_fill(seed, 0x0B);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);
    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, kTamperPayload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.expected_product = "not-widget";
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_WRONG_PRODUCT);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

/* 12-14. Expired, not yet valid, and issued in the future */

FB_TEST_CASE(v12_expired) {
    uint8_t seed[32];
    seed_fill(seed, 0x0C);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *payload = "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-12\","
                          "\"iat\":1000,\"exp\":5000,"
                          "\"offline\":true,\"features\":{}}";
    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.has_current_time = true;
    opts.current_time = 6000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_LICENSE_EXPIRED);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

FB_TEST_CASE(v13_not_yet_valid) {
    uint8_t seed[32];
    seed_fill(seed, 0x0D);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *payload = "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-13\","
                          "\"iat\":1000,\"nbf\":5000,\"exp\":9999999999,"
                          "\"offline\":true,\"features\":{}}";
    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_LICENSE_NOT_YET_VALID);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

FB_TEST_CASE(v14_issued_in_future) {
    uint8_t seed[32];
    seed_fill(seed, 0x0E);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *payload = "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-14\","
                          "\"iat\":9000,\"exp\":9999999999,"
                          "\"offline\":true,\"features\":{}}";
    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_LICENSE_ISSUED_IN_FUTURE);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

/* 15-16. Missing required claim and wrong claim type */

FB_TEST_CASE(v15_missing_required_claim) {
    uint8_t seed[32];
    seed_fill(seed, 0x0F);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *payload =
        "{\"fbt_ver\":1,\"iss\":\"acme\",\"jti\":\"lic-15\",\"iat\":1000,\"exp\":9999999999,"
        "\"offline\":true,\"features\":{}}"; /* missing "aud" */
    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), NULL, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_MALFORMED_PAYLOAD);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

FB_TEST_CASE(v16_wrong_claim_type) {
    uint8_t seed[32];
    seed_fill(seed, 0x10);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *payload = "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-16\","
                          "\"iat\":\"not-a-number\",\"exp\":9999999999,"
                          "\"offline\":true,\"features\":{}}";
    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), NULL, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_MALFORMED_PAYLOAD);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

/* 17-18. Unsupported protocol version and algorithm */

FB_TEST_CASE(v17_unsupported_version) {
    uint8_t seed[32];
    seed_fill(seed, 0x11);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *payload = "{\"fbt_ver\":2,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-17\","
                          "\"iat\":1000,\"exp\":9999999999,"
                          "\"offline\":true,\"features\":{}}";
    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), NULL, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_UNSUPPORTED_VERSION);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

FB_TEST_CASE(v18_unsupported_algorithm) {
    uint8_t seed[32];
    seed_fill(seed, 0x12);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *header = "{\"alg\":\"HS256\",\"kid\":\"" DEFAULT_KID "\",\"typ\":\"JWT\"}";
    char *license = fbtest_sign_compact(&kp, header, kTamperPayload);

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), NULL, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_UNSUPPORTED_ALGORITHM);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

/* 19. Offline verification disabled */

FB_TEST_CASE(v19_offline_false) {
    uint8_t seed[32];
    seed_fill(seed, 0x13);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *payload = "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-19\","
                          "\"iat\":1000,\"exp\":9999999999,"
                          "\"offline\":false,\"features\":{}}";
    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), NULL, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_OFFLINE_NOT_ALLOWED);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

/* 20. Required expiration missing */

FB_TEST_CASE(v20_expiration_required_missing) {
    uint8_t seed[32];
    seed_fill(seed, 0x15);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *payload =
        "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-20\",\"iat\":1000,"
        "\"offline\":true,\"features\":{}}";
    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.require_expiration = true;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_EXPIRATION_REQUIRED);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

/* 21-23. Hardware ID match, missing, and mismatch */

static char *build_hwid_license(const fb_test_keypair *kp) {
    const char *payload = "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-hwid\","
                          "\"iat\":1000,\"exp\":9999999999,"
                          "\"offline\":true,\"features\":{},\"hwid\":\"machine-1\"}";
    return fbtest_sign_compact_default_header(kp, DEFAULT_KID, payload);
}

FB_TEST_CASE(v21_hwid_match) {
    uint8_t seed[32];
    seed_fill(seed, 0x16);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);
    char *license = build_hwid_license(&kp);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.hardware_id = "machine-1";
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_TRUE(forgebit_result_is_valid(r));

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

FB_TEST_CASE(v22_hwid_missing) {
    uint8_t seed[32];
    seed_fill(seed, 0x17);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);
    char *license = build_hwid_license(&kp);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_HARDWARE_ID_REQUIRED);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

FB_TEST_CASE(v23_hwid_mismatch) {
    uint8_t seed[32];
    seed_fill(seed, 0x18);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);
    char *license = build_hwid_license(&kp);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.hardware_id = "machine-2";
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_HARDWARE_MISMATCH);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

/* 24. Malformed base64url */

FB_TEST_CASE(v24_malformed_base64url) {
    uint8_t seed[32];
    seed_fill(seed, 0x19);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *invalid_char = "abc!def.cGF5bG9hZA.c2ln";
    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)invalid_char, strlen(invalid_char), NULL, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_MALFORMED_LICENSE);
    forgebit_verify_result_destroy(r);

    const char *with_padding = "aGVhZGVy=.cGF5bG9hZA.c2ln";
    r = NULL;
    forgebit_verify(v, (const uint8_t *)with_padding, strlen(with_padding), NULL, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_MALFORMED_LICENSE);
    forgebit_verify_result_destroy(r);

    forgebit_verifier_destroy(v);
}

/* 25. Oversized input */

FB_TEST_CASE(v25_oversized_input) {
    uint8_t seed[32];
    seed_fill(seed, 0x1A);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    size_t pad_len = 1000000;
    size_t headroom = 300;
    char *payload = (char *)malloc(pad_len + headroom);
    int n = snprintf(
        payload,
        headroom,
        "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-25\",\"iat\":1000,"
        "\"exp\":9999999999,"
        "\"offline\":true,\"features\":{},\"metadata\":{\"note\":\""
    );
    memset(payload + n, 'x', pad_len);
    snprintf(payload + n + (int)pad_len, headroom - (size_t)n, "\"}}");

    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);
    FB_ASSERT_TRUE(strlen(license) > 1024 * 1024);

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), NULL, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_MALFORMED_LICENSE);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
    free(payload);
}

/* 26. Duplicate JSON keys */

FB_TEST_CASE(v26_duplicate_json_keys) {
    uint8_t seed[32];
    seed_fill(seed, 0x1B);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *dup_payload = "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-"
                              "26\",\"iat\":1000,\"iat\":1000,\"exp\":9999999999,"
                              "\"offline\":true,\"features\":{}}";
    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, dup_payload);

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), NULL, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_MALFORMED_PAYLOAD);
    forgebit_verify_result_destroy(r);
    free(license);

    const char *dup_header =
        "{\"alg\":\"EdDSA\",\"alg\":\"EdDSA\",\"kid\":\"" DEFAULT_KID "\",\"typ\":\"JWT\"}";
    char *license2 = fbtest_sign_compact(&kp, dup_header, kTamperPayload);
    r = NULL;
    forgebit_verify(v, (const uint8_t *)license2, strlen(license2), NULL, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_MALFORMED_HEADER);
    forgebit_verify_result_destroy(r);
    free(license2);

    forgebit_verifier_destroy(v);
}

/* 27-29. Unknown claims and permissive/strict typ handling */

FB_TEST_CASE(v27_unrecognized_claims) {
    uint8_t seed[32];
    seed_fill(seed, 0x1C);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *payload = "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-27\","
                          "\"iat\":1000,\"exp\":9999999999,"
                          "\"offline\":true,\"features\":{},\"custom_field\":true}";
    char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_TRUE(forgebit_result_is_valid(r));
    FB_ASSERT_EQ_INT(forgebit_result_warning_count(r), 1);
    FB_ASSERT_EQ_INT(forgebit_result_warning_at(r, 0), FORGEBIT_WARNING_UNRECOGNIZED_CLAIMS);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

FB_TEST_CASE(v28_unknown_typ_permissive) {
    uint8_t seed[32];
    seed_fill(seed, 0x1D);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *header = "{\"alg\":\"EdDSA\",\"kid\":\"" DEFAULT_KID "\",\"typ\":\"CUSTOM-TYPE\"}";
    char *license = fbtest_sign_compact(&kp, header, kTamperPayload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.strict_type = false;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_TRUE(forgebit_result_is_valid(r));
    FB_ASSERT_EQ_INT(forgebit_result_warning_count(r), 1);
    FB_ASSERT_EQ_INT(forgebit_result_warning_at(r, 0), FORGEBIT_WARNING_UNKNOWN_TYPE);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

FB_TEST_CASE(v29_unknown_typ_strict) {
    uint8_t seed[32];
    seed_fill(seed, 0x1E);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *header = "{\"alg\":\"EdDSA\",\"kid\":\"" DEFAULT_KID "\",\"typ\":\"CUSTOM-TYPE\"}";
    char *license = fbtest_sign_compact(&kp, header, kTamperPayload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.strict_type = true;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_UNSUPPORTED_TYPE);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

/* 30. Exact expiration-boundary behavior */

FB_TEST_CASE(v30_expiration_boundary) {
    uint8_t seed[32];
    seed_fill(seed, 0x1F);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const int64_t now = 2000000;

    /* exp == now -> expired */
    {
        char payload[256];
        snprintf(
            payload,
            sizeof(payload),
            "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-30a\",\"iat\":1000,"
            "\"exp\":%lld,"
            "\"offline\":true,\"features\":{}}",
            (long long)now
        );
        char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);
        forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
        opts.has_current_time = true;
        opts.current_time = now;
        forgebit_verify_result *r = NULL;
        forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
        FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_LICENSE_EXPIRED);
        forgebit_verify_result_destroy(r);
        free(license);
    }

    /* exp == now - 1 -> expired */
    {
        char payload[256];
        snprintf(
            payload,
            sizeof(payload),
            "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-30b\",\"iat\":1000,"
            "\"exp\":%lld,"
            "\"offline\":true,\"features\":{}}",
            (long long)(now - 1)
        );
        char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);
        forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
        opts.has_current_time = true;
        opts.current_time = now;
        forgebit_verify_result *r = NULL;
        forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
        FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_LICENSE_EXPIRED);
        forgebit_verify_result_destroy(r);
        free(license);
    }

    /* exp == now + 1 -> valid */
    {
        char payload[256];
        snprintf(
            payload,
            sizeof(payload),
            "{\"fbt_ver\":1,\"iss\":\"acme\",\"aud\":\"widget\",\"jti\":\"lic-30c\",\"iat\":1000,"
            "\"exp\":%lld,"
            "\"offline\":true,\"features\":{}}",
            (long long)(now + 1)
        );
        char *license = fbtest_sign_compact_default_header(&kp, DEFAULT_KID, payload);
        forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
        opts.has_current_time = true;
        opts.current_time = now;
        forgebit_verify_result *r = NULL;
        forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
        FB_ASSERT_TRUE(forgebit_result_is_valid(r));
        forgebit_verify_result_destroy(r);
        free(license);
    }

    forgebit_verifier_destroy(v);
}

/* Unsupported critical JWS header parameters */

FB_TEST_CASE(v31_crit_unsupported) {
    uint8_t seed[32];
    seed_fill(seed, 0x20);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *header = "{\"alg\":\"EdDSA\",\"kid\":\"" DEFAULT_KID
                         "\",\"typ\":\"JWT\",\"crit\":[\"b64\"],\"b64\":false}";
    char *license = fbtest_sign_compact(&kp, header, kTamperPayload);

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    opts.has_current_time = true;
    opts.current_time = 2000;

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), &opts, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_MALFORMED_HEADER);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

FB_TEST_CASE(v32_crit_empty_array) {
    uint8_t seed[32];
    seed_fill(seed, 0x21);
    fb_test_keypair kp;
    fbtest_keypair_from_seed(&kp, seed);
    forgebit_verifier *v = verifier_with_key(&kp, DEFAULT_KID);

    const char *header =
        "{\"alg\":\"EdDSA\",\"kid\":\"" DEFAULT_KID "\",\"typ\":\"JWT\",\"crit\":[]}";
    char *license = fbtest_sign_compact(&kp, header, kTamperPayload);

    forgebit_verify_result *r = NULL;
    forgebit_verify(v, (const uint8_t *)license, strlen(license), NULL, &r);
    FB_ASSERT_EQ_INT(forgebit_result_code_get(r), FORGEBIT_MALFORMED_HEADER);

    forgebit_verify_result_destroy(r);
    forgebit_verifier_destroy(v);
    free(license);
}

int main(void) {
    printf("test_vectors\n");
    FB_RUN_TEST(v01_valid_license);
    FB_RUN_TEST(v02_valid_non_expiring);
    FB_RUN_TEST(v03_valid_nested_features);
    FB_RUN_TEST(v04_valid_rotation_key);
    FB_RUN_TEST(v05_tampered_header);
    FB_RUN_TEST(v06_tampered_payload);
    FB_RUN_TEST(v07_tampered_signature);
    FB_RUN_TEST(v08_unknown_kid);
    FB_RUN_TEST(v09_malformed_public_key);
    FB_RUN_TEST(v10_wrong_vendor);
    FB_RUN_TEST(v11_wrong_product);
    FB_RUN_TEST(v12_expired);
    FB_RUN_TEST(v13_not_yet_valid);
    FB_RUN_TEST(v14_issued_in_future);
    FB_RUN_TEST(v15_missing_required_claim);
    FB_RUN_TEST(v16_wrong_claim_type);
    FB_RUN_TEST(v17_unsupported_version);
    FB_RUN_TEST(v18_unsupported_algorithm);
    FB_RUN_TEST(v19_offline_false);
    FB_RUN_TEST(v20_expiration_required_missing);
    FB_RUN_TEST(v21_hwid_match);
    FB_RUN_TEST(v22_hwid_missing);
    FB_RUN_TEST(v23_hwid_mismatch);
    FB_RUN_TEST(v24_malformed_base64url);
    FB_RUN_TEST(v25_oversized_input);
    FB_RUN_TEST(v26_duplicate_json_keys);
    FB_RUN_TEST(v27_unrecognized_claims);
    FB_RUN_TEST(v28_unknown_typ_permissive);
    FB_RUN_TEST(v29_unknown_typ_strict);
    FB_RUN_TEST(v30_expiration_boundary);
    FB_RUN_TEST(v31_crit_unsupported);
    FB_RUN_TEST(v32_crit_empty_array);
    FB_TEST_EXIT();
}
