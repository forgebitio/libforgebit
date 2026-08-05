#include "claims.h"

#include <stdint.h>
#include <string.h>

/* Saturating now ± skew so extreme current_time / clock_skew_seconds
 * pairs never invoke signed int64 overflow (undefined behavior). */
static int64_t saturating_add_skew(int64_t now, uint32_t skew) {
    int64_t skew64 = (int64_t)skew;
    if (now > INT64_MAX - skew64) return INT64_MAX;
    return now + skew64;
}

static int64_t saturating_sub_skew(int64_t now, uint32_t skew) {
    int64_t skew64 = (int64_t)skew;
    if (now < INT64_MIN + skew64) return INT64_MIN;
    return now - skew64;
}

static bool str_eq(const fb_json_value *v, const char *literal) {
    if (!fb_json_is_string(v)) return false;
    size_t len = strlen(literal);
    return v->as.str.len == len && memcmp(v->as.str.ptr, literal, len) == 0;
}

static bool is_nonempty_string(const fb_json_value *v) {
    return fb_json_is_string(v) && v->as.str.len > 0;
}

static bool is_array_of_nonempty_strings(const fb_json_value *v) {
    if (!fb_json_is_array(v)) return false;
    for (size_t i = 0; i < v->as.arr.count; i++) {
        if (!is_nonempty_string(v->as.arr.items[i])) return false;
    }
    return true;
}

static const char *const kKnownPayloadKeys[] = { "fbt_ver",     "iss",      "aud",      "jti",
                                                 "iat",         "offline",  "features", "nbf",
                                                 "exp",         "licensee", "hwid",     "metadata",
                                                 "entitlements" };
static const size_t kKnownPayloadKeyCount =
    sizeof(kKnownPayloadKeys) / sizeof(kKnownPayloadKeys[0]);

static bool is_known_payload_key(const char *key, size_t len) {
    for (size_t i = 0; i < kKnownPayloadKeyCount; i++) {
        size_t klen = strlen(kKnownPayloadKeys[i]);
        if (klen == len && memcmp(kKnownPayloadKeys[i], key, len) == 0) return true;
    }
    return false;
}

forgebit_result_code fb_claims_validate_required(
    const fb_json_value *payload,
    forgebit_verify_result *result
) {
    if (!fb_json_is_object(payload)) return FORGEBIT_MALFORMED_PAYLOAD;

    const fb_json_value *fbt_ver = fb_json_object_find(payload, "fbt_ver");
    if (!fb_json_is_int(fbt_ver)) return FORGEBIT_MALFORMED_PAYLOAD;

    if (!is_nonempty_string(fb_json_object_find(payload, "iss"))) return FORGEBIT_MALFORMED_PAYLOAD;
    if (!is_nonempty_string(fb_json_object_find(payload, "aud"))) return FORGEBIT_MALFORMED_PAYLOAD;
    if (!is_nonempty_string(fb_json_object_find(payload, "jti"))) return FORGEBIT_MALFORMED_PAYLOAD;

    if (!fb_json_is_int(fb_json_object_find(payload, "iat"))) return FORGEBIT_MALFORMED_PAYLOAD;

    const fb_json_value *offline = fb_json_object_find(payload, "offline");
    if (!fb_json_is_bool(offline)) return FORGEBIT_MALFORMED_PAYLOAD;

    const fb_json_value *features = fb_json_object_find(payload, "features");
    if (!fb_json_is_object(features)) return FORGEBIT_MALFORMED_PAYLOAD;

    const fb_json_value *nbf = fb_json_object_find(payload, "nbf");
    if (nbf != NULL && !fb_json_is_int(nbf)) return FORGEBIT_MALFORMED_PAYLOAD;

    const fb_json_value *exp = fb_json_object_find(payload, "exp");
    if (exp != NULL && !fb_json_is_int(exp)) return FORGEBIT_MALFORMED_PAYLOAD;

    const fb_json_value *licensee = fb_json_object_find(payload, "licensee");
    if (licensee != NULL && !fb_json_is_object(licensee)) return FORGEBIT_MALFORMED_PAYLOAD;

    const fb_json_value *hwid = fb_json_object_find(payload, "hwid");
    if (hwid != NULL && !is_nonempty_string(hwid) && !is_array_of_nonempty_strings(hwid)) {
        return FORGEBIT_MALFORMED_PAYLOAD;
    }

    const fb_json_value *metadata = fb_json_object_find(payload, "metadata");
    if (metadata != NULL && !fb_json_is_object(metadata)) return FORGEBIT_MALFORMED_PAYLOAD;

    const fb_json_value *entitlements = fb_json_object_find(payload, "entitlements");
    if (entitlements != NULL && !fb_json_is_array(entitlements)) return FORGEBIT_MALFORMED_PAYLOAD;

    for (size_t i = 0; i < payload->as.obj.count; i++) {
        if (!is_known_payload_key(payload->as.obj.keys[i], payload->as.obj.key_lens[i])) {
            fb_result_add_warning(result, FORGEBIT_WARNING_UNRECOGNIZED_CLAIMS);
            break;
        }
    }

    return FORGEBIT_VALID;
}

forgebit_result_code fb_claims_validate_version(const fb_json_value *payload) {
    const fb_json_value *v = fb_json_object_find(payload, "fbt_ver");
    if (!fb_json_is_int(v) || v->as.i != FORGEBIT_PROTOCOL_VERSION)
        return FORGEBIT_UNSUPPORTED_VERSION;
    return FORGEBIT_VALID;
}

forgebit_result_code fb_claims_validate_offline(const fb_json_value *payload) {
    const fb_json_value *v = fb_json_object_find(payload, "offline");
    if (!fb_json_is_bool(v) || v->as.b != true) return FORGEBIT_OFFLINE_NOT_ALLOWED;
    return FORGEBIT_VALID;
}

forgebit_result_code fb_claims_validate_vendor_product(
    const fb_json_value *payload,
    const char *expected_vendor,
    const char *expected_product
) {
    if (expected_vendor != NULL) {
        const fb_json_value *iss = fb_json_object_find(payload, "iss");
        if (!str_eq(iss, expected_vendor)) return FORGEBIT_WRONG_VENDOR;
    }
    if (expected_product != NULL) {
        const fb_json_value *aud = fb_json_object_find(payload, "aud");
        if (!str_eq(aud, expected_product)) return FORGEBIT_WRONG_PRODUCT;
    }
    return FORGEBIT_VALID;
}

forgebit_result_code fb_claims_validate_time(
    const fb_json_value *payload,
    int64_t now,
    uint32_t skew,
    bool require_expiration,
    forgebit_verify_result *result
) {
    const fb_json_value *iat_v = fb_json_object_find(payload, "iat");
    const fb_json_value *nbf_v = fb_json_object_find(payload, "nbf");
    const fb_json_value *exp_v = fb_json_object_find(payload, "exp");

    int64_t iat = iat_v->as.i;
    bool has_nbf = nbf_v != NULL;
    bool has_exp = exp_v != NULL;
    int64_t nbf = has_nbf ? nbf_v->as.i : 0;
    int64_t exp = has_exp ? exp_v->as.i : 0;

    int64_t upper = saturating_add_skew(now, skew);
    int64_t lower = saturating_sub_skew(now, skew);

    if (iat > upper) return FORGEBIT_LICENSE_ISSUED_IN_FUTURE;

    if (has_exp && exp <= iat) return FORGEBIT_MALFORMED_PAYLOAD;

    if (has_nbf && has_exp && nbf >= exp) return FORGEBIT_MALFORMED_PAYLOAD;

    if (has_nbf && nbf > upper) return FORGEBIT_LICENSE_NOT_YET_VALID;

    if (has_exp && exp <= lower) return FORGEBIT_LICENSE_EXPIRED;

    if (!has_exp) {
        if (require_expiration) return FORGEBIT_EXPIRATION_REQUIRED;
        fb_result_add_warning(result, FORGEBIT_WARNING_NO_EXPIRATION);
    }

    return FORGEBIT_VALID;
}

forgebit_result_code fb_claims_validate_hardware(
    const fb_json_value *payload,
    const char *hardware_id
) {
    const fb_json_value *hwid = fb_json_object_find(payload, "hwid");
    if (hwid == NULL) return FORGEBIT_VALID;

    if (hardware_id == NULL) return FORGEBIT_HARDWARE_ID_REQUIRED;

    size_t hwid_len = strlen(hardware_id);

    if (fb_json_is_string(hwid)) {
        if (hwid->as.str.len == hwid_len && memcmp(hwid->as.str.ptr, hardware_id, hwid_len) == 0) {
            return FORGEBIT_VALID;
        }
        return FORGEBIT_HARDWARE_MISMATCH;
    }

    if (fb_json_is_array(hwid)) {
        for (size_t i = 0; i < hwid->as.arr.count; i++) {
            const fb_json_value *item = hwid->as.arr.items[i];
            if (fb_json_is_string(item) && item->as.str.len == hwid_len &&
                memcmp(item->as.str.ptr, hardware_id, hwid_len) == 0) {
                return FORGEBIT_VALID;
            }
        }
        return FORGEBIT_HARDWARE_MISMATCH;
    }

    return FORGEBIT_HARDWARE_MISMATCH;
}

forgebit_result_code fb_header_validate_typ(
    const fb_json_value *typ_value,
    bool strict_type,
    forgebit_verify_result *result
) {
    bool accepted = str_eq(typ_value, "JWT") || str_eq(typ_value, "FORGEBIT-LICENSE");
    if (accepted) return FORGEBIT_VALID;

    if (strict_type) return FORGEBIT_UNSUPPORTED_TYPE;

    fb_result_add_warning(result, FORGEBIT_WARNING_UNKNOWN_TYPE);
    return FORGEBIT_VALID;
}

forgebit_result_code fb_header_validate_crit(const fb_json_value *crit_value) {
    if (crit_value == NULL) return FORGEBIT_VALID;

    if (!fb_json_is_array(crit_value)) return FORGEBIT_MALFORMED_HEADER;
    if (crit_value->as.arr.count == 0) return FORGEBIT_MALFORMED_HEADER;

    for (size_t i = 0; i < crit_value->as.arr.count; i++) {
        if (!is_nonempty_string(crit_value->as.arr.items[i])) {
            return FORGEBIT_MALFORMED_HEADER;
        }
    }

    /* Protocol Version 1 defines no critical header extensions. Any
     * present crit name is therefore unsupported (universal SPEC §4). */
    return FORGEBIT_MALFORMED_HEADER;
}
