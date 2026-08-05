#include "forgebit/forgebit.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base64url.h"
#include "claims.h"
#include "crypto.h"
#include "internal.h"
#include "json.h"
#include "jws.h"
#include "result.h"

/* Trusted public keys indexed by kid. */

typedef struct {
    char *key_id;
    forgebit_public_key key;
} verifier_entry;

struct forgebit_verifier {
    verifier_entry *entries;
    size_t count;
    size_t capacity;
};

forgebit_verifier *forgebit_verifier_create(void) {
    return (forgebit_verifier *)calloc(1, sizeof(forgebit_verifier));
}

void forgebit_verifier_destroy(forgebit_verifier *verifier) {
    if (verifier == NULL) return;
    for (size_t i = 0; i < verifier->count; i++) {
        free(verifier->entries[i].key_id);
    }
    free(verifier->entries);
    free(verifier);
}

static const forgebit_public_key *find_key(
    const forgebit_verifier *verifier,
    const char *kid,
    size_t kid_len
) {
    for (size_t i = 0; i < verifier->count; i++) {
        if (strlen(verifier->entries[i].key_id) == kid_len &&
            memcmp(verifier->entries[i].key_id, kid, kid_len) == 0) {
            return &verifier->entries[i].key;
        }
    }
    return NULL;
}

forgebit_status forgebit_verifier_add_key(
    forgebit_verifier *verifier,
    const char *key_id,
    const forgebit_public_key *public_key
) {
    if (verifier == NULL || key_id == NULL || key_id[0] == '\0' || public_key == NULL) {
        return FORGEBIT_STATUS_INVALID_CALL;
    }
    if (public_key->struct_size < sizeof(forgebit_public_key)) {
        return FORGEBIT_STATUS_INVALID_PUBLIC_KEY;
    }

    size_t key_id_len = strlen(key_id);
    if (find_key(verifier, key_id, key_id_len) != NULL) {
        return FORGEBIT_STATUS_DUPLICATE_KEY_ID;
    }
    if (verifier->count >= FB_LIMIT_KEY_COUNT) {
        return FORGEBIT_STATUS_KEY_LIMIT_EXCEEDED;
    }

    if (verifier->count == verifier->capacity) {
        size_t new_cap = verifier->capacity == 0 ? 4 : verifier->capacity * 2;
        verifier_entry *n =
            (verifier_entry *)realloc(verifier->entries, new_cap * sizeof(verifier_entry));
        if (n == NULL) return FORGEBIT_STATUS_ALLOCATION_FAILED;
        verifier->entries = n;
        verifier->capacity = new_cap;
    }

    char *key_id_copy = (char *)malloc(key_id_len + 1);
    if (key_id_copy == NULL) return FORGEBIT_STATUS_ALLOCATION_FAILED;
    memcpy(key_id_copy, key_id, key_id_len + 1);

    verifier->entries[verifier->count].key_id = key_id_copy;
    verifier->entries[verifier->count].key = *public_key;
    verifier->entries[verifier->count].key.struct_size = sizeof(forgebit_public_key);
    verifier->count++;

    return FORGEBIT_STATUS_OK;
}

forgebit_status forgebit_verifier_add_key_base64url(
    forgebit_verifier *verifier,
    const char *key_id,
    const char *public_key_base64url
) {
    if (verifier == NULL || key_id == NULL || public_key_base64url == NULL) {
        return FORGEBIT_STATUS_INVALID_CALL;
    }

    uint8_t *decoded = NULL;
    size_t decoded_len = 0;
    fb_b64_status bst = fb_base64url_decode(
        public_key_base64url,
        strlen(public_key_base64url),
        &decoded,
        &decoded_len
    );
    if (bst != FB_B64_OK) {
        free(decoded);
        return FORGEBIT_STATUS_INVALID_PUBLIC_KEY;
    }
    if (decoded_len != FORGEBIT_PUBLIC_KEY_BYTES) {
        free(decoded);
        return FORGEBIT_STATUS_INVALID_PUBLIC_KEY;
    }

    forgebit_public_key key = FORGEBIT_PUBLIC_KEY_INIT;
    memcpy(key.bytes, decoded, FORGEBIT_PUBLIC_KEY_BYTES);
    free(decoded);

    return forgebit_verifier_add_key(verifier, key_id, &key);
}

void forgebit_verify_options_init(forgebit_verify_options *options) {
    if (options == NULL) return;
    forgebit_verify_options defaults = FORGEBIT_VERIFY_OPTIONS_INIT;
    *options = defaults;
}

forgebit_status forgebit_verify(
    const forgebit_verifier *verifier,
    const uint8_t *license,
    size_t license_length,
    const forgebit_verify_options *options,
    forgebit_verify_result **result
) {
    if (result == NULL) return FORGEBIT_STATUS_INVALID_CALL;
    *result = NULL;

    forgebit_verify_result *r = fb_result_create();
    if (r == NULL) return FORGEBIT_STATUS_ALLOCATION_FAILED;
    *result = r;

    uint8_t *header_bytes = NULL;
    uint8_t *payload_bytes = NULL;
    uint8_t *sig_bytes = NULL;
    fb_json_value *header_tree = NULL;
    fb_json_value *payload_tree = NULL;

    forgebit_result_code code;

    /* Keep these checks in the order defined by protocol section 10. */
    if (verifier == NULL || (license == NULL && license_length > 0)) {
        fb_result_set_failure(r, FORGEBIT_INVALID_ARGUMENT);
        goto cleanup;
    }

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    if (options != NULL) {
        size_t copy_size = options->struct_size;
        if (copy_size > sizeof(opts)) copy_size = sizeof(opts);
        memcpy(&opts, options, copy_size);
    }

    if (!fb_crypto_ensure_initialized()) {
        fb_result_set_failure(r, FORGEBIT_INTERNAL_ERROR);
        goto cleanup;
    }

    if (license_length > FB_LIMIT_LICENSE_BYTES) {
        fb_result_set_failure(r, FORGEBIT_MALFORMED_LICENSE);
        goto cleanup;
    }

    /* Step 2 */
    fb_jws_segments segs;
    if (fb_jws_split(license, license_length, &segs) != FB_JWS_OK) {
        fb_result_set_failure(r, FORGEBIT_MALFORMED_LICENSE);
        goto cleanup;
    }

    /* Steps 3-4 */
    size_t header_bytes_len;
    if (fb_base64url_decode(
            (const char *)segs.header_b64,
            segs.header_b64_len,
            &header_bytes,
            &header_bytes_len
        ) != FB_B64_OK) {
        fb_result_set_failure(r, FORGEBIT_MALFORMED_LICENSE);
        goto cleanup;
    }

    {
        fb_json_parse_options header_popts = { FB_LIMIT_JSON_DEPTH, FB_LIMIT_HEADER_BYTES, true };
        fb_json_status hst =
            fb_json_parse(header_bytes, header_bytes_len, &header_popts, &header_tree);
        if (hst != FB_JSON_OK) {
            fb_result_set_failure(r, FORGEBIT_MALFORMED_HEADER);
            goto cleanup;
        }
    }

    {
        const fb_json_value *alg = fb_json_object_find(header_tree, "alg");
        if (!fb_json_is_string(alg) || alg->as.str.len != 5 ||
            memcmp(alg->as.str.ptr, "EdDSA", 5) != 0) {
            fb_result_set_failure(r, FORGEBIT_UNSUPPORTED_ALGORITHM);
            goto cleanup;
        }
    }

    const fb_json_value *kid = fb_json_object_find(header_tree, "kid");
    if (!fb_json_is_string(kid) || kid->as.str.len == 0) {
        fb_result_set_failure(r, FORGEBIT_MALFORMED_HEADER);
        goto cleanup;
    }
    fb_result_set_key_id(r, kid->as.str.ptr, kid->as.str.len);

    {
        const fb_json_value *typ = fb_json_object_find(header_tree, "typ");
        if (typ != NULL && !fb_json_is_string(typ)) {
            fb_result_set_failure(r, FORGEBIT_MALFORMED_HEADER);
            goto cleanup;
        }
        code = fb_header_validate_typ(typ, opts.strict_type, r);
        if (code != FORGEBIT_VALID) {
            fb_result_set_failure(r, code);
            goto cleanup;
        }
    }

    {
        const fb_json_value *crit = fb_json_object_find(header_tree, "crit");
        code = fb_header_validate_crit(crit);
        if (code != FORGEBIT_VALID) {
            fb_result_set_failure(r, code);
            goto cleanup;
        }
    }

    /* Step 5 */
    const forgebit_public_key *key = find_key(verifier, kid->as.str.ptr, kid->as.str.len);
    if (key == NULL) {
        fb_result_set_failure(r, FORGEBIT_UNKNOWN_KEY);
        goto cleanup;
    }

    /* Step 6 */
    size_t sig_len;
    if (fb_base64url_decode((const char *)segs.sig_b64, segs.sig_b64_len, &sig_bytes, &sig_len) !=
        FB_B64_OK) {
        fb_result_set_failure(r, FORGEBIT_MALFORMED_LICENSE);
        goto cleanup;
    }
    if (sig_len != FB_ED25519_SIGNATURE_BYTES) {
        fb_result_set_failure(r, FORGEBIT_INVALID_SIGNATURE);
        goto cleanup;
    }
    if (!fb_crypto_ed25519_verify(
            key->bytes,
            sig_bytes,
            segs.signing_input,
            segs.signing_input_len
        )) {
        fb_result_set_failure(r, FORGEBIT_INVALID_SIGNATURE);
        goto cleanup;
    }

    /* Step 7 */
    size_t payload_bytes_len;
    if (fb_base64url_decode(
            (const char *)segs.payload_b64,
            segs.payload_b64_len,
            &payload_bytes,
            &payload_bytes_len
        ) != FB_B64_OK) {
        fb_result_set_failure(r, FORGEBIT_MALFORMED_LICENSE);
        goto cleanup;
    }
    {
        fb_json_parse_options payload_popts = { FB_LIMIT_JSON_DEPTH, FB_LIMIT_PAYLOAD_BYTES, true };
        fb_json_status pst =
            fb_json_parse(payload_bytes, payload_bytes_len, &payload_popts, &payload_tree);
        if (pst != FB_JSON_OK) {
            fb_result_set_failure(r, FORGEBIT_MALFORMED_PAYLOAD);
            goto cleanup;
        }
    }

    /* Step 8 */
    code = fb_claims_validate_required(payload_tree, r);
    if (code != FORGEBIT_VALID) {
        fb_result_set_failure(r, code);
        goto cleanup;
    }

    /* Step 9 */
    code = fb_claims_validate_version(payload_tree);
    if (code != FORGEBIT_VALID) {
        fb_result_set_failure(r, code);
        goto cleanup;
    }

    /* Step 10 */
    code = fb_claims_validate_offline(payload_tree);
    if (code != FORGEBIT_VALID) {
        fb_result_set_failure(r, code);
        goto cleanup;
    }

    /* Step 11 */
    code = fb_claims_validate_vendor_product(
        payload_tree,
        opts.expected_vendor,
        opts.expected_product
    );
    if (code != FORGEBIT_VALID) {
        fb_result_set_failure(r, code);
        goto cleanup;
    }

    /* Step 12 */
    {
        int64_t now = opts.has_current_time ? opts.current_time : (int64_t)time(NULL);
        code = fb_claims_validate_time(
            payload_tree,
            now,
            opts.clock_skew_seconds,
            opts.require_expiration,
            r
        );
        if (code != FORGEBIT_VALID) {
            fb_result_set_failure(r, code);
            goto cleanup;
        }
    }

    /* Step 13 */
    code = fb_claims_validate_hardware(payload_tree, opts.hardware_id);
    if (code != FORGEBIT_VALID) {
        fb_result_set_failure(r, code);
        goto cleanup;
    }

    /* Step 14 */
    fb_result_set_success(r, payload_tree);
    payload_tree = NULL; /* now owned by r */

cleanup:
    free(header_bytes);
    free(payload_bytes);
    free(sig_bytes);
    fb_json_free(header_tree);
    fb_json_free(payload_tree);
    return FORGEBIT_STATUS_OK;
}
