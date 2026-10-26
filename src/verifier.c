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
    size_t key_id_len;
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
        if (verifier->entries[i].key_id_len == kid_len &&
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
    verifier->entries[verifier->count].key_id_len = key_id_len;
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
    if (bst == FB_B64_ALLOC_FAILED) return FORGEBIT_STATUS_ALLOCATION_FAILED;
    if (bst != FB_B64_OK || decoded_len != FORGEBIT_PUBLIC_KEY_BYTES) {
        free(decoded);
        return FORGEBIT_STATUS_INVALID_PUBLIC_KEY;
    }

    forgebit_public_key key = FORGEBIT_PUBLIC_KEY_INIT;
    memcpy(key.bytes, decoded, FORGEBIT_PUBLIC_KEY_BYTES);
    free(decoded);

    return forgebit_verifier_add_key(verifier, key_id, &key);
}

/* Bad input is malformed; running out of memory is an internal error. */
static forgebit_result_code decode_segment(
    const uint8_t *b64,
    size_t b64_len,
    uint8_t **out,
    size_t *out_len
) {
    fb_b64_status st = fb_base64url_decode((const char *)b64, b64_len, out, out_len);
    if (st == FB_B64_OK) return FORGEBIT_VALID;
    return st == FB_B64_ALLOC_FAILED ? FORGEBIT_INTERNAL_ERROR : FORGEBIT_MALFORMED_LICENSE;
}

static forgebit_result_code parse_segment(
    const uint8_t *bytes,
    size_t len,
    size_t max_bytes,
    forgebit_result_code malformed,
    fb_json_value **out
) {
    fb_json_parse_options popts = { FB_LIMIT_JSON_DEPTH, max_bytes, true };
    fb_json_status st = fb_json_parse(bytes, len, &popts, out);
    if (st == FB_JSON_OK) return FORGEBIT_VALID;
    return st == FB_JSON_ERR_ALLOC ? FORGEBIT_INTERNAL_ERROR : malformed;
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
        code = FORGEBIT_INVALID_ARGUMENT;
        goto fail;
    }

    forgebit_verify_options opts = FORGEBIT_VERIFY_OPTIONS_INIT;
    if (options != NULL) {
        size_t copy_size = options->struct_size;
        if (copy_size > sizeof(opts)) copy_size = sizeof(opts);
        memcpy(&opts, options, copy_size);
    }

    if (!fb_crypto_ensure_initialized()) {
        code = FORGEBIT_INTERNAL_ERROR;
        goto fail;
    }

    /* Steps 1-2 */
    fb_jws_segments segs;
    if (license_length > FB_LIMIT_LICENSE_BYTES ||
        fb_jws_split(license, license_length, &segs) != FB_JWS_OK) {
        code = FORGEBIT_MALFORMED_LICENSE;
        goto fail;
    }

    /* Steps 3-4 */
    size_t header_bytes_len;
    code = decode_segment(segs.header_b64, segs.header_b64_len, &header_bytes, &header_bytes_len);
    if (code != FORGEBIT_VALID) goto fail;
    code = parse_segment(
        header_bytes,
        header_bytes_len,
        FB_LIMIT_HEADER_BYTES,
        FORGEBIT_MALFORMED_HEADER,
        &header_tree
    );
    if (code != FORGEBIT_VALID) goto fail;

    const fb_json_value *alg = fb_json_object_find(header_tree, "alg");
    if (!fb_json_is_string(alg) || alg->as.str.len != 5 ||
        memcmp(alg->as.str.ptr, "EdDSA", 5) != 0) {
        code = FORGEBIT_UNSUPPORTED_ALGORITHM;
        goto fail;
    }

    const fb_json_value *kid = fb_json_object_find(header_tree, "kid");
    if (!fb_json_is_string(kid) || kid->as.str.len == 0) {
        code = FORGEBIT_MALFORMED_HEADER;
        goto fail;
    }
    fb_result_set_key_id(r, kid->as.str.ptr, kid->as.str.len);

    code = fb_header_validate_typ(fb_json_object_find(header_tree, "typ"), opts.strict_type, r);
    if (code != FORGEBIT_VALID) goto fail;

    code = fb_header_validate_crit(fb_json_object_find(header_tree, "crit"));
    if (code != FORGEBIT_VALID) goto fail;

    /* Step 5 */
    const forgebit_public_key *key = find_key(verifier, kid->as.str.ptr, kid->as.str.len);
    if (key == NULL) {
        code = FORGEBIT_UNKNOWN_KEY;
        goto fail;
    }

    /* Step 6 */
    size_t sig_len;
    code = decode_segment(segs.sig_b64, segs.sig_b64_len, &sig_bytes, &sig_len);
    if (code != FORGEBIT_VALID) goto fail;
    if (sig_len != FB_ED25519_SIGNATURE_BYTES) {
        code = FORGEBIT_INVALID_SIGNATURE;
        goto fail;
    }
    if (!fb_crypto_ed25519_verify(
            key->bytes,
            sig_bytes,
            segs.signing_input,
            segs.signing_input_len
        )) {
        code = FORGEBIT_INVALID_SIGNATURE;
        goto fail;
    }

    /* Step 7 */
    size_t payload_bytes_len;
    code =
        decode_segment(segs.payload_b64, segs.payload_b64_len, &payload_bytes, &payload_bytes_len);
    if (code != FORGEBIT_VALID) goto fail;
    code = parse_segment(
        payload_bytes,
        payload_bytes_len,
        FB_LIMIT_PAYLOAD_BYTES,
        FORGEBIT_MALFORMED_PAYLOAD,
        &payload_tree
    );
    if (code != FORGEBIT_VALID) goto fail;

    /* Step 8 */
    code = fb_claims_validate_required(payload_tree, r);
    if (code != FORGEBIT_VALID) goto fail;

    /* Step 9 */
    code = fb_claims_validate_version(payload_tree);
    if (code != FORGEBIT_VALID) goto fail;

    /* Step 10 */
    code = fb_claims_validate_offline(payload_tree);
    if (code != FORGEBIT_VALID) goto fail;

    /* Step 11 */
    code = fb_claims_validate_vendor_product(
        payload_tree,
        opts.expected_vendor,
        opts.expected_product
    );
    if (code != FORGEBIT_VALID) goto fail;

    /* Step 12 */
    int64_t now = opts.has_current_time ? opts.current_time : (int64_t)time(NULL);
    code = fb_claims_validate_time(
        payload_tree,
        now,
        opts.clock_skew_seconds,
        opts.require_expiration,
        r
    );
    if (code != FORGEBIT_VALID) goto fail;

    /* Step 13 */
    code = fb_claims_validate_hardware(payload_tree, opts.hardware_id);
    if (code != FORGEBIT_VALID) goto fail;

    /* Step 14 */
    fb_result_set_success(r, payload_tree);
    payload_tree = NULL; /* now owned by r */
    goto cleanup;

fail:
    fb_result_set_failure(r, code);
cleanup:
    free(header_bytes);
    free(payload_bytes);
    free(sig_bytes);
    fb_json_free(header_tree);
    fb_json_free(payload_tree);
    return FORGEBIT_STATUS_OK;
}
