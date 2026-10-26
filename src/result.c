#include "result.h"

#include <stdlib.h>
#include <string.h>

#include "codes.h"

static char *dup_bytes_nul_terminated(const char *bytes, size_t len) {
    char *copy = (char *)malloc(len + 1);
    if (copy == NULL) return NULL;
    if (len > 0) memcpy(copy, bytes, len);
    copy[len] = '\0';
    return copy;
}

forgebit_verify_result *fb_result_create(void) {
    forgebit_verify_result *r = (forgebit_verify_result *)calloc(1, sizeof(forgebit_verify_result));
    return r;
}

void fb_result_set_failure(forgebit_verify_result *result, forgebit_result_code code) {
    if (result == NULL) return;
    result->valid = false;
    result->code = code;
    result->message = fb_code_default_message(code);
}

void fb_result_set_success(forgebit_verify_result *result, fb_json_value *payload_tree) {
    if (result == NULL) return;
    result->valid = true;
    result->code = FORGEBIT_VALID;
    result->message = fb_code_default_message(FORGEBIT_VALID);
    result->claims_root = payload_tree;
    result->features_view = fb_json_object_find(payload_tree, "features");
}

void fb_result_set_key_id(forgebit_verify_result *result, const char *key_id_bytes, size_t len) {
    if (result == NULL) return;
    free(result->key_id);
    result->key_id = dup_bytes_nul_terminated(key_id_bytes, len);
}

void fb_result_add_warning(forgebit_verify_result *result, forgebit_warning_code warning) {
    if (result == NULL) return;
    if (result->warning_count == result->warning_cap) {
        size_t new_cap = result->warning_cap == 0 ? 4 : result->warning_cap * 2;
        forgebit_warning_code *n = (forgebit_warning_code *)
            realloc(result->warnings, new_cap * sizeof(forgebit_warning_code));
        if (n == NULL) return;
        result->warnings = n;
        result->warning_cap = new_cap;
    }
    result->warnings[result->warning_count++] = warning;
}

void forgebit_verify_result_destroy(forgebit_verify_result *result) {
    if (result == NULL) return;
    free(result->key_id);
    fb_json_free(result->claims_root);
    free(result->warnings);
    free(result);
}

/* Public accessors */

bool forgebit_result_is_valid(const forgebit_verify_result *result) {
    return result != NULL && result->valid;
}

forgebit_result_code forgebit_result_code_get(const forgebit_verify_result *result) {
    if (result == NULL) return FORGEBIT_INTERNAL_ERROR;
    return result->code;
}

const char *forgebit_result_message(const forgebit_verify_result *result) {
    return result != NULL ? result->message : NULL;
}

const char *forgebit_result_key_id(const forgebit_verify_result *result) {
    return result != NULL ? result->key_id : NULL;
}

static const fb_json_value *claims_field(const forgebit_verify_result *result) {
    if (result == NULL || !result->valid) return NULL;
    return result->claims_root;
}

const char *forgebit_result_vendor(const forgebit_verify_result *result) {
    const fb_json_value *claims = claims_field(result);
    const fb_json_value *v = fb_json_object_find(claims, "iss");
    return fb_json_is_string(v) ? v->as.str.ptr : NULL;
}

const char *forgebit_result_product(const forgebit_verify_result *result) {
    const fb_json_value *claims = claims_field(result);
    const fb_json_value *v = fb_json_object_find(claims, "aud");
    return fb_json_is_string(v) ? v->as.str.ptr : NULL;
}

const char *forgebit_result_license_id(const forgebit_verify_result *result) {
    const fb_json_value *claims = claims_field(result);
    const fb_json_value *v = fb_json_object_find(claims, "jti");
    return fb_json_is_string(v) ? v->as.str.ptr : NULL;
}

static bool timestamp_field(const forgebit_verify_result *result, const char *key, int64_t *out) {
    const fb_json_value *claims = claims_field(result);
    const fb_json_value *v = fb_json_object_find(claims, key);
    if (!fb_json_is_int(v) || out == NULL) return false;
    *out = v->as.i;
    return true;
}

bool forgebit_result_issued_at(const forgebit_verify_result *result, int64_t *out) {
    return timestamp_field(result, "iat", out);
}

bool forgebit_result_not_before(const forgebit_verify_result *result, int64_t *out) {
    return timestamp_field(result, "nbf", out);
}

bool forgebit_result_expires_at(const forgebit_verify_result *result, int64_t *out) {
    return timestamp_field(result, "exp", out);
}

const forgebit_json_value *forgebit_result_claims(const forgebit_verify_result *result) {
    return claims_field(result);
}

const forgebit_json_value *forgebit_result_features(const forgebit_verify_result *result) {
    if (result == NULL || !result->valid) return NULL;
    return result->features_view;
}

size_t forgebit_result_warning_count(const forgebit_verify_result *result) {
    return result != NULL ? result->warning_count : 0;
}

forgebit_warning_code forgebit_result_warning_at(
    const forgebit_verify_result *result,
    size_t index
) {
    if (result == NULL || index >= result->warning_count) return 0;
    return result->warnings[index];
}
