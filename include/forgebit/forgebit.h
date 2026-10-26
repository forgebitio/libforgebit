#ifndef FORGEBIT_H
#define FORGEBIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) && (__GNUC__ >= 4)
#define FORGEBIT_API __attribute__((visibility("default")))
#else
#define FORGEBIT_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define FORGEBIT_VERSION_MAJOR    0
#define FORGEBIT_VERSION_MINOR    2
#define FORGEBIT_VERSION_PATCH    0

/* fbt_ver protocol version this build supports. */
#define FORGEBIT_PROTOCOL_VERSION 1

/* Opaque types */

typedef struct forgebit_verifier forgebit_verifier;
typedef struct forgebit_verify_result forgebit_verify_result;
typedef struct forgebit_json_value forgebit_json_value;

/* API status, separate from the license verification result. */

typedef int32_t forgebit_status;

#define FORGEBIT_STATUS_OK                 0
#define FORGEBIT_STATUS_INVALID_CALL       1
#define FORGEBIT_STATUS_ALLOCATION_FAILED  2
#define FORGEBIT_STATUS_INVALID_PUBLIC_KEY 3
#define FORGEBIT_STATUS_DUPLICATE_KEY_ID   4
#define FORGEBIT_STATUS_KEY_LIMIT_EXCEEDED 5

/* Result codes from protocol section 14. Published values are permanent. */

typedef int32_t forgebit_result_code;

#define FORGEBIT_VALID                    0

#define FORGEBIT_INVALID_ARGUMENT         1000
#define FORGEBIT_MALFORMED_LICENSE        1001
#define FORGEBIT_MALFORMED_HEADER         1002
#define FORGEBIT_MALFORMED_PAYLOAD        1003

#define FORGEBIT_UNSUPPORTED_ALGORITHM    2000
#define FORGEBIT_UNSUPPORTED_TYPE         2001
#define FORGEBIT_UNSUPPORTED_VERSION      2002

#define FORGEBIT_UNKNOWN_KEY              3000
#define FORGEBIT_INVALID_PUBLIC_KEY       3001
#define FORGEBIT_INVALID_SIGNATURE        3002

#define FORGEBIT_OFFLINE_NOT_ALLOWED      4000
#define FORGEBIT_WRONG_VENDOR             4001
#define FORGEBIT_WRONG_PRODUCT            4002

#define FORGEBIT_LICENSE_NOT_YET_VALID    5000
#define FORGEBIT_LICENSE_EXPIRED          5001
#define FORGEBIT_LICENSE_ISSUED_IN_FUTURE 5002
#define FORGEBIT_EXPIRATION_REQUIRED      5003

#define FORGEBIT_HARDWARE_ID_REQUIRED     6000
#define FORGEBIT_HARDWARE_MISMATCH        6001

#define FORGEBIT_INTERNAL_ERROR           9000

/* Non-fatal warning codes from protocol section 15. Zero is reserved. */

typedef int32_t forgebit_warning_code;

#define FORGEBIT_WARNING_UNKNOWN_TYPE        1
#define FORGEBIT_WARNING_NO_EXPIRATION       2
#define FORGEBIT_WARNING_UNRECOGNIZED_CLAIMS 3

/* Public keys */

#define FORGEBIT_PUBLIC_KEY_BYTES            32

typedef struct forgebit_public_key {
    size_t struct_size;
    uint8_t bytes[FORGEBIT_PUBLIC_KEY_BYTES];
} forgebit_public_key;

#define FORGEBIT_PUBLIC_KEY_INIT { sizeof(forgebit_public_key), { 0 } }

/* Verifier lifecycle and key management */

FORGEBIT_API forgebit_verifier *forgebit_verifier_create(void);
FORGEBIT_API void forgebit_verifier_destroy(forgebit_verifier *verifier);

/* key_id and public_key are copied internally; neither needs to outlive
 * the call. */
FORGEBIT_API forgebit_status forgebit_verifier_add_key(
    forgebit_verifier *verifier,
    const char *key_id,
    const forgebit_public_key *public_key
);

/* The encoded key must be strict, unpadded base64url and decode to
 * FORGEBIT_PUBLIC_KEY_BYTES bytes. */
FORGEBIT_API forgebit_status forgebit_verifier_add_key_base64url(
    forgebit_verifier *verifier,
    const char *key_id,
    const char *public_key_base64url
);

/* Verification options */

typedef struct forgebit_verify_options {
    size_t struct_size;
    const char *expected_vendor;
    const char *expected_product;
    int64_t current_time;
    bool has_current_time;
    uint32_t clock_skew_seconds;
    const char *hardware_id;
    bool strict_type;
    bool require_expiration;
} forgebit_verify_options;

#define FORGEBIT_VERIFY_OPTIONS_INIT \
    { sizeof(forgebit_verify_options), NULL, NULL, 0, false, 0, NULL, false, false }

FORGEBIT_API void forgebit_verify_options_init(forgebit_verify_options *options);

/* Verification */

/* options may be NULL. FORGEBIT_STATUS_OK means *result contains the
 * verification outcome; inspect it with forgebit_result_is_valid() or
 * forgebit_result_code_get(). A rejected license is not an API error. */
FORGEBIT_API forgebit_status forgebit_verify(
    const forgebit_verifier *verifier,
    const uint8_t *license,
    size_t license_length,
    const forgebit_verify_options *options,
    forgebit_verify_result **result
);

FORGEBIT_API void forgebit_verify_result_destroy(forgebit_verify_result *result);

/* Result accessors */

FORGEBIT_API bool forgebit_result_is_valid(const forgebit_verify_result *result);
FORGEBIT_API forgebit_result_code forgebit_result_code_get(const forgebit_verify_result *result);
FORGEBIT_API const char *forgebit_result_code_name(forgebit_result_code code);
FORGEBIT_API const char *forgebit_result_message(const forgebit_verify_result *result);
FORGEBIT_API const char *forgebit_result_key_id(const forgebit_verify_result *result);

/* Only populated when forgebit_result_is_valid() is true. */
FORGEBIT_API const char *forgebit_result_vendor(const forgebit_verify_result *result);
FORGEBIT_API const char *forgebit_result_product(const forgebit_verify_result *result);
FORGEBIT_API const char *forgebit_result_license_id(const forgebit_verify_result *result);
FORGEBIT_API bool forgebit_result_issued_at(const forgebit_verify_result *result, int64_t *out);
FORGEBIT_API bool forgebit_result_not_before(const forgebit_verify_result *result, int64_t *out);
FORGEBIT_API bool forgebit_result_expires_at(const forgebit_verify_result *result, int64_t *out);

FORGEBIT_API const forgebit_json_value *forgebit_result_claims(
    const forgebit_verify_result *result
);
FORGEBIT_API const forgebit_json_value *forgebit_result_features(
    const forgebit_verify_result *result
);

FORGEBIT_API size_t forgebit_result_warning_count(const forgebit_verify_result *result);
FORGEBIT_API forgebit_warning_code
forgebit_result_warning_at(const forgebit_verify_result *result, size_t index);
FORGEBIT_API const char *forgebit_warning_code_name(forgebit_warning_code code);

/* Opaque JSON value inspection (claims / features).
 * Returned JSON pointers belong to the result. Do not free them or use them
 * after destroying the result. */

typedef enum forgebit_json_type {
    FORGEBIT_JSON_NULL = 0,
    FORGEBIT_JSON_BOOL = 1,
    FORGEBIT_JSON_INTEGER = 2,
    FORGEBIT_JSON_NUMBER = 3,
    FORGEBIT_JSON_STRING = 4,
    FORGEBIT_JSON_ARRAY = 5,
    FORGEBIT_JSON_OBJECT = 6
} forgebit_json_type;

FORGEBIT_API forgebit_json_type forgebit_json_type_of(const forgebit_json_value *value);

FORGEBIT_API bool forgebit_json_get_bool(const forgebit_json_value *value, bool *out);
FORGEBIT_API bool forgebit_json_get_integer(const forgebit_json_value *value, int64_t *out);
FORGEBIT_API bool forgebit_json_get_number(const forgebit_json_value *value, double *out);
FORGEBIT_API bool forgebit_json_get_string(
    const forgebit_json_value *value,
    const char **out_utf8,
    size_t *out_len
);

FORGEBIT_API size_t forgebit_json_array_length(const forgebit_json_value *value);
FORGEBIT_API const forgebit_json_value *forgebit_json_array_get(
    const forgebit_json_value *value,
    size_t index
);

FORGEBIT_API size_t forgebit_json_object_size(const forgebit_json_value *value);
FORGEBIT_API const forgebit_json_value *forgebit_json_object_get(
    const forgebit_json_value *value,
    const char *key
);
FORGEBIT_API bool forgebit_json_object_key_at(
    const forgebit_json_value *value,
    size_t index,
    const char **out_key,
    size_t *out_len
);
FORGEBIT_API const forgebit_json_value *forgebit_json_object_value_at(
    const forgebit_json_value *value,
    size_t index
);

#ifdef __cplusplus
}
#endif

#endif /* FORGEBIT_H */
