#ifndef FORGEBIT_RESULT_H
#define FORGEBIT_RESULT_H

#include "forgebit/forgebit.h"

#include "json.h"

/* Backing storage for the public opaque result. features_view borrows from
 * claims_root and is released with it. */
struct forgebit_verify_result {
    bool valid;
    forgebit_result_code code;
    const char *message;
    char *key_id; /* may be NULL if no kid was safely parsed */
    fb_json_value *claims_root;
    const fb_json_value *features_view;
    forgebit_warning_code *warnings;
    size_t warning_count;
    size_t warning_cap;
};

forgebit_verify_result *fb_result_create(void);

/* Keeps any key ID captured before the failure. */
void fb_result_set_failure(forgebit_verify_result *result, forgebit_result_code code);

/* Transfers ownership of payload_tree to result. */
void fb_result_set_success(forgebit_verify_result *result, fb_json_value *payload_tree);

/* key_id_bytes need not be NUL-terminated. */
void fb_result_set_key_id(forgebit_verify_result *result, const char *key_id_bytes, size_t len);

void fb_result_add_warning(forgebit_verify_result *result, forgebit_warning_code warning);

#endif /* FORGEBIT_RESULT_H */
