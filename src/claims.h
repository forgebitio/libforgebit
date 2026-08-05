#ifndef FORGEBIT_CLAIMS_H
#define FORGEBIT_CLAIMS_H

#include <stdint.h>

#include "json.h"
#include "result.h"

/* Payload is expected to be a parsed JSON object. Validation functions
 * return FORGEBIT_VALID when their checks pass. */

forgebit_result_code fb_claims_validate_required(
    const fb_json_value *payload,
    forgebit_verify_result *result
);
forgebit_result_code fb_claims_validate_version(const fb_json_value *payload);
forgebit_result_code fb_claims_validate_offline(const fb_json_value *payload);
forgebit_result_code fb_claims_validate_vendor_product(
    const fb_json_value *payload,
    const char *expected_vendor,
    const char *expected_product
);

forgebit_result_code fb_claims_validate_time(
    const fb_json_value *payload,
    int64_t now,
    uint32_t skew,
    bool require_expiration,
    forgebit_verify_result *result
);

forgebit_result_code fb_claims_validate_hardware(
    const fb_json_value *payload,
    const char *hardware_id
);

/* typ_value may be NULL when the header has no typ field. */
forgebit_result_code fb_header_validate_typ(
    const fb_json_value *typ_value,
    bool strict_type,
    forgebit_verify_result *result
);

/* Version 1 supports no critical header extensions. crit_value may be NULL. */
forgebit_result_code fb_header_validate_crit(const fb_json_value *crit_value);

#endif /* FORGEBIT_CLAIMS_H */
