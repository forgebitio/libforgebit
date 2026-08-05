#include "codes.h"

typedef struct {
    forgebit_result_code code;
    const char *name;
    const char *message;
} code_entry;

static const code_entry codes[] = {
    { FORGEBIT_VALID, "VALID", "The license is valid." },
    { FORGEBIT_INVALID_ARGUMENT,
      "INVALID_ARGUMENT",
      "One or more arguments passed to the verification call were invalid." },
    { FORGEBIT_MALFORMED_LICENSE,
      "MALFORMED_LICENSE",
      "The license is not a well-formed compact JWS." },
    { FORGEBIT_MALFORMED_HEADER, "MALFORMED_HEADER", "The protected header is malformed." },
    { FORGEBIT_MALFORMED_PAYLOAD,
      "MALFORMED_PAYLOAD",
      "The payload is malformed or missing required claims." },
    { FORGEBIT_UNSUPPORTED_ALGORITHM,
      "UNSUPPORTED_ALGORITHM",
      "The protected header specifies an unsupported signing algorithm." },
    { FORGEBIT_UNSUPPORTED_TYPE,
      "UNSUPPORTED_TYPE",
      "The protected header's typ is missing or not accepted under strict type checking." },
    { FORGEBIT_UNSUPPORTED_VERSION,
      "UNSUPPORTED_VERSION",
      "The signed protocol version (fbt_ver) is not supported." },
    { FORGEBIT_UNKNOWN_KEY,
      "UNKNOWN_KEY",
      "No trusted public key is registered for the license's kid." },
    { FORGEBIT_INVALID_PUBLIC_KEY,
      "INVALID_PUBLIC_KEY",
      "The supplied public key material is invalid." },
    { FORGEBIT_INVALID_SIGNATURE, "INVALID_SIGNATURE", "Signature verification failed." },
    { FORGEBIT_OFFLINE_NOT_ALLOWED,
      "OFFLINE_NOT_ALLOWED",
      "The license does not permit offline verification." },
    { FORGEBIT_WRONG_VENDOR,
      "WRONG_VENDOR",
      "The license was not issued for the expected vendor." },
    { FORGEBIT_WRONG_PRODUCT,
      "WRONG_PRODUCT",
      "The license was not issued for the expected product." },
    { FORGEBIT_LICENSE_NOT_YET_VALID,
      "LICENSE_NOT_YET_VALID",
      "The license is not valid yet (nbf is in the future)." },
    { FORGEBIT_LICENSE_EXPIRED, "LICENSE_EXPIRED", "The license has expired." },
    { FORGEBIT_LICENSE_ISSUED_IN_FUTURE,
      "LICENSE_ISSUED_IN_FUTURE",
      "The license's iat is in the future." },
    { FORGEBIT_EXPIRATION_REQUIRED,
      "EXPIRATION_REQUIRED",
      "The caller requires an expiration date, but the license has none." },
    { FORGEBIT_HARDWARE_ID_REQUIRED,
      "HARDWARE_ID_REQUIRED",
      "The license is hardware-bound but no hardware identifier was supplied." },
    { FORGEBIT_HARDWARE_MISMATCH,
      "HARDWARE_MISMATCH",
      "The supplied hardware identifier does not match the license." },
    { FORGEBIT_INTERNAL_ERROR, "INTERNAL_ERROR", "An unexpected internal error occurred." }
};

static const size_t code_count = sizeof(codes) / sizeof(codes[0]);

static const code_entry *find_entry(forgebit_result_code code) {
    for (size_t i = 0; i < code_count; i++) {
        if (codes[i].code == code) return &codes[i];
    }
    return NULL;
}

const char *fb_code_default_message(forgebit_result_code code) {
    const code_entry *e = find_entry(code);
    return e != NULL ? e->message : "Unknown result code.";
}

const char *forgebit_result_code_name(forgebit_result_code code) {
    const code_entry *e = find_entry(code);
    return e != NULL ? e->name : "UNKNOWN";
}

const char *forgebit_warning_code_name(forgebit_warning_code code) {
    switch (code) {
    case FORGEBIT_WARNING_UNKNOWN_TYPE:
        return "UNKNOWN_TYPE";
    case FORGEBIT_WARNING_NO_EXPIRATION:
        return "NO_EXPIRATION";
    case FORGEBIT_WARNING_UNRECOGNIZED_CLAIMS:
        return "UNRECOGNIZED_CLAIMS";
    default:
        return "UNKNOWN";
    }
}
