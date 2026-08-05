#ifndef FORGEBIT_CODES_H
#define FORGEBIT_CODES_H

#include "forgebit/forgebit.h"

/* Default English message for a result code, used to seed
 * forgebit_verify_result.message. Never returns NULL. */
const char *fb_code_default_message(forgebit_result_code code);

#endif /* FORGEBIT_CODES_H */
