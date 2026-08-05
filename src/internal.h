#ifndef FORGEBIT_INTERNAL_H
#define FORGEBIT_INTERNAL_H

#include <stddef.h>

/* Recommended default maximums, universal spec Sec 17. */
#define FB_LIMIT_LICENSE_BYTES      ((size_t)1 * 1024 * 1024) /* 1 MiB */
#define FB_LIMIT_HEADER_BYTES       ((size_t)16 * 1024)       /* 16 KiB */
#define FB_LIMIT_PAYLOAD_BYTES      ((size_t)768 * 1024)      /* 768 KiB */
#define FB_LIMIT_KEY_COUNT          ((size_t)1024)
#define FB_LIMIT_JSON_DEPTH         ((size_t)64)

#define FB_ED25519_PUBLIC_KEY_BYTES 32
#define FB_ED25519_SIGNATURE_BYTES  64

#endif /* FORGEBIT_INTERNAL_H */
