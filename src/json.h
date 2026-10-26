#ifndef FORGEBIT_JSON_H
#define FORGEBIT_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Private backing for the public forgebit_json_value type. */

typedef enum fb_json_tag {
    FB_JSON_TAG_NULL,
    FB_JSON_TAG_BOOL,
    FB_JSON_TAG_INT,
    FB_JSON_TAG_DOUBLE,
    FB_JSON_TAG_STRING,
    FB_JSON_TAG_ARRAY,
    FB_JSON_TAG_OBJECT
} fb_json_tag;

struct forgebit_json_value {
    fb_json_tag tag;
    union {
        bool b;
        int64_t i;
        double d;
        struct {
            char *ptr;
            size_t len;
        } str;
        struct {
            struct forgebit_json_value **items;
            size_t count;
        } arr;
        struct {
            char **keys;
            size_t *key_lens;
            struct forgebit_json_value **values;
            size_t count;
        } obj;
    } as;
};

typedef struct forgebit_json_value fb_json_value;

typedef enum {
    FB_JSON_OK = 0,
    FB_JSON_ERR_UTF8,
    FB_JSON_ERR_SYNTAX,
    FB_JSON_ERR_DEPTH,
    FB_JSON_ERR_DUPLICATE_KEY,
    FB_JSON_ERR_TRAILING_DATA,
    FB_JSON_ERR_NOT_OBJECT,
    FB_JSON_ERR_TOO_LARGE,
    FB_JSON_ERR_NUMBER_RANGE,
    FB_JSON_ERR_ALLOC
} fb_json_status;

typedef struct {
    size_t max_depth;
    size_t max_bytes;
    bool require_object_root;
} fb_json_parse_options;

/* utf8/len need not be NUL-terminated; parsing uses the explicit length
 * throughout. On success, *out is a heap-allocated tree owned by the
 * caller and must be released with fb_json_free(). */
fb_json_status fb_json_parse(
    const uint8_t *utf8,
    size_t len,
    const fb_json_parse_options *opts,
    fb_json_value **out
);

void fb_json_free(fb_json_value *value);

/* Internal typed access used by claim validation. */
static inline bool fb_json_is_object(const fb_json_value *v) {
    return v != NULL && v->tag == FB_JSON_TAG_OBJECT;
}
static inline bool fb_json_is_array(const fb_json_value *v) {
    return v != NULL && v->tag == FB_JSON_TAG_ARRAY;
}
static inline bool fb_json_is_string(const fb_json_value *v) {
    return v != NULL && v->tag == FB_JSON_TAG_STRING;
}
static inline bool fb_json_is_int(const fb_json_value *v) {
    return v != NULL && v->tag == FB_JSON_TAG_INT;
}
static inline bool fb_json_is_bool(const fb_json_value *v) {
    return v != NULL && v->tag == FB_JSON_TAG_BOOL;
}

const fb_json_value *fb_json_object_find(const fb_json_value *object, const char *key);

#endif /* FORGEBIT_JSON_H */
