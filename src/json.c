#define _GNU_SOURCE /* strtod_l and newlocale on glibc */

#include "json.h"

#include "forgebit/forgebit.h"

#include <errno.h>
#include <locale.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#if defined(__APPLE__)
#include <xlocale.h>
#endif

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
    size_t max_depth;
    locale_t c_locale; /* created on first float, freed by fb_json_parse */
} parse_ctx;

static fb_json_status parse_value(parse_ctx *ctx, size_t depth, fb_json_value **out);

/* Allocation */

static fb_json_value *alloc_value(fb_json_tag tag) {
    fb_json_value *v = (fb_json_value *)calloc(1, sizeof(fb_json_value));
    if (v == NULL) return NULL;
    v->tag = tag;
    return v;
}

void fb_json_free(fb_json_value *value) {
    if (value == NULL) return;
    switch (value->tag) {
    case FB_JSON_TAG_STRING:
        free(value->as.str.ptr);
        break;
    case FB_JSON_TAG_ARRAY:
        for (size_t i = 0; i < value->as.arr.count; i++) {
            fb_json_free(value->as.arr.items[i]);
        }
        free(value->as.arr.items);
        break;
    case FB_JSON_TAG_OBJECT:
        for (size_t i = 0; i < value->as.obj.count; i++) {
            free(value->as.obj.keys[i]);
            fb_json_free(value->as.obj.values[i]);
        }
        free(value->as.obj.keys);
        free(value->as.obj.key_lens);
        free(value->as.obj.values);
        break;
    default:
        break;
    }
    free(value);
}

/* Lexing */

static bool is_ws(uint8_t c) {
    return c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D;
}

static void skip_ws(parse_ctx *ctx) {
    while (ctx->pos < ctx->len && is_ws(ctx->data[ctx->pos])) {
        ctx->pos++;
    }
}

static bool at_end(const parse_ctx *ctx) {
    return ctx->pos >= ctx->len;
}

static int peek(const parse_ctx *ctx) {
    if (at_end(ctx)) return -1;
    return ctx->data[ctx->pos];
}

/* UTF-8 decode of one codepoint starting at ctx->pos (not used for the
 * escape-sequence path -- only for raw bytes appearing directly inside a
 * JSON string literal). Returns the number of bytes consumed, or 0 on
 * invalid encoding. Writes the codepoint to *cp. Rejects overlong
 * encodings and encoded surrogate halves, matching strict UTF-8. */

static size_t utf8_decode(const uint8_t *p, size_t remaining, uint32_t *cp) {
    if (remaining == 0) return 0;
    uint8_t b0 = p[0];

    if (b0 < 0x80) {
        *cp = b0;
        return 1;
    }
    if ((b0 & 0xE0) == 0xC0) {
        if (remaining < 2) return 0;
        uint8_t b1 = p[1];
        if ((b1 & 0xC0) != 0x80) return 0;
        uint32_t c = ((uint32_t)(b0 & 0x1F) << 6) | (b1 & 0x3F);
        if (c < 0x80) return 0; /* overlong */
        *cp = c;
        return 2;
    }
    if ((b0 & 0xF0) == 0xE0) {
        if (remaining < 3) return 0;
        uint8_t b1 = p[1], b2 = p[2];
        if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80) return 0;
        uint32_t c = ((uint32_t)(b0 & 0x0F) << 12) | ((uint32_t)(b1 & 0x3F) << 6) | (b2 & 0x3F);
        if (c < 0x800) return 0;                  /* overlong */
        if (c >= 0xD800 && c <= 0xDFFF) return 0; /* encoded surrogate half */
        *cp = c;
        return 3;
    }
    if ((b0 & 0xF8) == 0xF0) {
        if (remaining < 4) return 0;
        uint8_t b1 = p[1], b2 = p[2], b3 = p[3];
        if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80) return 0;
        uint32_t c = ((uint32_t)(b0 & 0x07) << 18) | ((uint32_t)(b1 & 0x3F) << 12) |
                     ((uint32_t)(b2 & 0x3F) << 6) | (b3 & 0x3F);
        if (c < 0x10000 || c > 0x10FFFF) return 0; /* overlong or out of range */
        *cp = c;
        return 4;
    }
    return 0;
}

static size_t utf8_encode(uint32_t cp, uint8_t out[4]) {
    if (cp < 0x80) {
        out[0] = (uint8_t)cp;
        return 1;
    }
    if (cp < 0x800) {
        out[0] = (uint8_t)(0xC0 | (cp >> 6));
        out[1] = (uint8_t)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = (uint8_t)(0xE0 | (cp >> 12));
        out[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (uint8_t)(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = (uint8_t)(0xF0 | (cp >> 18));
    out[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (uint8_t)(0x80 | (cp & 0x3F));
    return 4;
}

/* Scratch buffer for decoded strings. */

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} byte_buf;

static bool byte_buf_reserve(byte_buf *bb, size_t extra) {
    if (bb->len + extra <= bb->cap) return true;
    size_t new_cap = bb->cap == 0 ? 32 : bb->cap;
    while (new_cap < bb->len + extra)
        new_cap *= 2;
    char *n = (char *)realloc(bb->buf, new_cap);
    if (n == NULL) return false;
    bb->buf = n;
    bb->cap = new_cap;
    return true;
}

static bool byte_buf_push(byte_buf *bb, const uint8_t *bytes, size_t n) {
    if (!byte_buf_reserve(bb, n)) return false;
    memcpy(bb->buf + bb->len, bytes, n);
    bb->len += n;
    return true;
}

/* ctx->pos points to the opening quote on entry. */

static bool hex4(const parse_ctx *ctx, size_t pos, uint16_t *out) {
    if (pos + 4 > ctx->len) return false;
    uint16_t v = 0;
    for (size_t i = 0; i < 4; i++) {
        uint8_t c = ctx->data[pos + i];
        v <<= 4;
        if (c >= '0' && c <= '9')
            v |= (uint16_t)(c - '0');
        else if (c >= 'a' && c <= 'f')
            v |= (uint16_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            v |= (uint16_t)(c - 'A' + 10);
        else
            return false;
    }
    *out = v;
    return true;
}

static fb_json_status parse_string_raw(parse_ctx *ctx, char **out_ptr, size_t *out_len) {
    if (peek(ctx) != '"') return FB_JSON_ERR_SYNTAX;
    ctx->pos++;

    byte_buf bb = { 0 };

    for (;;) {
        if (at_end(ctx)) {
            free(bb.buf);
            return FB_JSON_ERR_SYNTAX;
        }
        uint8_t c = ctx->data[ctx->pos];

        if (c == '"') {
            ctx->pos++;
            if (!byte_buf_reserve(&bb, 1)) {
                free(bb.buf);
                return FB_JSON_ERR_ALLOC;
            }
            bb.buf[bb.len] = '\0';
            *out_ptr = bb.buf;
            *out_len = bb.len;
            return FB_JSON_OK;
        }

        if (c == '\\') {
            ctx->pos++;
            if (at_end(ctx)) {
                free(bb.buf);
                return FB_JSON_ERR_SYNTAX;
            }
            uint8_t esc = ctx->data[ctx->pos];
            uint8_t single;
            switch (esc) {
            case '"':
                single = '"';
                break;
            case '\\':
                single = '\\';
                break;
            case '/':
                single = '/';
                break;
            case 'b':
                single = '\b';
                break;
            case 'f':
                single = '\f';
                break;
            case 'n':
                single = '\n';
                break;
            case 'r':
                single = '\r';
                break;
            case 't':
                single = '\t';
                break;
            case 'u': {
                uint16_t u1;
                if (!hex4(ctx, ctx->pos + 1, &u1)) {
                    free(bb.buf);
                    return FB_JSON_ERR_SYNTAX;
                }
                ctx->pos += 5; /* 'u' + 4 hex digits */
                uint32_t cp;
                if (u1 >= 0xD800 && u1 <= 0xDBFF) {
                    /* high surrogate: must be followed by \u low surrogate */
                    if (ctx->pos + 1 >= ctx->len || ctx->data[ctx->pos] != '\\' ||
                        ctx->data[ctx->pos + 1] != 'u') {
                        free(bb.buf);
                        return FB_JSON_ERR_UTF8;
                    }
                    uint16_t u2;
                    if (!hex4(ctx, ctx->pos + 2, &u2)) {
                        free(bb.buf);
                        return FB_JSON_ERR_SYNTAX;
                    }
                    if (u2 < 0xDC00 || u2 > 0xDFFF) {
                        free(bb.buf);
                        return FB_JSON_ERR_UTF8; /* unpaired high surrogate */
                    }
                    ctx->pos += 6;
                    cp = 0x10000 + (((uint32_t)u1 - 0xD800) << 10) + ((uint32_t)u2 - 0xDC00);
                } else if (u1 >= 0xDC00 && u1 <= 0xDFFF) {
                    free(bb.buf);
                    return FB_JSON_ERR_UTF8; /* unpaired low surrogate */
                } else {
                    cp = u1;
                }
                uint8_t enc[4];
                size_t n = utf8_encode(cp, enc);
                if (!byte_buf_push(&bb, enc, n)) {
                    free(bb.buf);
                    return FB_JSON_ERR_ALLOC;
                }
                continue;
            }
            default:
                free(bb.buf);
                return FB_JSON_ERR_SYNTAX;
            }
            if (!byte_buf_push(&bb, &single, 1)) {
                free(bb.buf);
                return FB_JSON_ERR_ALLOC;
            }
            ctx->pos++;
            continue;
        }

        if (c < 0x20) {
            /* raw control characters must be escaped */
            free(bb.buf);
            return FB_JSON_ERR_SYNTAX;
        }

        if (c < 0x80) {
            if (!byte_buf_push(&bb, &c, 1)) {
                free(bb.buf);
                return FB_JSON_ERR_ALLOC;
            }
            ctx->pos++;
            continue;
        }

        uint32_t cp;
        size_t n = utf8_decode(ctx->data + ctx->pos, ctx->len - ctx->pos, &cp);
        if (n == 0) {
            free(bb.buf);
            return FB_JSON_ERR_UTF8;
        }
        if (!byte_buf_push(&bb, ctx->data + ctx->pos, n)) {
            free(bb.buf);
            return FB_JSON_ERR_ALLOC;
        }
        ctx->pos += n;
    }
}

/* Numbers */

static fb_json_status parse_number(parse_ctx *ctx, fb_json_value **out) {
    size_t start = ctx->pos;
    bool is_float = false;

    if (peek(ctx) == '-') ctx->pos++;

    if (at_end(ctx) || ctx->data[ctx->pos] < '0' || ctx->data[ctx->pos] > '9') {
        return FB_JSON_ERR_SYNTAX;
    }
    if (ctx->data[ctx->pos] == '0') {
        ctx->pos++;
    } else {
        while (!at_end(ctx) && ctx->data[ctx->pos] >= '0' && ctx->data[ctx->pos] <= '9')
            ctx->pos++;
    }

    if (!at_end(ctx) && ctx->data[ctx->pos] == '.') {
        is_float = true;
        ctx->pos++;
        if (at_end(ctx) || ctx->data[ctx->pos] < '0' || ctx->data[ctx->pos] > '9') {
            return FB_JSON_ERR_SYNTAX;
        }
        while (!at_end(ctx) && ctx->data[ctx->pos] >= '0' && ctx->data[ctx->pos] <= '9')
            ctx->pos++;
    }

    if (!at_end(ctx) && (ctx->data[ctx->pos] == 'e' || ctx->data[ctx->pos] == 'E')) {
        is_float = true;
        ctx->pos++;
        if (!at_end(ctx) && (ctx->data[ctx->pos] == '+' || ctx->data[ctx->pos] == '-')) ctx->pos++;
        if (at_end(ctx) || ctx->data[ctx->pos] < '0' || ctx->data[ctx->pos] > '9') {
            return FB_JSON_ERR_SYNTAX;
        }
        while (!at_end(ctx) && ctx->data[ctx->pos] >= '0' && ctx->data[ctx->pos] <= '9')
            ctx->pos++;
    }

    size_t tok_len = ctx->pos - start;
    char *tok = (char *)malloc(tok_len + 1);
    if (tok == NULL) return FB_JSON_ERR_ALLOC;
    memcpy(tok, ctx->data + start, tok_len);
    tok[tok_len] = '\0';

    fb_json_value *v;
    if (is_float) {
        /* Plain strtod follows the process locale and stops at '.' under
         * locales such as de_DE, so parse in the C locale explicitly. */
        if (ctx->c_locale == (locale_t)0) {
            ctx->c_locale = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
            if (ctx->c_locale == (locale_t)0) {
                free(tok);
                return FB_JSON_ERR_ALLOC;
            }
        }
        char *endptr = NULL;
        double d = strtod_l(tok, &endptr, ctx->c_locale);
        bool ok = (endptr == tok + tok_len);
        free(tok);
        if (!ok) return FB_JSON_ERR_SYNTAX;
        if (!isfinite(d)) return FB_JSON_ERR_NUMBER_RANGE;
        v = alloc_value(FB_JSON_TAG_DOUBLE);
        if (v == NULL) return FB_JSON_ERR_ALLOC;
        v->as.d = d;
    } else {
        errno = 0;
        char *endptr = NULL;
        long long ll = strtoll(tok, &endptr, 10);
        bool ok = (endptr == tok + tok_len);
        bool range_err = (errno == ERANGE);
        free(tok);
        if (!ok) return FB_JSON_ERR_SYNTAX;
        if (range_err) return FB_JSON_ERR_NUMBER_RANGE;
        v = alloc_value(FB_JSON_TAG_INT);
        if (v == NULL) return FB_JSON_ERR_ALLOC;
        v->as.i = (int64_t)ll;
    }

    *out = v;
    return FB_JSON_OK;
}

/* Arrays and objects */

static fb_json_status parse_array(parse_ctx *ctx, size_t depth, fb_json_value **out) {
    ctx->pos++; /* consume '[' */
    fb_json_value *v = alloc_value(FB_JSON_TAG_ARRAY);
    if (v == NULL) return FB_JSON_ERR_ALLOC;

    size_t cap = 0;

    skip_ws(ctx);
    if (peek(ctx) == ']') {
        ctx->pos++;
        *out = v;
        return FB_JSON_OK;
    }

    for (;;) {
        skip_ws(ctx);
        fb_json_value *item = NULL;
        fb_json_status st = parse_value(ctx, depth, &item);
        if (st != FB_JSON_OK) {
            fb_json_free(v);
            return st;
        }
        if (v->as.arr.count == cap) {
            size_t new_cap = cap == 0 ? 4 : cap * 2;
            fb_json_value **n =
                (fb_json_value **)realloc(v->as.arr.items, new_cap * sizeof(fb_json_value *));
            if (n == NULL) {
                fb_json_free(item);
                fb_json_free(v);
                return FB_JSON_ERR_ALLOC;
            }
            v->as.arr.items = n;
            cap = new_cap;
        }
        v->as.arr.items[v->as.arr.count++] = item;

        skip_ws(ctx);
        int c = peek(ctx);
        if (c == ',') {
            ctx->pos++;
            continue;
        }
        if (c == ']') {
            ctx->pos++;
            break;
        }
        fb_json_free(v);
        return FB_JSON_ERR_SYNTAX;
    }

    *out = v;
    return FB_JSON_OK;
}

static fb_json_status parse_object(parse_ctx *ctx, size_t depth, fb_json_value **out) {
    ctx->pos++; /* consume '{' */
    fb_json_value *v = alloc_value(FB_JSON_TAG_OBJECT);
    if (v == NULL) return FB_JSON_ERR_ALLOC;

    size_t cap = 0;

    skip_ws(ctx);
    if (peek(ctx) == '}') {
        ctx->pos++;
        *out = v;
        return FB_JSON_OK;
    }

    for (;;) {
        skip_ws(ctx);
        if (peek(ctx) != '"') {
            fb_json_free(v);
            return FB_JSON_ERR_SYNTAX;
        }
        char *key = NULL;
        size_t key_len = 0;
        fb_json_status st = parse_string_raw(ctx, &key, &key_len);
        if (st != FB_JSON_OK) {
            fb_json_free(v);
            return st;
        }

        for (size_t i = 0; i < v->as.obj.count; i++) {
            if (v->as.obj.key_lens[i] == key_len && memcmp(v->as.obj.keys[i], key, key_len) == 0) {
                free(key);
                fb_json_free(v);
                return FB_JSON_ERR_DUPLICATE_KEY;
            }
        }

        skip_ws(ctx);
        if (peek(ctx) != ':') {
            free(key);
            fb_json_free(v);
            return FB_JSON_ERR_SYNTAX;
        }
        ctx->pos++;
        skip_ws(ctx);

        fb_json_value *val = NULL;
        st = parse_value(ctx, depth, &val);
        if (st != FB_JSON_OK) {
            free(key);
            fb_json_free(v);
            return st;
        }

        if (v->as.obj.count == cap) {
            size_t new_cap = cap == 0 ? 4 : cap * 2;
            char **nk = (char **)realloc(v->as.obj.keys, new_cap * sizeof(char *));
            size_t *nkl = (size_t *)realloc(v->as.obj.key_lens, new_cap * sizeof(size_t));
            fb_json_value **nv =
                (fb_json_value **)realloc(v->as.obj.values, new_cap * sizeof(fb_json_value *));
            if (nk == NULL || nkl == NULL || nv == NULL) {
                /* Preserve successful reallocations so fb_json_free() owns the
                 * current pointers. key and val have not been attached yet. */
                if (nk != NULL) v->as.obj.keys = nk;
                if (nkl != NULL) v->as.obj.key_lens = nkl;
                if (nv != NULL) v->as.obj.values = nv;
                free(key);
                fb_json_free(val);
                fb_json_free(v);
                return FB_JSON_ERR_ALLOC;
            }
            v->as.obj.keys = nk;
            v->as.obj.key_lens = nkl;
            v->as.obj.values = nv;
            cap = new_cap;
        }
        v->as.obj.keys[v->as.obj.count] = key;
        v->as.obj.key_lens[v->as.obj.count] = key_len;
        v->as.obj.values[v->as.obj.count] = val;
        v->as.obj.count++;

        skip_ws(ctx);
        int c = peek(ctx);
        if (c == ',') {
            ctx->pos++;
            continue;
        }
        if (c == '}') {
            ctx->pos++;
            break;
        }
        fb_json_free(v);
        return FB_JSON_ERR_SYNTAX;
    }

    *out = v;
    return FB_JSON_OK;
}

/* Values */

static fb_json_status parse_value(parse_ctx *ctx, size_t depth, fb_json_value **out) {
    skip_ws(ctx);
    int c = peek(ctx);
    if (c < 0) return FB_JSON_ERR_SYNTAX;

    switch (c) {
    case '{':
    case '[':
        if (depth + 1 > ctx->max_depth) return FB_JSON_ERR_DEPTH;
        return c == '{' ? parse_object(ctx, depth + 1, out) : parse_array(ctx, depth + 1, out);
    case '"': {
        char *s = NULL;
        size_t slen = 0;
        fb_json_status st = parse_string_raw(ctx, &s, &slen);
        if (st != FB_JSON_OK) return st;
        fb_json_value *v = alloc_value(FB_JSON_TAG_STRING);
        if (v == NULL) {
            free(s);
            return FB_JSON_ERR_ALLOC;
        }
        v->as.str.ptr = s;
        v->as.str.len = slen;
        *out = v;
        return FB_JSON_OK;
    }
    case 't':
        if (ctx->pos + 4 <= ctx->len && memcmp(ctx->data + ctx->pos, "true", 4) == 0) {
            ctx->pos += 4;
            fb_json_value *v = alloc_value(FB_JSON_TAG_BOOL);
            if (v == NULL) return FB_JSON_ERR_ALLOC;
            v->as.b = true;
            *out = v;
            return FB_JSON_OK;
        }
        return FB_JSON_ERR_SYNTAX;
    case 'f':
        if (ctx->pos + 5 <= ctx->len && memcmp(ctx->data + ctx->pos, "false", 5) == 0) {
            ctx->pos += 5;
            fb_json_value *v = alloc_value(FB_JSON_TAG_BOOL);
            if (v == NULL) return FB_JSON_ERR_ALLOC;
            v->as.b = false;
            *out = v;
            return FB_JSON_OK;
        }
        return FB_JSON_ERR_SYNTAX;
    case 'n':
        if (ctx->pos + 4 <= ctx->len && memcmp(ctx->data + ctx->pos, "null", 4) == 0) {
            ctx->pos += 4;
            fb_json_value *v = alloc_value(FB_JSON_TAG_NULL);
            if (v == NULL) return FB_JSON_ERR_ALLOC;
            *out = v;
            return FB_JSON_OK;
        }
        return FB_JSON_ERR_SYNTAX;
    case '-':
        return parse_number(ctx, out);
    default:
        if (c >= '0' && c <= '9') return parse_number(ctx, out);
        return FB_JSON_ERR_SYNTAX;
    }
}

/* Parser entry point */

fb_json_status fb_json_parse(
    const uint8_t *utf8,
    size_t len,
    const fb_json_parse_options *opts,
    fb_json_value **out
) {
    if (out == NULL || opts == NULL) return FB_JSON_ERR_SYNTAX;
    *out = NULL;

    if (len > opts->max_bytes) return FB_JSON_ERR_TOO_LARGE;
    if (len > 0 && utf8 == NULL) return FB_JSON_ERR_SYNTAX;

    parse_ctx ctx = { utf8, len, 0, opts->max_depth, (locale_t)0 };

    fb_json_value *root = NULL;
    fb_json_status st = parse_value(&ctx, 0, &root);
    if (ctx.c_locale != (locale_t)0) freelocale(ctx.c_locale);
    if (st != FB_JSON_OK) return st;

    skip_ws(&ctx);
    if (!at_end(&ctx)) {
        fb_json_free(root);
        return FB_JSON_ERR_TRAILING_DATA;
    }

    if (opts->require_object_root && root->tag != FB_JSON_TAG_OBJECT) {
        fb_json_free(root);
        return FB_JSON_ERR_NOT_OBJECT;
    }

    *out = root;
    return FB_JSON_OK;
}

const fb_json_value *fb_json_object_find(const fb_json_value *object, const char *key) {
    if (!fb_json_is_object(object) || key == NULL) return NULL;
    size_t key_len = strlen(key);
    for (size_t i = 0; i < object->as.obj.count; i++) {
        if (object->as.obj.key_lens[i] == key_len &&
            memcmp(object->as.obj.keys[i], key, key_len) == 0) {
            return object->as.obj.values[i];
        }
    }
    return NULL;
}

/* Public JSON accessors */

forgebit_json_type forgebit_json_type_of(const forgebit_json_value *value) {
    if (value == NULL) return FORGEBIT_JSON_NULL;
    switch (value->tag) {
    case FB_JSON_TAG_NULL:
        return FORGEBIT_JSON_NULL;
    case FB_JSON_TAG_BOOL:
        return FORGEBIT_JSON_BOOL;
    case FB_JSON_TAG_INT:
        return FORGEBIT_JSON_INTEGER;
    case FB_JSON_TAG_DOUBLE:
        return FORGEBIT_JSON_NUMBER;
    case FB_JSON_TAG_STRING:
        return FORGEBIT_JSON_STRING;
    case FB_JSON_TAG_ARRAY:
        return FORGEBIT_JSON_ARRAY;
    case FB_JSON_TAG_OBJECT:
        return FORGEBIT_JSON_OBJECT;
    }
    return FORGEBIT_JSON_NULL;
}

bool forgebit_json_get_bool(const forgebit_json_value *value, bool *out) {
    if (value == NULL || out == NULL || value->tag != FB_JSON_TAG_BOOL) return false;
    *out = value->as.b;
    return true;
}

bool forgebit_json_get_integer(const forgebit_json_value *value, int64_t *out) {
    if (value == NULL || out == NULL || value->tag != FB_JSON_TAG_INT) return false;
    *out = value->as.i;
    return true;
}

bool forgebit_json_get_number(const forgebit_json_value *value, double *out) {
    if (value == NULL || out == NULL) return false;
    if (value->tag == FB_JSON_TAG_DOUBLE) {
        *out = value->as.d;
        return true;
    }
    if (value->tag == FB_JSON_TAG_INT) {
        *out = (double)value->as.i;
        return true;
    }
    return false;
}

bool forgebit_json_get_string(
    const forgebit_json_value *value,
    const char **out_utf8,
    size_t *out_len
) {
    if (value == NULL || out_utf8 == NULL || out_len == NULL || value->tag != FB_JSON_TAG_STRING)
        return false;
    *out_utf8 = value->as.str.ptr;
    *out_len = value->as.str.len;
    return true;
}

size_t forgebit_json_array_length(const forgebit_json_value *value) {
    if (value == NULL || value->tag != FB_JSON_TAG_ARRAY) return 0;
    return value->as.arr.count;
}

const forgebit_json_value *forgebit_json_array_get(const forgebit_json_value *value, size_t index) {
    if (value == NULL || value->tag != FB_JSON_TAG_ARRAY || index >= value->as.arr.count)
        return NULL;
    return value->as.arr.items[index];
}

size_t forgebit_json_object_size(const forgebit_json_value *value) {
    if (value == NULL || value->tag != FB_JSON_TAG_OBJECT) return 0;
    return value->as.obj.count;
}

const forgebit_json_value *forgebit_json_object_get(
    const forgebit_json_value *value,
    const char *key
) {
    return fb_json_object_find(value, key);
}

bool forgebit_json_object_key_at(
    const forgebit_json_value *value,
    size_t index,
    const char **out_key,
    size_t *out_len
) {
    if (value == NULL || value->tag != FB_JSON_TAG_OBJECT || index >= value->as.obj.count)
        return false;
    if (out_key != NULL) *out_key = value->as.obj.keys[index];
    if (out_len != NULL) *out_len = value->as.obj.key_lens[index];
    return true;
}

const forgebit_json_value *forgebit_json_object_value_at(
    const forgebit_json_value *value,
    size_t index
) {
    if (value == NULL || value->tag != FB_JSON_TAG_OBJECT || index >= value->as.obj.count)
        return NULL;
    return value->as.obj.values[index];
}
