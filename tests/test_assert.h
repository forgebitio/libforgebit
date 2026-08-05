#ifndef FORGEBIT_TEST_ASSERT_H
#define FORGEBIT_TEST_ASSERT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fb_test_failures = 0;
static const char *fb_test_current_name = "";

#define FB_TEST_CASE(name) static void name(void)

#define FB_RUN_TEST(name)               \
    do {                                \
        fb_test_current_name = #name;   \
        printf("  %-40s", #name);       \
        int before = fb_test_failures;  \
        name();                         \
        if (fb_test_failures == before) \
            printf("ok\n");             \
        else                            \
            printf("FAILED\n");         \
    } while (0)

#define FB_ASSERT_TRUE(cond)                                                                  \
    do {                                                                                      \
        if (!(cond)) {                                                                        \
            fb_test_failures++;                                                               \
            fprintf(stderr, "    assertion failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
        }                                                                                     \
    } while (0)

#define FB_ASSERT_FALSE(cond) FB_ASSERT_TRUE(!(cond))

#define FB_ASSERT_EQ_INT(actual, expected)                    \
    do {                                                      \
        long long a_ = (long long)(actual);                   \
        long long e_ = (long long)(expected);                 \
        if (a_ != e_) {                                       \
            fb_test_failures++;                               \
            fprintf(                                          \
                stderr,                                       \
                "    %s:%d: expected %s == %lld, got %lld\n", \
                __FILE__,                                     \
                __LINE__,                                     \
                #actual,                                      \
                e_,                                           \
                a_                                            \
            );                                                \
        }                                                     \
    } while (0)

#define FB_ASSERT_STR_EQ(actual, expected)                        \
    do {                                                          \
        const char *a_ = (actual);                                \
        const char *e_ = (expected);                              \
        if (a_ == NULL || e_ == NULL || strcmp(a_, e_) != 0) {    \
            fb_test_failures++;                                   \
            fprintf(                                              \
                stderr,                                           \
                "    %s:%d: expected %s == \"%s\", got \"%s\"\n", \
                __FILE__,                                         \
                __LINE__,                                         \
                #actual,                                          \
                e_ ? e_ : "(null)",                               \
                a_ ? a_ : "(null)"                                \
            );                                                    \
        }                                                         \
    } while (0)

#define FB_TEST_EXIT() return fb_test_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE

#endif /* FORGEBIT_TEST_ASSERT_H */
