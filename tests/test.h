#ifndef TACHYON_TEST_H
#define TACHYON_TEST_H

#include <stdio.h>

static int test_failures;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        test_failures++; \
    } \
} while (0)

#define TEST_REPORT(name) do { \
    if (test_failures) { \
        fprintf(stderr, "%s: %d checks failed\n", (name), test_failures); \
        return 1; \
    } \
    printf("%s: ok\n", (name)); \
    return 0; \
} while (0)

#endif
