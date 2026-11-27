#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "apex/pool.h"
#include "apex/buf.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_cleanup_count = 0;

static void dummy_cleanup_one(void *data) {
    int *val = (int *)data;
    if (val != NULL) {
        *val += 10;
    }
    g_cleanup_count++;
}

static void dummy_cleanup_two(void *data) {
    int *val = (int *)data;
    if (val != NULL) {
        *val += 20;
    }
    g_cleanup_count++;
}

static void test_pool_basic(void) {
    apex_pool_t *pool = apex_pool_create(4096);
    assert(pool != NULL);

    void *p1 = apex_palloc(pool, 16);
    assert(p1 != NULL);
    assert(((uintptr_t)p1 % APEX_POOL_ALIGNMENT) == 0);

    void *p2 = apex_palloc(pool, 32);
    assert(p2 != NULL);
    assert(((uintptr_t)p2 % APEX_POOL_ALIGNMENT) == 0);
    assert((uint8_t *)p2 >= (uint8_t *)p1 + 16);

    void *p3 = apex_pcalloc(pool, 64);
    assert(p3 != NULL);
    for (int i = 0; i < 64; i++) {
        assert(((uint8_t *)p3)[i] == 0);
    }

    apex_pool_destroy(pool);
    printf("test_pool_basic: PASSED\n");
}

static void test_pool_block_chaining(void) {
    apex_pool_t *pool = apex_pool_create(1024);
    assert(pool != NULL);

    /* Allocate 50 chunks of 100 bytes each -> 5000 bytes, exceeding 1024-byte block */
    void *ptrs[50];
    for (int i = 0; i < 50; i++) {
        ptrs[i] = apex_palloc(pool, 100);
        assert(ptrs[i] != NULL);
        memset(ptrs[i], (uint8_t)i, 100);
    }

    for (int i = 0; i < 50; i++) {
        for (int j = 0; j < 100; j++) {
            assert(((uint8_t *)ptrs[i])[j] == (uint8_t)i);
        }
    }

    apex_pool_destroy(pool);
    printf("test_pool_block_chaining: PASSED\n");
}

static void test_pool_large_alloc(void) {
    apex_pool_t *pool = apex_pool_create(4096);
    assert(pool != NULL);

    /* Large allocation: 64 KB (> pool->max) */
    size_t large_sz = 64 * 1024;
    void *p_large = apex_palloc(pool, large_sz);
    assert(p_large != NULL);
    memset(p_large, 0xAB, large_sz);

    assert(pool->large != NULL);
    assert(pool->large->alloc == p_large);

    int free_res = apex_pfree(pool, p_large);
    assert(free_res == 0);
    assert(pool->large->alloc == NULL);

    apex_pool_destroy(pool);
    printf("test_pool_large_alloc: PASSED\n");
}

static void test_pool_cleanups_and_reset(void) {
    apex_pool_t *pool = apex_pool_create(4096);
    assert(pool != NULL);

    g_cleanup_count = 0;
    int data1 = 1;
    int data2 = 2;

    apex_pool_cleanup_t *c1 = apex_pool_cleanup_add(pool, 0);
    assert(c1 != NULL);
    c1->handler = dummy_cleanup_one;
    c1->data = &data1;

    apex_pool_cleanup_t *c2 = apex_pool_cleanup_add(pool, 0);
    assert(c2 != NULL);
    c2->handler = dummy_cleanup_two;
    c2->data = &data2;

    /* Reset pool -> cleanups must execute */
    apex_pool_reset(pool);
    assert(g_cleanup_count == 2);
    assert(data1 == 11);
    assert(data2 == 22);
    assert(pool->cleanup == NULL);

    /* Allocate again after reset */
    void *p_after = apex_palloc(pool, 128);
    assert(p_after != NULL);

    apex_pool_destroy(pool);
    printf("test_pool_cleanups_and_reset: PASSED\n");
}

static void test_pool_strings(void) {
    apex_pool_t *pool = apex_pool_create(4096);
    assert(pool != NULL);

    const char *orig = "Apex Reverse Proxy Architecture";
    char *s1 = apex_pstrdup(pool, orig);
    assert(s1 != NULL);
    assert(strcmp(s1, orig) == 0);
    assert(s1 != orig);

    char *s2 = apex_pstrndup(pool, orig, 4);
    assert(s2 != NULL);
    assert(strcmp(s2, "Apex") == 0);

    apex_pool_destroy(pool);
    printf("test_pool_strings: PASSED\n");
}

static void test_buf_and_chains(void) {
    apex_pool_t *pool = apex_pool_create(4096);
    assert(pool != NULL);

    apex_buf_t *b1 = apex_create_temp_buf(pool, 128);
    assert(b1 != NULL);
    assert(b1->temporary == true);
    assert(b1->memory == true);
    memcpy(b1->pos, "Hello ", 6);
    b1->last += 6;
    assert(apex_buf_size(b1) == 6);

    apex_buf_t *b2 = apex_create_temp_buf(pool, 128);
    assert(b2 != NULL);
    memcpy(b2->pos, "World!", 6);
    b2->last += 6;
    assert(apex_buf_size(b2) == 6);

    apex_chain_t *head = NULL;
    apex_chain_t *tail = NULL;
    head = apex_chain_append(pool, &tail, b1);
    assert(head != NULL);
    assert(tail == head);

    apex_chain_append(pool, &tail, b2);
    assert(head->next == tail);
    assert(apex_chain_size(head) == 12);

    apex_pool_destroy(pool);
    printf("test_buf_and_chains: PASSED\n");
}

static void test_pool_unaligned_and_overflow_guard(void) {
    /* Create pool with unaligned size */
    apex_pool_t *pool = apex_pool_create(1027);
    assert(pool != NULL);

    /* Allocate until pool fills up and triggers block chaining */
    for (int i = 0; i < 200; i++) {
        void *p = apex_palloc(pool, 17); /* unaligned allocation size */
        assert(p != NULL);
        assert(((uintptr_t)p % APEX_POOL_ALIGNMENT) == 0);
        memset(p, 0x42, 17);
    }

    apex_pool_destroy(pool);
    printf("test_pool_unaligned_and_overflow_guard: PASSED\n");
}

int main(void) {
    printf("Running Apex Memory Pool & Buffer Chain Test Suite...\n");
    test_pool_basic();
    test_pool_block_chaining();
    test_pool_large_alloc();
    test_pool_cleanups_and_reset();
    test_pool_strings();
    test_buf_and_chains();
    test_pool_unaligned_and_overflow_guard();
    printf("ALL POOL TESTS PASSED!\n");
    return 0;
}
