#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "apex/pool.h"

#include <stdlib.h>
#include <string.h>

#define APEX_POOL_MAX_ALLOC_FROM_POOL (4096u - 1u)

static void *apex_palloc_block(apex_pool_t *pool, size_t size);
static void *apex_palloc_large(apex_pool_t *pool, size_t size);

apex_pool_t *apex_pool_create(size_t size) {
    if (size < sizeof(apex_pool_t) + APEX_POOL_ALIGNMENT) {
        size = APEX_POOL_DEFAULT_SIZE;
    }
    size = size & ~((size_t)APEX_POOL_ALIGNMENT - 1u);

    void *mem = NULL;
    if (posix_memalign(&mem, APEX_POOL_ALIGNMENT, size) != 0 || mem == NULL) {
        return NULL;
    }

    apex_pool_t *pool = (apex_pool_t *)mem;
    uint8_t *first_avail = (uint8_t *)mem + sizeof(apex_pool_t);
    first_avail = (uint8_t *)apex_align_ptr(first_avail, APEX_POOL_ALIGNMENT);

    pool->first_block.last = first_avail;
    pool->first_block.end = (uint8_t *)mem + size;
    pool->first_block.next = NULL;
    pool->first_block.failed = 0;

    size_t usable = pool->first_block.end >= pool->first_block.last
                        ? (size_t)(pool->first_block.end - pool->first_block.last)
                        : 0;
    pool->max = usable < APEX_POOL_MAX_ALLOC_FROM_POOL ? usable : APEX_POOL_MAX_ALLOC_FROM_POOL;

    pool->current = &pool->first_block;
    pool->large = NULL;
    pool->cleanup = NULL;

    return pool;
}

void apex_pool_destroy(apex_pool_t *pool) {
    if (pool == NULL) {
        return;
    }

    /* Run cleanups */
    for (apex_pool_cleanup_t *c = pool->cleanup; c != NULL; c = c->next) {
        if (c->handler != NULL) {
            c->handler(c->data);
        }
    }

    /* Free large allocations */
    for (apex_pool_large_t *l = pool->large; l != NULL; l = l->next) {
        if (l->alloc != NULL) {
            free(l->alloc);
        }
    }

    /* Free secondary blocks */
    apex_pool_block_t *block = pool->first_block.next;
    while (block != NULL) {
        apex_pool_block_t *next = block->next;
        free(block);
        block = next;
    }

    /* Free primary block (which holds apex_pool_t) */
    free(pool);
}

void apex_pool_reset(apex_pool_t *pool) {
    if (pool == NULL) {
        return;
    }

    /* Run and reset cleanups */
    for (apex_pool_cleanup_t *c = pool->cleanup; c != NULL; c = c->next) {
        if (c->handler != NULL) {
            c->handler(c->data);
        }
    }
    pool->cleanup = NULL;

    /* Free large allocations */
    for (apex_pool_large_t *l = pool->large; l != NULL; l = l->next) {
        if (l->alloc != NULL) {
            free(l->alloc);
        }
    }
    pool->large = NULL;

    /* Reset primary block */
    uint8_t *first_avail = (uint8_t *)pool + sizeof(apex_pool_t);
    first_avail = (uint8_t *)apex_align_ptr(first_avail, APEX_POOL_ALIGNMENT);
    pool->first_block.last = first_avail;
    pool->first_block.failed = 0;

    /* Reset secondary blocks */
    for (apex_pool_block_t *b = pool->first_block.next; b != NULL; b = b->next) {
        uint8_t *avail = (uint8_t *)b + sizeof(apex_pool_block_t);
        avail = (uint8_t *)apex_align_ptr(avail, APEX_POOL_ALIGNMENT);
        b->last = avail;
        b->failed = 0;
    }

    pool->current = &pool->first_block;
}

void *apex_palloc(apex_pool_t *pool, size_t size) {
    if (pool == NULL || size == 0) {
        return NULL;
    }

    if (size <= pool->max) {
        apex_pool_block_t *block = pool->current;
        do {
            uint8_t *m = (uint8_t *)apex_align_ptr(block->last, APEX_POOL_ALIGNMENT);
            if (block->end >= m && (size_t)(block->end - m) >= size) {
                block->last = m + size;
                return m;
            }
            block = block->next;
        } while (block != NULL);

        return apex_palloc_block(pool, size);
    }

    return apex_palloc_large(pool, size);
}

void *apex_pnalloc(apex_pool_t *pool, size_t size) {
    if (pool == NULL || size == 0) {
        return NULL;
    }

    if (size <= pool->max) {
        apex_pool_block_t *block = pool->current;
        do {
            uint8_t *m = block->last;
            if (block->end >= m && (size_t)(block->end - m) >= size) {
                block->last = m + size;
                return m;
            }
            block = block->next;
        } while (block != NULL);

        return apex_palloc_block(pool, size);
    }

    return apex_palloc_large(pool, size);
}

static void *apex_palloc_block(apex_pool_t *pool, size_t size) {
    size_t psize = (size_t)(pool->first_block.end - (uint8_t *)pool);
    psize = psize & ~((size_t)APEX_POOL_ALIGNMENT - 1u);
    void *mem = NULL;

    if (posix_memalign(&mem, APEX_POOL_ALIGNMENT, psize) != 0 || mem == NULL) {
        return NULL;
    }

    apex_pool_block_t *new_block = (apex_pool_block_t *)mem;
    new_block->end = (uint8_t *)mem + psize;
    new_block->next = NULL;
    new_block->failed = 0;

    uint8_t *m = (uint8_t *)mem + sizeof(apex_pool_block_t);
    m = (uint8_t *)apex_align_ptr(m, APEX_POOL_ALIGNMENT);
    new_block->last = m + size;

    apex_pool_block_t *block = pool->current;
    for (; block->next != NULL; block = block->next) {
        if (block->failed++ > 4) {
            pool->current = block->next;
        }
    }
    block->next = new_block;

    return m;
}

static void *apex_palloc_large(apex_pool_t *pool, size_t size) {
    void *p = malloc(size);
    if (p == NULL) {
        return NULL;
    }

    /* Reuse any freed large slots if present */
    size_t checked = 0;
    for (apex_pool_large_t *l = pool->large; l != NULL; l = l->next) {
        if (l->alloc == NULL) {
            l->alloc = p;
            return p;
        }
        if (checked++ > 3) {
            break;
        }
    }

    /* Allocate large wrapper from pool itself */
    apex_pool_large_t *large = (apex_pool_large_t *)apex_palloc(pool, sizeof(apex_pool_large_t));
    if (large == NULL) {
        free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}

void *apex_pcalloc(apex_pool_t *pool, size_t size) {
    void *p = apex_palloc(pool, size);
    if (p != NULL) {
        memset(p, 0, size);
    }
    return p;
}

void *apex_pmemalign(apex_pool_t *pool, size_t size, size_t alignment) {
    if (pool == NULL || size == 0) {
        return NULL;
    }

    void *p = NULL;
    if (posix_memalign(&p, alignment, size) != 0 || p == NULL) {
        return NULL;
    }

    apex_pool_large_t *large = (apex_pool_large_t *)apex_palloc(pool, sizeof(apex_pool_large_t));
    if (large == NULL) {
        free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}

int apex_pfree(apex_pool_t *pool, void *p) {
    if (pool == NULL || p == NULL) {
        return -1;
    }

    for (apex_pool_large_t *l = pool->large; l != NULL; l = l->next) {
        if (l->alloc == p) {
            free(l->alloc);
            l->alloc = NULL;
            return 0;
        }
    }

    return -1;
}

char *apex_pstrdup(apex_pool_t *pool, const char *src) {
    if (src == NULL) {
        return NULL;
    }
    size_t len = strlen(src);
    char *dst = (char *)apex_pnalloc(pool, len + 1);
    if (dst != NULL) {
        memcpy(dst, src, len);
        dst[len] = '\0';
    }
    return dst;
}

char *apex_pstrndup(apex_pool_t *pool, const char *src, size_t n) {
    if (src == NULL) {
        return NULL;
    }
    size_t len = 0;
    while (len < n && src[len] != '\0') {
        len++;
    }
    char *dst = (char *)apex_pnalloc(pool, len + 1);
    if (dst != NULL) {
        memcpy(dst, src, len);
        dst[len] = '\0';
    }
    return dst;
}

apex_pool_cleanup_t *apex_pool_cleanup_add(apex_pool_t *pool, size_t size) {
    if (pool == NULL) {
        return NULL;
    }

    apex_pool_cleanup_t *c = (apex_pool_cleanup_t *)apex_palloc(pool, sizeof(apex_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size > 0) {
        c->data = apex_palloc(pool, size);
        if (c->data == NULL) {
            return NULL;
        }
    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next = pool->cleanup;
    pool->cleanup = c;

    return c;
}
