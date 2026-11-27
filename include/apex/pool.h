#ifndef APEX_POOL_H
#define APEX_POOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define APEX_POOL_DEFAULT_SIZE (4096u)
#define APEX_POOL_ALIGNMENT    (sizeof(unsigned long))

/* Align pointer up to the nearest multiple of alignment */
#define apex_align_ptr(p, a) \
    (void *)(((uintptr_t)(p) + ((uintptr_t)(a) - 1)) & ~((uintptr_t)(a) - 1))

typedef void (*apex_pool_cleanup_pt)(void *data);

typedef struct apex_pool_cleanup_s apex_pool_cleanup_t;
struct apex_pool_cleanup_s {
    apex_pool_cleanup_pt handler;
    void *data;
    apex_pool_cleanup_t *next;
};

typedef struct apex_pool_large_s apex_pool_large_t;
struct apex_pool_large_s {
    apex_pool_large_t *next;
    void *alloc;
};

typedef struct apex_pool_block_s apex_pool_block_t;
struct apex_pool_block_s {
    uint8_t *last;
    uint8_t *end;
    apex_pool_block_t *next;
    size_t failed;
};

typedef struct apex_pool_s apex_pool_t;
struct apex_pool_s {
    apex_pool_block_t *current;
    apex_pool_large_t *large;
    apex_pool_cleanup_t *cleanup;
    size_t max;
    apex_pool_block_t first_block;
};

apex_pool_t *apex_pool_create(size_t size);
void apex_pool_destroy(apex_pool_t *pool);
void apex_pool_reset(apex_pool_t *pool);

void *apex_palloc(apex_pool_t *pool, size_t size);
void *apex_pnalloc(apex_pool_t *pool, size_t size);
void *apex_pcalloc(apex_pool_t *pool, size_t size);
void *apex_pmemalign(apex_pool_t *pool, size_t size, size_t alignment);
int apex_pfree(apex_pool_t *pool, void *p);

char *apex_pstrdup(apex_pool_t *pool, const char *src);
char *apex_pstrndup(apex_pool_t *pool, const char *src, size_t n);

apex_pool_cleanup_t *apex_pool_cleanup_add(apex_pool_t *pool, size_t size);

#endif /* APEX_POOL_H */
