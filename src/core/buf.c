#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "apex/buf.h"

apex_buf_t *apex_create_temp_buf(apex_pool_t *pool, size_t size) {
    if (pool == NULL) {
        return NULL;
    }

    apex_buf_t *b = (apex_buf_t *)apex_pcalloc(pool, sizeof(apex_buf_t));
    if (b == NULL) {
        return NULL;
    }

    if (size > 0) {
        b->start = (uint8_t *)apex_palloc(pool, size);
        if (b->start == NULL) {
            return NULL;
        }
        b->pos = b->start;
        b->last = b->start;
        b->end = b->start + size;
        b->temporary = true;
        b->memory = true;
    }

    b->file_fd = -1;
    return b;
}

apex_chain_t *apex_alloc_chain_link(apex_pool_t *pool) {
    if (pool == NULL) {
        return NULL;
    }
    return (apex_chain_t *)apex_pcalloc(pool, sizeof(apex_chain_t));
}

apex_chain_t *apex_chain_append(apex_pool_t *pool, apex_chain_t **chain_tail, apex_buf_t *buf) {
    if (pool == NULL || chain_tail == NULL || buf == NULL) {
        return NULL;
    }

    apex_chain_t *cl = apex_alloc_chain_link(pool);
    if (cl == NULL) {
        return NULL;
    }
    cl->buf = buf;
    cl->next = NULL;

    if (*chain_tail != NULL) {
        (*chain_tail)->next = cl;
    }
    *chain_tail = cl;

    return cl;
}

size_t apex_buf_size(const apex_buf_t *b) {
    if (b == NULL) {
        return 0;
    }
    if (b->in_file) {
        return b->file_last > b->file_pos ? (size_t)(b->file_last - b->file_pos) : 0;
    }
    return b->last > b->pos ? (size_t)(b->last - b->pos) : 0;
}

size_t apex_chain_size(const apex_chain_t *chain) {
    size_t total = 0;
    for (const apex_chain_t *cl = chain; cl != NULL; cl = cl->next) {
        total += apex_buf_size(cl->buf);
    }
    return total;
}
