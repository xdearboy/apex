#ifndef APEX_BUF_H
#define APEX_BUF_H

#include "apex/pool.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct apex_buf_s apex_buf_t;
typedef struct apex_chain_s apex_chain_t;

struct apex_buf_s {
    uint8_t *pos;
    uint8_t *last;
    uint8_t *start;
    uint8_t *end;

    off_t file_pos;
    off_t file_last;
    int file_fd;

    bool temporary;
    bool memory;
    bool in_file;
    bool flush;
    bool last_buf;
    bool last_in_chain;
};

struct apex_chain_s {
    apex_buf_t *buf;
    apex_chain_t *next;
};

apex_buf_t *apex_create_temp_buf(apex_pool_t *pool, size_t size);
apex_chain_t *apex_alloc_chain_link(apex_pool_t *pool);
apex_chain_t *apex_chain_append(apex_pool_t *pool, apex_chain_t **chain_tail, apex_buf_t *buf);
size_t apex_buf_size(const apex_buf_t *b);
size_t apex_chain_size(const apex_chain_t *chain);

#endif /* APEX_BUF_H */
