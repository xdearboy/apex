#ifndef WORKER_H
#define WORKER_H

#include "tachyon.h"

enum { REQUEST_UNKNOWN, REQUEST_STATIC, REQUEST_STATS };

typedef struct {
    uint8_t in_use;
    uint8_t want_write;
    uint8_t closing;
    uint8_t mstate;
    uint8_t request_kind;
    uint8_t request_pos;
    uint8_t handshake_done;
    uint8_t ktls_tx;
    uint8_t ktls_rx;
    time_t  last_active;
    size_t  pending;
    size_t  off;
    SSL     *ssl;
} conn_t;

void worker_init_batch(void);
void worker_run(int listen_fd, int cpu, int worker_id, int conn_cap);

#endif /* WORKER_H */
