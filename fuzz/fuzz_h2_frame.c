#include "core/internal.h"
#include <nghttp2/nghttp2.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        return 0;
    }

    apex_app_t dummy_app = {0};
    worker_arg_t dummy_worker = {
        .app = &dummy_app,
        .generation = NULL,
        .epoll_fd = -1,
        .listen_fd = -1,
    };
    conn_t dummy_conn = {
        .fd = -1,
    };

    if (h2_connection_create(&dummy_conn, &dummy_worker) != 0) {
        return 0;
    }

    /* Ingest raw HTTP/2 frames, settings, headers, continuation, data */
    h2_feed_data(&dummy_conn, data, size);

    h2_connection_destroy(&dummy_conn);
    return 0;
}
