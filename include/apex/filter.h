#ifndef APEX_FILTER_H
#define APEX_FILTER_H

#include "apex/pool.h"
#include "apex/buf.h"
#include "apex/config.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define APEX_FILTER_OK 0
#define APEX_FILTER_ERROR (-1)
#define APEX_FILTER_DONE (-2)

#define APEX_MAX_FILTERS 32u

typedef struct conn conn_t;
typedef struct apex_res apex_res_t;
typedef struct apex_filter_ctx apex_filter_ctx_t;

typedef int (*apex_header_filter_pt)(apex_filter_ctx_t *ctx);
typedef int (*apex_body_filter_pt)(apex_filter_ctx_t *ctx, apex_chain_t **in);

struct apex_filter_ctx {
    conn_t *conn;
    apex_pool_t *pool;
    const apex_server_config_t *server;
    const apex_location_config_t *location;
    const apex_runtime_t *runtime;

    int status;
    const char *reason;
    int64_t content_length_n; /* -1 if unknown or chunked */
    const char *content_type;
    size_t content_type_len;

    /* Formatted header buffer */
    char *headers_out;
    size_t headers_out_len;
    size_t headers_out_cap;

    /* Extra headers to append */
    const char *extra_headers;
    size_t extra_headers_len;

    /* Flags */
    bool is_head;
    bool no_body;
    bool header_sent;
    bool last_buf_sent;

    /* Chain accumulator */
    apex_chain_t *out_chain;
};

void apex_filter_init(void);
int apex_register_header_filter(apex_header_filter_pt filter);
int apex_register_body_filter(apex_body_filter_pt filter);

int apex_http_send_header(apex_filter_ctx_t *ctx);
int apex_http_output_filter(apex_filter_ctx_t *ctx, apex_chain_t *in);

apex_filter_ctx_t *apex_create_filter_ctx(conn_t *conn, apex_pool_t *pool, int status, const char *reason);
void apex_destroy_filter_ctx(apex_filter_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* APEX_FILTER_H */
