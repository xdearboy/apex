#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "apex/filter.h"
#include "apex/pool.h"
#include "apex/buf.h"
#include "internal.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_custom_header_filter_called = 0;
static int g_custom_body_filter_called = 0;

static int custom_test_header_filter(apex_filter_ctx_t *ctx) {
    g_custom_header_filter_called++;
    /* Prepend custom extra header */
    if (ctx->extra_headers == NULL) {
        ctx->extra_headers = "X-Apex-Custom: FilterChain\r\n";
        ctx->extra_headers_len = strlen(ctx->extra_headers);
    }
    return APEX_FILTER_OK;
}

static int custom_test_body_filter(apex_filter_ctx_t *ctx, apex_chain_t **in) {
    (void)ctx;
    g_custom_body_filter_called++;
    if (in == NULL || *in == NULL) {
        return APEX_FILTER_OK;
    }
    for (apex_chain_t *cl = *in; cl != NULL; cl = cl->next) {
        if (cl->buf != NULL && cl->buf->pos != NULL && cl->buf->last != NULL) {
            /* Touch bytes in buffer */
            for (uint8_t *p = cl->buf->pos; p < cl->buf->last; p++) {
                if (*p >= 'a' && *p <= 'z') {
                    *p = (uint8_t)(*p - 32); /* Uppercase transform in filter */
                }
            }
        }
    }
    return APEX_FILTER_OK;
}

static void test_filter_basic(void) {
    apex_pool_t *pool = apex_pool_create(4096);
    assert(pool != NULL);

    conn_t conn = {0};
    conn.fd = -1;
    conn.is_virtual = 1;
    conn.transport = APEX_TRANSPORT_PLAIN;

    apex_filter_ctx_t *ctx = apex_create_filter_ctx(&conn, pool, 200, "OK");
    assert(ctx != NULL);
    assert(ctx->pool == pool);
    assert(ctx->status == 200);
    assert(strcmp(ctx->reason, "OK") == 0);

    ctx->content_length_n = 13;
    ctx->content_type = "text/plain";
    ctx->content_type_len = strlen(ctx->content_type);

    int rc = apex_http_send_header(ctx);
    assert(rc == APEX_FILTER_OK);
    assert(ctx->header_sent == true);
    assert(ctx->headers_out != NULL);
    assert(strstr(ctx->headers_out, "HTTP/1.1 200 OK\r\n") != NULL);
    assert(strstr(ctx->headers_out, "Server: apex\r\n") != NULL);
    assert(strstr(ctx->headers_out, "Content-Length: 13\r\n") != NULL);
    assert(strstr(ctx->headers_out, "Content-Type: text/plain\r\n") != NULL);

    apex_pool_destroy(pool);
    printf("test_filter_basic: PASSED\n");
}

static void test_filter_chaining_and_transformation(void) {
    apex_filter_init();
    int rc1 = apex_register_header_filter(custom_test_header_filter);
    assert(rc1 == APEX_FILTER_OK);
    int rc2 = apex_register_body_filter(custom_test_body_filter);
    assert(rc2 == APEX_FILTER_OK);

    apex_pool_t *pool = apex_pool_create(4096);
    assert(pool != NULL);

    conn_t conn = {0};
    conn.fd = -1;
    conn.is_virtual = 1;
    conn.transport = APEX_TRANSPORT_PLAIN;

    apex_filter_ctx_t *ctx = apex_create_filter_ctx(&conn, pool, 200, "OK");
    assert(ctx != NULL);
    ctx->content_length_n = 11;

    /* Prepare buffer chain with lowercase text "hello world" */
    char raw_text[] = "hello world";
    apex_buf_t *buf = apex_create_temp_buf(pool, 32);
    assert(buf != NULL);
    memcpy(buf->pos, raw_text, 11);
    buf->last = buf->pos + 11;
    buf->last_buf = 1;

    apex_chain_t *chain = apex_alloc_chain_link(pool);
    assert(chain != NULL);
    chain->buf = buf;
    chain->next = NULL;

    int rc_out = apex_http_output_filter(ctx, chain);
    assert(rc_out == APEX_FILTER_OK);
    assert(g_custom_header_filter_called > 0);
    assert(g_custom_body_filter_called > 0);
    assert(ctx->header_sent == true);
    assert(strstr(ctx->headers_out, "X-Apex-Custom: FilterChain\r\n") != NULL);

    /* Verify custom body filter converted text to uppercase in-place */
    assert(memcmp(buf->start, "HELLO WORLD", 11) == 0);

    /* Verify connection write buffer captured the uppercase output */
    assert(conn.write_length > 0);
    assert(memcmp(conn.write_buffer + conn.write_length - 11, "HELLO WORLD", 11) == 0);

    apex_pool_destroy(pool);
    printf("test_filter_chaining_and_transformation: PASSED\n");
}

static void test_filter_head_suppression(void) {
    apex_pool_t *pool = apex_pool_create(4096);
    assert(pool != NULL);

    conn_t conn = {0};
    conn.fd = -1;
    conn.is_virtual = 1;
    conn.transport = APEX_TRANSPORT_PLAIN;

    apex_filter_ctx_t *ctx = apex_create_filter_ctx(&conn, pool, 200, "OK");
    assert(ctx != NULL);
    ctx->is_head = true;
    ctx->content_length_n = 100;

    apex_buf_t *buf = apex_create_temp_buf(pool, 64);
    assert(buf != NULL);
    buf->last = buf->pos + 30;

    apex_chain_t *chain = apex_alloc_chain_link(pool);
    chain->buf = buf;
    chain->next = NULL;

    uint32_t len_before = conn.write_length;
    int rc = apex_http_output_filter(ctx, chain);
    assert(rc == APEX_FILTER_OK);
    assert(ctx->header_sent == true);

    /* Verify headers sent, but no body data added */
    uint32_t header_len = conn.write_length - len_before;
    assert(header_len > 0);
    assert(strstr((char *)conn.write_buffer + len_before, "Content-Length: 100\r\n") != NULL);
    assert(conn.write_length == len_before + header_len);

    apex_pool_destroy(pool);
    printf("test_filter_head_suppression: PASSED\n");
}

static void test_filter_rfc9112_framing(void) {
    apex_pool_t *pool = apex_pool_create(4096);
    assert(pool != NULL);

    conn_t conn = {0};
    conn.fd = -1;
    conn.is_virtual = 1;
    conn.transport = APEX_TRANSPORT_PLAIN;

    /* 1. Test 204 No Content suppresses Content-Length even if content_length_n == 0 */
    apex_filter_ctx_t *ctx_204 = apex_create_filter_ctx(&conn, pool, 204, "No Content");
    assert(ctx_204 != NULL);
    ctx_204->content_length_n = 0;
    int rc = apex_http_send_header(ctx_204);
    assert(rc == APEX_FILTER_OK);
    assert(strstr(ctx_204->headers_out, "HTTP/1.1 204 No Content\r\n") != NULL);
    assert(strstr(ctx_204->headers_out, "Content-Length:") == NULL);

    /* 2. Test streaming body (content_length_n < 0) emits Transfer-Encoding: chunked */
    conn.write_length = 0;
    apex_filter_ctx_t *ctx_stream = apex_create_filter_ctx(&conn, pool, 200, "OK");
    assert(ctx_stream != NULL);
    ctx_stream->content_length_n = -1;
    rc = apex_http_send_header(ctx_stream);
    assert(rc == APEX_FILTER_OK);
    assert(strstr(ctx_stream->headers_out, "Transfer-Encoding: chunked\r\n") != NULL);

    apex_pool_destroy(pool);
    printf("test_filter_rfc9112_framing: PASSED\n");
}

static void test_filter_null_pool_lifecycle(void) {
    conn_t conn = {0};
    conn.fd = -1;
    conn.is_virtual = 1;
    conn.transport = APEX_TRANSPORT_PLAIN;

    /* Create without pool */
    apex_filter_ctx_t *ctx = apex_create_filter_ctx(&conn, NULL, 200, "OK");
    assert(ctx != NULL);
    assert(ctx->pool == NULL);
    ctx->content_length_n = 5;

    int rc = apex_http_send_header(ctx);
    assert(rc == APEX_FILTER_OK);
    assert(ctx->headers_out != NULL);

    /* Free safely without leaks */
    apex_destroy_filter_ctx(ctx);
    printf("test_filter_null_pool_lifecycle: PASSED\n");
}

int main(void) {
    printf("Running Apex Streaming Filter Chains Test Suite...\n");
    test_filter_basic();
    test_filter_chaining_and_transformation();
    test_filter_head_suppression();
    test_filter_rfc9112_framing();
    test_filter_null_pool_lifecycle();
    printf("ALL FILTER TESTS PASSED!\n");
    return 0;
}
