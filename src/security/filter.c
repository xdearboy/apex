#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "apex/filter.h"
#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

static apex_header_filter_pt s_header_filters[APEX_MAX_FILTERS];
static size_t s_header_filter_count = 0;

static apex_body_filter_pt s_body_filters[APEX_MAX_FILTERS];
static size_t s_body_filter_count = 0;

static pthread_rwlock_t s_filter_lock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_once_t s_filter_once = PTHREAD_ONCE_INIT;

static bool apex_ensure_header_capacity(apex_filter_ctx_t *ctx, size_t needed) {
    if (needed <= ctx->headers_out_cap) {
        return true;
    }
    size_t new_cap = ctx->headers_out_cap ? ctx->headers_out_cap * 2u : 4096u;
    if (new_cap < needed) {
        new_cap = needed + 512u;
    }

    char *new_buf = NULL;
    if (ctx->pool != NULL) {
        new_buf = apex_palloc(ctx->pool, new_cap);
        if (new_buf != NULL && ctx->headers_out != NULL && ctx->headers_out_len > 0) {
            memcpy(new_buf, ctx->headers_out, ctx->headers_out_len);
        }
    } else {
        new_buf = realloc(ctx->headers_out, new_cap);
    }

    if (new_buf == NULL) {
        return false;
    }
    ctx->headers_out = new_buf;
    ctx->headers_out_cap = new_cap;
    return true;
}

static int apex_default_header_filter(apex_filter_ctx_t *ctx) {
    if (ctx == NULL) {
        return APEX_FILTER_ERROR;
    }

    if (ctx->headers_out_cap == 0) {
        if (!apex_ensure_header_capacity(ctx, 4096)) {
            return APEX_FILTER_ERROR;
        }
        ctx->headers_out_len = 0;
    }

    const char *reason = ctx->reason;
    if (reason == NULL) {
        switch (ctx->status) {
        case 200: reason = "OK"; break;
        case 201: reason = "Created"; break;
        case 204: reason = "No Content"; break;
        case 206: reason = "Partial Content"; break;
        case 301: reason = "Moved Permanently"; break;
        case 302: reason = "Found"; break;
        case 304: reason = "Not Modified"; break;
        case 400: reason = "Bad Request"; break;
        case 401: reason = "Unauthorized"; break;
        case 403: reason = "Forbidden"; break;
        case 404: reason = "Not Found"; break;
        case 405: reason = "Method Not Allowed"; break;
        case 412: reason = "Precondition Failed"; break;
        case 413: reason = "Payload Too Large"; break;
        case 416: reason = "Range Not Satisfiable"; break;
        case 429: reason = "Too Many Requests"; break;
        case 431: reason = "Request Header Fields Too Large"; break;
        case 500: reason = "Internal Server Error"; break;
        case 502: reason = "Bad Gateway"; break;
        case 503: reason = "Service Unavailable"; break;
        case 504: reason = "Gateway Timeout"; break;
        default:  reason = "Unknown"; break;
        }
    }

    char date_buf[64];
    time_t now = time(NULL);
    struct tm tm_val;
    gmtime_r(&now, &tm_val);
    strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S GMT", &tm_val);

    const char *conn_header = "keep-alive";
    if (ctx->conn != NULL && ctx->conn->close_after_write) {
        conn_header = "close";
    }

    /* RFC 9112 §6.3: A 204 No Content or 1xx response MUST NOT include Content-Length */
    bool suppress_content_length = (ctx->status == 204 || (ctx->status >= 100 && ctx->status < 200));

    int written = 0;
    if (ctx->content_length_n >= 0 && !suppress_content_length) {
        written = snprintf(ctx->headers_out, ctx->headers_out_cap,
                           "HTTP/1.1 %d %s\r\n"
                           "Date: %s\r\n"
                           "Server: apex\r\n"
                           "Connection: %s\r\n"
                           "Content-Length: %lld\r\n",
                           ctx->status, reason,
                           date_buf,
                           conn_header,
                           (long long)ctx->content_length_n);
    } else if (!ctx->no_body && !ctx->is_head && ctx->content_length_n < 0) {
        /* RFC 9112 §6.3: Streaming response without fixed length requires chunked framing */
        written = snprintf(ctx->headers_out, ctx->headers_out_cap,
                           "HTTP/1.1 %d %s\r\n"
                           "Date: %s\r\n"
                           "Server: apex\r\n"
                           "Connection: %s\r\n"
                           "Transfer-Encoding: chunked\r\n",
                           ctx->status, reason,
                           date_buf,
                           conn_header);
    } else {
        written = snprintf(ctx->headers_out, ctx->headers_out_cap,
                           "HTTP/1.1 %d %s\r\n"
                           "Date: %s\r\n"
                           "Server: apex\r\n"
                           "Connection: %s\r\n",
                           ctx->status, reason,
                           date_buf,
                           conn_header);
    }

    if (written < 0 || (size_t)written >= ctx->headers_out_cap) {
        return APEX_FILTER_ERROR;
    }
    ctx->headers_out_len = (size_t)written;

    if (ctx->content_type != NULL && ctx->content_type_len > 0) {
        size_t needed = ctx->headers_out_len + ctx->content_type_len + 32u;
        if (!apex_ensure_header_capacity(ctx, needed)) {
            return APEX_FILTER_ERROR;
        }
        int ct_len = snprintf(ctx->headers_out + ctx->headers_out_len,
                              ctx->headers_out_cap - ctx->headers_out_len,
                              "Content-Type: %.*s\r\n",
                              (int)ctx->content_type_len, ctx->content_type);
        if (ct_len > 0) {
            ctx->headers_out_len += (size_t)ct_len;
        }
    }

    if (ctx->extra_headers != NULL && ctx->extra_headers_len > 0) {
        size_t needed = ctx->headers_out_len + ctx->extra_headers_len + 8u;
        if (!apex_ensure_header_capacity(ctx, needed)) {
            return APEX_FILTER_ERROR;
        }
        memcpy(ctx->headers_out + ctx->headers_out_len, ctx->extra_headers, ctx->extra_headers_len);
        ctx->headers_out_len += ctx->extra_headers_len;
    }

    /* Terminate header block */
    if (!apex_ensure_header_capacity(ctx, ctx->headers_out_len + 4u)) {
        return APEX_FILTER_ERROR;
    }
    ctx->headers_out[ctx->headers_out_len++] = '\r';
    ctx->headers_out[ctx->headers_out_len++] = '\n';
    ctx->headers_out[ctx->headers_out_len] = '\0';

    return APEX_FILTER_OK;
}

static int apex_default_write_filter(apex_filter_ctx_t *ctx, apex_chain_t **in) {
    if (ctx == NULL || ctx->conn == NULL || in == NULL) {
        return APEX_FILTER_ERROR;
    }

    for (apex_chain_t *link = *in; link != NULL; link = link->next) {
        apex_buf_t *b = link->buf;
        if (b == NULL) {
            continue;
        }

        if (b->pos != NULL && b->last != NULL && b->last > b->pos) {
            size_t size = (size_t)(b->last - b->pos);
            apex_conn_write(ctx->conn, b->pos, size);
            b->pos = b->last;
        }

        if (b->last_buf) {
            ctx->last_buf_sent = true;
        }
    }

    return APEX_FILTER_OK;
}

static void apex_filter_do_init(void) {
    s_header_filter_count = 0;
    s_body_filter_count = 0;

    s_header_filters[s_header_filter_count++] = apex_default_header_filter;
    s_body_filters[s_body_filter_count++] = apex_default_write_filter;
}

void apex_filter_init(void) {
    pthread_once(&s_filter_once, apex_filter_do_init);
}

int apex_register_header_filter(apex_header_filter_pt filter) {
    if (filter == NULL) {
        return APEX_FILTER_ERROR;
    }

    apex_filter_init();

    pthread_rwlock_wrlock(&s_filter_lock);
    if (s_header_filter_count >= APEX_MAX_FILTERS) {
        pthread_rwlock_unlock(&s_filter_lock);
        return APEX_FILTER_ERROR;
    }

    /* Shift default filter to end so new filter runs before default */
    apex_header_filter_pt default_filter = s_header_filters[s_header_filter_count - 1];
    s_header_filters[s_header_filter_count - 1] = filter;
    s_header_filters[s_header_filter_count] = default_filter;
    s_header_filter_count++;

    pthread_rwlock_unlock(&s_filter_lock);
    return APEX_FILTER_OK;
}

int apex_register_body_filter(apex_body_filter_pt filter) {
    if (filter == NULL) {
        return APEX_FILTER_ERROR;
    }

    apex_filter_init();

    pthread_rwlock_wrlock(&s_filter_lock);
    if (s_body_filter_count >= APEX_MAX_FILTERS) {
        pthread_rwlock_unlock(&s_filter_lock);
        return APEX_FILTER_ERROR;
    }

    /* Shift default write filter to end so new filter transforms chain before writing */
    apex_body_filter_pt default_filter = s_body_filters[s_body_filter_count - 1];
    s_body_filters[s_body_filter_count - 1] = filter;
    s_body_filters[s_body_filter_count] = default_filter;
    s_body_filter_count++;

    pthread_rwlock_unlock(&s_filter_lock);
    return APEX_FILTER_OK;
}

int apex_http_send_header(apex_filter_ctx_t *ctx) {
    if (ctx == NULL) {
        return APEX_FILTER_ERROR;
    }

    apex_filter_init();

    pthread_rwlock_rdlock(&s_filter_lock);
    for (size_t i = 0; i < s_header_filter_count; i++) {
        int rc = s_header_filters[i](ctx);
        if (rc != APEX_FILTER_OK) {
            pthread_rwlock_unlock(&s_filter_lock);
            return rc;
        }
    }
    pthread_rwlock_unlock(&s_filter_lock);

    if (ctx->conn != NULL && ctx->headers_out != NULL && ctx->headers_out_len > 0) {
        apex_conn_write(ctx->conn, ctx->headers_out, ctx->headers_out_len);
        ctx->header_sent = true;
    }

    return APEX_FILTER_OK;
}

int apex_http_output_filter(apex_filter_ctx_t *ctx, apex_chain_t *in) {
    if (ctx == NULL) {
        return APEX_FILTER_ERROR;
    }

    if (!ctx->header_sent) {
        int rc = apex_http_send_header(ctx);
        if (rc != APEX_FILTER_OK) {
            return rc;
        }
    }

    if (ctx->is_head || ctx->no_body) {
        return APEX_FILTER_OK;
    }

    apex_filter_init();

    apex_chain_t *chain = in;
    pthread_rwlock_rdlock(&s_filter_lock);
    for (size_t i = 0; i < s_body_filter_count; i++) {
        int rc = s_body_filters[i](ctx, &chain);
        if (rc != APEX_FILTER_OK) {
            pthread_rwlock_unlock(&s_filter_lock);
            return rc;
        }
    }
    pthread_rwlock_unlock(&s_filter_lock);

    return APEX_FILTER_OK;
}

apex_filter_ctx_t *apex_create_filter_ctx(conn_t *conn, apex_pool_t *pool, int status, const char *reason) {
    apex_filter_ctx_t *ctx = NULL;
    if (pool != NULL) {
        ctx = apex_pcalloc(pool, sizeof(apex_filter_ctx_t));
    } else {
        ctx = calloc(1, sizeof(apex_filter_ctx_t));
    }

    if (ctx == NULL) {
        return NULL;
    }

    ctx->conn = conn;
    ctx->pool = pool;
    ctx->status = status;
    ctx->reason = reason;
    ctx->content_length_n = -1;
    ctx->is_head = false;
    ctx->no_body = (status == 204 || status == 304 || (status >= 100 && status < 200));
    ctx->header_sent = false;
    ctx->last_buf_sent = false;
    ctx->headers_out = NULL;
    ctx->headers_out_len = 0;
    ctx->headers_out_cap = 0;
    ctx->extra_headers = NULL;
    ctx->extra_headers_len = 0;
    ctx->out_chain = NULL;

    return ctx;
}

void apex_destroy_filter_ctx(apex_filter_ctx_t *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->pool == NULL) {
        if (ctx->headers_out != NULL) {
            free(ctx->headers_out);
        }
        free(ctx);
    }
}
