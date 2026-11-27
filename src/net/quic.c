#include "apex/quic.h"
#include "internal.h"
#include "apex/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define QUIC_CONN_MAP_SIZE 1024
#define QUIC_MAX_HEADERS 64
#define QUIC_OUTPUT_PKT_SIZE 1452

/* Upstream ngtcp2_crypto declarations */
int ngtcp2_crypto_recv_client_initial_cb(ngtcp2_conn *conn, const ngtcp2_cid *dcid, void *user_data);
int ngtcp2_crypto_recv_crypto_data_cb(ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level,
                                     uint64_t offset, const uint8_t *data, size_t datalen, void *user_data);
int ngtcp2_crypto_encrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                            const ngtcp2_crypto_aead_ctx *aead_ctx,
                            const uint8_t *plaintext, size_t plaintextlen,
                            const uint8_t *nonce, size_t noncelen,
                            const uint8_t *aad, size_t aadlen);
int ngtcp2_crypto_decrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                            const ngtcp2_crypto_aead_ctx *aead_ctx,
                            const uint8_t *ciphertext, size_t ciphertextlen,
                            const uint8_t *nonce, size_t noncelen,
                            const uint8_t *aad, size_t aadlen);
int ngtcp2_crypto_hp_mask_cb(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                            const ngtcp2_crypto_cipher_ctx *hp_ctx,
                            const uint8_t *sample);
int ngtcp2_crypto_update_key_cb(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
                               ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                               ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                               const uint8_t *current_rx_secret, const uint8_t *current_tx_secret,
                               size_t secretlen, void *user_data);
void ngtcp2_crypto_delete_crypto_aead_ctx_cb(ngtcp2_conn *conn, ngtcp2_crypto_aead_ctx *aead_ctx, void *user_data);
void ngtcp2_crypto_delete_crypto_cipher_ctx_cb(ngtcp2_conn *conn, ngtcp2_crypto_cipher_ctx *cipher_ctx, void *user_data);
int ngtcp2_crypto_get_path_challenge_data_cb(ngtcp2_conn *conn, uint8_t *data, void *user_data);
int ngtcp2_crypto_version_negotiation_cb(ngtcp2_conn *conn, uint32_t version, const ngtcp2_cid *client_dcid, void *user_data);

typedef struct apex_h3_stream {
    int64_t stream_id;
    struct apex_h3_stream *next;

    char method[16];
    size_t method_len;
    char *scheme;
    size_t scheme_len;
    char *authority;
    size_t authority_len;
    char *path;
    size_t path_len;

    char *raw_headers;
    size_t raw_headers_len;
    size_t raw_headers_cap;

    char *body;
    size_t body_len;
    size_t body_cap;

    conn_t *virtual_conn;
    const char *response_body;
    size_t response_body_len;
    size_t response_offset;
    char *response_owned;
    char *separate_body_owned;

    nghttp3_nv *resp_nva;
    size_t resp_nvlen;
    char *resp_hdrs_buf;
    bool response_submitted;
} apex_h3_stream_t;

typedef struct apex_quic_cid_entry {
    uint8_t cid[NGTCP2_MAX_CIDLEN];
    size_t cidlen;
    struct apex_quic_conn *conn;
    struct apex_quic_cid_entry *next;
    struct apex_quic_cid_entry *conn_next;
} apex_quic_cid_entry_t;

typedef struct apex_quic_conn {
    apex_quic_server_t *server;
    struct apex_quic_conn *all_next;
    apex_quic_cid_entry_t *cid_entries;

    ngtcp2_conn *qconn;
    nghttp3_conn *h3conn;
    SSL *ssl;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;

    struct {
        ngtcp2_conn *(*get_conn)(void *ref);
        void *user_data;
    } conn_ref;

    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    ngtcp2_path path;

    ngtcp2_cid scid;
    ngtcp2_cid dcid;

    int64_t ctrl_stream_id;
    int64_t qenc_stream_id;
    int64_t qdec_stream_id;

    apex_h3_stream_t *streams;
    bool handshake_done;
    uint64_t last_activity_ms;
} apex_quic_conn_t;

struct apex_quic_server {
    worker_arg_t *worker;
    int udp_fd;
    uint16_t port;
    SSL_CTX *ssl_ctx;
    apex_quic_cid_entry_t *cid_map[QUIC_CONN_MAP_SIZE];
    apex_quic_conn_t *all_conns;
    size_t connection_count;
};

static ngtcp2_tstamp quic_get_tstamp(void) {
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (ngtcp2_tstamp)tp.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)tp.tv_nsec;
}

static void quic_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
    (void)rand_ctx;
    RAND_bytes(dest, (int)destlen);
}

static ngtcp2_conn *quic_conn_ref_get_conn(void *ref) {
    apex_quic_conn_t *c = (apex_quic_conn_t *)(((char *)ref) - offsetof(apex_quic_conn_t, conn_ref));
    return c->qconn;
}

static uint32_t quic_cid_hash(const uint8_t *data, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h % QUIC_CONN_MAP_SIZE;
}

static void quic_insert_cid(apex_quic_server_t *server, apex_quic_conn_t *conn, const uint8_t *cid, size_t cidlen) {
    if (server == NULL || conn == NULL || cid == NULL || cidlen == 0 || cidlen > NGTCP2_MAX_CIDLEN) {
        return;
    }
    uint32_t idx = quic_cid_hash(cid, cidlen);
    for (apex_quic_cid_entry_t *e = server->cid_map[idx]; e != NULL; e = e->next) {
        if (e->cidlen == cidlen && memcmp(e->cid, cid, cidlen) == 0) {
            e->conn = conn;
            return;
        }
    }
    apex_quic_cid_entry_t *entry = malloc(sizeof(*entry));
    if (entry == NULL) {
        return;
    }
    memcpy(entry->cid, cid, cidlen);
    entry->cidlen = cidlen;
    entry->conn = conn;
    entry->next = server->cid_map[idx];
    server->cid_map[idx] = entry;

    entry->conn_next = conn->cid_entries;
    conn->cid_entries = entry;
}

static void quic_remove_all_cids(apex_quic_server_t *server, apex_quic_conn_t *conn) {
    if (server == NULL || conn == NULL) {
        return;
    }
    apex_quic_cid_entry_t *curr = conn->cid_entries;
    while (curr != NULL) {
        apex_quic_cid_entry_t *next = curr->conn_next;
        uint32_t idx = quic_cid_hash(curr->cid, curr->cidlen);
        apex_quic_cid_entry_t **p = &server->cid_map[idx];
        while (*p != NULL) {
            if (*p == curr) {
                *p = curr->next;
                break;
            }
            p = &(*p)->next;
        }
        free(curr);
        curr = next;
    }
    conn->cid_entries = NULL;
}

static apex_quic_conn_t *quic_find_conn(apex_quic_server_t *server, const uint8_t *cid, size_t cidlen) {
    if (server == NULL || cid == NULL || cidlen == 0) {
        return NULL;
    }
    uint32_t idx = quic_cid_hash(cid, cidlen);
    for (apex_quic_cid_entry_t *e = server->cid_map[idx]; e != NULL; e = e->next) {
        if (e->cidlen == cidlen && memcmp(e->cid, cid, cidlen) == 0) {
            return e->conn;
        }
    }
    return NULL;
}

static int quic_get_new_cid(ngtcp2_conn *qconn, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data) {
    (void)qconn;
    apex_quic_conn_t *conn = user_data;
    cid->datalen = cidlen;
    RAND_bytes(cid->data, (int)cidlen);
    if (token != NULL) {
        RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    }
    if (conn != NULL && conn->server != NULL) {
        quic_insert_cid(conn->server, conn, cid->data, cid->datalen);
    }
    return 0;
}

static apex_h3_stream_t *quic_find_stream(apex_quic_conn_t *conn, int64_t stream_id) {
    for (apex_h3_stream_t *s = conn->streams; s != NULL; s = s->next) {
        if (s->stream_id == stream_id) {
            return s;
        }
    }
    return NULL;
}

static apex_h3_stream_t *quic_get_or_create_stream(apex_quic_conn_t *conn, int64_t stream_id) {
    apex_h3_stream_t *s = quic_find_stream(conn, stream_id);
    if (s != NULL) {
        return s;
    }
    s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    s->stream_id = stream_id;
    s->next = conn->streams;
    conn->streams = s;
    return s;
}

static void quic_stream_destroy(apex_h3_stream_t *s) {
    if (s == NULL) {
        return;
    }
    free(s->scheme);
    free(s->authority);
    free(s->path);
    free(s->raw_headers);
    free(s->body);
    free(s->response_owned);
    free(s->separate_body_owned);
    free(s->resp_nva);
    free(s->resp_hdrs_buf);
    if (s->virtual_conn != NULL) {
        free(s->virtual_conn->aux_buffer);
        free(s->virtual_conn->trailers_buffer);
        free(s->virtual_conn);
    }
    free(s);
}

static void quic_conn_destroy(apex_quic_server_t *server, apex_quic_conn_t *conn) {
    if (conn == NULL) {
        return;
    }
    if (server != NULL) {
        quic_remove_all_cids(server, conn);
        apex_quic_conn_t **curr = &server->all_conns;
        while (*curr != NULL) {
            if (*curr == conn) {
                *curr = conn->all_next;
                break;
            }
            curr = &(*curr)->all_next;
        }
        server->connection_count--;
    }

    apex_h3_stream_t *s = conn->streams;
    while (s != NULL) {
        apex_h3_stream_t *next = s->next;
        quic_stream_destroy(s);
        s = next;
    }
    conn->streams = NULL;

    if (conn->h3conn != NULL) {
        nghttp3_conn_del(conn->h3conn);
        conn->h3conn = NULL;
    }
    if (conn->qconn != NULL) {
        ngtcp2_conn_del(conn->qconn);
        conn->qconn = NULL;
    }
    if (conn->ssl != NULL) {
        SSL_set_app_data(conn->ssl, NULL);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->ossl_ctx != NULL) {
        ngtcp2_crypto_ossl_ctx_del(conn->ossl_ctx);
        conn->ossl_ctx = NULL;
    }
    free(conn);
}

/* Response body reader for nghttp3 */
static nghttp3_ssize h3_read_data(nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec, size_t veccnt,
                                   uint32_t *pflags, void *user_data, void *stream_user_data) {
    (void)conn; (void)stream_id; (void)veccnt; (void)user_data;
    apex_h3_stream_t *s = stream_user_data;
    if (s == NULL) {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    size_t rem = s->response_body_len - s->response_offset;
    if (rem == 0) {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    vec[0].base = (uint8_t *)s->response_body + s->response_offset;
    vec[0].len = rem;
    s->response_offset += rem;
    *pflags |= NGHTTP3_DATA_FLAG_EOF;
    return 1;
}

static inline bool h3_drop_h1_header(const char *name, size_t name_length) {
    if (name_length == 10 && strncasecmp(name, "connection", 10) == 0) return true;
    if (name_length == 10 && strncasecmp(name, "keep-alive", 10) == 0) return true;
    if (name_length == 16 && strncasecmp(name, "proxy-connection", 16) == 0) return true;
    if (name_length == 17 && strncasecmp(name, "transfer-encoding", 17) == 0) return true;
    if (name_length == 7 && strncasecmp(name, "upgrade", 7) == 0) return true;
    return false;
}

static bool h3_response_blob(conn_t *virtual_conn, char **blob, size_t *blob_length, char **owned,
                             const char **separate_body, size_t *separate_body_length, char **separate_body_owned) {
    char *first = virtual_conn->write_buffer;
    size_t first_length = virtual_conn->write_length;
    char *second = virtual_conn->aux_buffer;
    size_t second_length = virtual_conn->aux_length;
    *separate_body = NULL;
    *separate_body_length = 0;
    *separate_body_owned = NULL;

    if (first_length > 0 && second_length > 0) {
        if (first_length >= 4u && memcmp(first + first_length - 4u, "\r\n\r\n", 4u) == 0) {
            *blob = first;
            *blob_length = first_length;
            *owned = NULL;
            *separate_body = second;
            *separate_body_length = second_length;
            *separate_body_owned = second;
            virtual_conn->aux_buffer = NULL;
            virtual_conn->aux_capacity = 0;
            virtual_conn->aux_length = 0;
            return true;
        }
        if (first_length > SIZE_MAX - second_length) {
            return false;
        }
        char *joined = malloc(first_length + second_length);
        if (joined == NULL) {
            return false;
        }
        memcpy(joined, first, first_length);
        memcpy(joined + first_length, second, second_length);
        *owned = joined;
        *blob = joined;
        *blob_length = first_length + second_length;
        return true;
    }
    if (second_length > 0) {
        *blob = second;
        *blob_length = second_length;
    } else {
        *blob = first;
        *blob_length = first_length;
    }
    *owned = NULL;
    return true;
}

static void h3_dispatch_and_submit_response(apex_quic_conn_t *conn, apex_h3_stream_t *stream) {
    if (stream->response_submitted) {
        return;
    }
    stream->response_submitted = true;

    /* Build HTTP/1.1 request */
    size_t cap = 2048 + stream->raw_headers_len + (stream->authority_len ? stream->authority_len : 16) + (stream->path_len ? stream->path_len : 1);
    char *req = malloc(cap);
    if (req == NULL) {
        return;
    }

    const char *m = stream->method_len > 0 ? stream->method : "GET";
    const char *p = stream->path_len > 0 ? stream->path : "/";
    const char *a = stream->authority_len > 0 ? stream->authority : "localhost";

    int off = snprintf(req, cap, "%s %s HTTP/1.1\r\nHost: %s\r\nX-Forwarded-Proto: https\r\n", m, p, a);
    if (off < 0 || (size_t)off >= cap) {
        free(req);
        return;
    }

    if (stream->raw_headers != NULL && stream->raw_headers_len > 0) {
        if ((size_t)off + stream->raw_headers_len < cap) {
            memcpy(req + off, stream->raw_headers, stream->raw_headers_len);
            off += (int)stream->raw_headers_len;
        }
    }

    int cl = snprintf(req + off, cap - (size_t)off, "Content-Length: %zu\r\n\r\n", stream->body_len);
    if (cl < 0 || (size_t)off + (size_t)cl >= cap) {
        free(req);
        return;
    }
    size_t header_len = (size_t)off + (size_t)cl;

    stream->virtual_conn = calloc(1, sizeof(*stream->virtual_conn));
    if (stream->virtual_conn == NULL) {
        free(req);
        return;
    }
    stream->virtual_conn->is_virtual = 1;
    stream->virtual_conn->listener_port = conn->server->port;
    stream->virtual_conn->is_tls = 1;
    stream->virtual_conn->transport = APEX_TRANSPORT_PLAIN;

    apex_res_t response = {.conn = stream->virtual_conn};
    const apex_runtime_t *runtime = conn->server->worker->generation != NULL ? conn->server->worker->generation->runtime : NULL;

    apex_dispatch_runtime(conn->server->worker->app, runtime, req, header_len,
                          stream->body, stream->body_len, &response);
    free(req);

    /* Translate response for HTTP/3 */
    char *blob = NULL;
    char *owned = NULL;
    size_t blob_length = 0;
    const char *sep_body = NULL;
    size_t sep_body_length = 0;
    char *sep_body_owned = NULL;

    if (!h3_response_blob(stream->virtual_conn, &blob, &blob_length, &owned,
                          &sep_body, &sep_body_length, &sep_body_owned)) {
        return;
    }
    stream->response_owned = owned;
    stream->separate_body_owned = sep_body_owned;

    if (blob_length < 14u || (memcmp(blob, "HTTP/1.1 ", 9) != 0 && memcmp(blob, "HTTP/1.0 ", 9) != 0)) {
        return;
    }

    char status_str[4];
    memcpy(status_str, blob + 9, 3);
    status_str[3] = '\0';

    const char *body_start = NULL;
    for (size_t i = 0; i + 3 < blob_length; i++) {
        if (blob[i] == '\r' && blob[i+1] == '\n' && blob[i+2] == '\r' && blob[i+3] == '\n') {
            body_start = blob + i + 4;
            break;
        }
    }
    if (body_start == NULL) {
        return;
    }

    if (sep_body != NULL) {
        stream->response_body = sep_body;
        stream->response_body_len = sep_body_length;
    } else {
        stream->response_body = body_start;
        stream->response_body_len = blob_length - (size_t)(body_start - blob);
    }
    stream->response_offset = 0;

    /* Build nghttp3 headers */
    stream->resp_nva = calloc(QUIC_MAX_HEADERS, sizeof(nghttp3_nv));
    if (stream->resp_nva == NULL) {
        return;
    }
    stream->resp_hdrs_buf = malloc(4096);
    if (stream->resp_hdrs_buf == NULL) {
        free(stream->resp_nva);
        stream->resp_nva = NULL;
        return;
    }
    size_t buf_off = 0;

    /* Copy :status value into heap-allocated resp_hdrs_buf to prevent dangling stack pointer */
    char *status_dest = stream->resp_hdrs_buf + buf_off;
    memcpy(status_dest, status_str, 3);
    status_dest[3] = '\0';
    buf_off += 4;

    /* Pseudo-header :status */
    stream->resp_nva[0].name = (uint8_t *)":status";
    stream->resp_nva[0].namelen = 7;
    stream->resp_nva[0].value = (uint8_t *)status_dest;
    stream->resp_nva[0].valuelen = 3;
    stream->resp_nvlen = 1;

    /* Parse headers */
    const char *h_cur = memchr(blob, '\r', blob_length);
    if (h_cur != NULL && h_cur + 2 < body_start) {
        h_cur += 2;
        while (h_cur < body_start - 2 && stream->resp_nvlen < QUIC_MAX_HEADERS) {
            const char *eol = memchr(h_cur, '\r', (size_t)(body_start - h_cur));
            if (eol == NULL || eol + 1 >= body_start) break;
            const char *col = memchr(h_cur, ':', (size_t)(eol - h_cur));
            if (col != NULL && col < eol) {
                size_t nlen = (size_t)(col - h_cur);
                const char *val = col + 1;
                while (val < eol && (*val == ' ' || *val == '\t')) val++;
                size_t vlen = (size_t)(eol - val);

                if (!h3_drop_h1_header(h_cur, nlen)) {
                    if (buf_off + nlen + 1 + vlen + 1 < 4096) {
                        char *name_dest = stream->resp_hdrs_buf + buf_off;
                        for (size_t k = 0; k < nlen; k++) {
                            name_dest[k] = (char)tolower((unsigned char)h_cur[k]);
                        }
                        name_dest[nlen] = '\0';
                        buf_off += nlen + 1;

                        char *val_dest = stream->resp_hdrs_buf + buf_off;
                        memcpy(val_dest, val, vlen);
                        val_dest[vlen] = '\0';
                        buf_off += vlen + 1;

                        stream->resp_nva[stream->resp_nvlen].name = (uint8_t *)name_dest;
                        stream->resp_nva[stream->resp_nvlen].namelen = nlen;
                        stream->resp_nva[stream->resp_nvlen].value = (uint8_t *)val_dest;
                        stream->resp_nva[stream->resp_nvlen].valuelen = vlen;
                        stream->resp_nvlen++;
                    }
                }
            }
            h_cur = eol + 2;
        }
    }

    nghttp3_data_reader dr = {
        .read_data = h3_read_data
    };
    nghttp3_conn_set_stream_user_data(conn->h3conn, stream->stream_id, stream);
    nghttp3_conn_submit_response(conn->h3conn, stream->stream_id, stream->resp_nva, stream->resp_nvlen, &dr);
}

/* nghttp3 callbacks */
static int h3_acked_stream_data(nghttp3_conn *conn, int64_t stream_id, uint64_t datalen, void *user_data, void *stream_user_data) {
    (void)conn; (void)stream_id; (void)datalen; (void)user_data; (void)stream_user_data;
    return 0;
}

static int h3_stream_close(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code, void *user_data, void *stream_user_data) {
    (void)conn; (void)app_error_code;
    apex_quic_conn_t *c = user_data;
    if (c == NULL) return 0;
    apex_h3_stream_t *s = stream_user_data ? (apex_h3_stream_t *)stream_user_data : quic_find_stream(c, stream_id);
    if (s != NULL) {
        apex_h3_stream_t **curr = &c->streams;
        while (*curr != NULL) {
            if (*curr == s) {
                *curr = s->next;
                break;
            }
            curr = &(*curr)->next;
        }
        quic_stream_destroy(s);
    }
    return 0;
}

static int h3_recv_data(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data) {
    (void)conn; (void)user_data; (void)stream_user_data;
    apex_quic_conn_t *c = user_data;
    apex_h3_stream_t *s = quic_get_or_create_stream(c, stream_id);
    if (s == NULL) return 0;

    if (s->body_len + datalen > s->body_cap) {
        size_t ncap = s->body_cap ? s->body_cap * 2 : 4096;
        while (s->body_len + datalen > ncap) ncap *= 2;
        char *nb = realloc(s->body, ncap);
        if (nb == NULL) return 0;
        s->body = nb;
        s->body_cap = ncap;
    }
    memcpy(s->body + s->body_len, data, datalen);
    s->body_len += datalen;
    return 0;
}

static int h3_deferred_consume(nghttp3_conn *conn, int64_t stream_id, size_t consumed, void *user_data, void *stream_user_data) {
    (void)conn; (void)stream_id; (void)consumed; (void)user_data; (void)stream_user_data;
    return 0;
}

static int h3_begin_headers(nghttp3_conn *conn, int64_t stream_id, void *user_data, void *stream_user_data) {
    (void)conn; (void)stream_id; (void)user_data; (void)stream_user_data;
    return 0;
}

static int h3_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                          nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                          void *user_data, void *stream_user_data) {
    (void)conn; (void)token; (void)flags; (void)stream_user_data;
    apex_quic_conn_t *c = user_data;
    apex_h3_stream_t *s = quic_get_or_create_stream(c, stream_id);
    if (s == NULL) return 0;

    nghttp3_vec nv = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec vv = nghttp3_rcbuf_get_buf(value);

    if (nv.len == 7 && memcmp(nv.base, ":method", 7) == 0) {
        size_t cp = vv.len < sizeof(s->method) - 1 ? vv.len : sizeof(s->method) - 1;
        memcpy(s->method, vv.base, cp);
        s->method[cp] = '\0';
        s->method_len = cp;
    } else if (nv.len == 7 && memcmp(nv.base, ":scheme", 7) == 0) {
        s->scheme = strndup((const char *)vv.base, vv.len);
        s->scheme_len = vv.len;
    } else if (nv.len == 10 && memcmp(nv.base, ":authority", 10) == 0) {
        s->authority = strndup((const char *)vv.base, vv.len);
        s->authority_len = vv.len;
    } else if (nv.len == 5 && memcmp(nv.base, ":path", 5) == 0) {
        s->path = strndup((const char *)vv.base, vv.len);
        s->path_len = vv.len;
    } else {
        /* Regular header: format "Name: Value\r\n" */
        size_t needed = nv.len + 2 + vv.len + 2;
        if (s->raw_headers_len + needed + 1 > s->raw_headers_cap) {
            size_t ncap = s->raw_headers_cap ? s->raw_headers_cap * 2 : 1024;
            while (s->raw_headers_len + needed + 1 > ncap) ncap *= 2;
            char *nb = realloc(s->raw_headers, ncap);
            if (nb != NULL) {
                s->raw_headers = nb;
                s->raw_headers_cap = ncap;
            }
        }
        if (s->raw_headers != NULL && s->raw_headers_len + needed < s->raw_headers_cap) {
            memcpy(s->raw_headers + s->raw_headers_len, nv.base, nv.len);
            s->raw_headers_len += nv.len;
            memcpy(s->raw_headers + s->raw_headers_len, ": ", 2);
            s->raw_headers_len += 2;
            memcpy(s->raw_headers + s->raw_headers_len, vv.base, vv.len);
            s->raw_headers_len += vv.len;
            memcpy(s->raw_headers + s->raw_headers_len, "\r\n", 2);
            s->raw_headers_len += 2;
            s->raw_headers[s->raw_headers_len] = '\0';
        }
    }
    return 0;
}

static int h3_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin, void *user_data, void *stream_user_data) {
    (void)conn; (void)stream_id; (void)fin; (void)user_data; (void)stream_user_data;
    return 0;
}

static int h3_stop_sending(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code, void *user_data, void *stream_user_data) {
    (void)conn; (void)stream_id; (void)app_error_code; (void)user_data; (void)stream_user_data;
    return 0;
}

static int h3_reset_stream(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code, void *user_data, void *stream_user_data) {
    (void)conn; (void)stream_id; (void)app_error_code; (void)user_data; (void)stream_user_data;
    return 0;
}

static int h3_end_stream(nghttp3_conn *conn, int64_t stream_id, void *user_data, void *stream_user_data) {
    (void)conn; (void)stream_user_data;
    apex_quic_conn_t *c = user_data;
    apex_h3_stream_t *s = quic_find_stream(c, stream_id);
    if (s != NULL) {
        h3_dispatch_and_submit_response(c, s);
    }
    return 0;
}

static int h3_setup_streams(apex_quic_conn_t *c) {
    if (c->h3conn != NULL) return 0;
    nghttp3_callbacks cb = {
        .acked_stream_data = h3_acked_stream_data,
        .stream_close = h3_stream_close,
        .recv_data = h3_recv_data,
        .deferred_consume = h3_deferred_consume,
        .begin_headers = h3_begin_headers,
        .recv_header = h3_recv_header,
        .end_headers = h3_end_headers,
        .stop_sending = h3_stop_sending,
        .end_stream = h3_end_stream,
        .reset_stream = h3_reset_stream,
    };
    nghttp3_settings settings;
    nghttp3_settings_default(&settings);

    int rv = nghttp3_conn_server_new(&c->h3conn, &cb, &settings, NULL, c);
    if (rv != 0) {
        return -1;
    }

    if (ngtcp2_conn_open_uni_stream(c->qconn, &c->ctrl_stream_id, NULL) == 0) {
        nghttp3_conn_bind_control_stream(c->h3conn, c->ctrl_stream_id);
    }
    if (ngtcp2_conn_open_uni_stream(c->qconn, &c->qenc_stream_id, NULL) == 0 &&
        ngtcp2_conn_open_uni_stream(c->qconn, &c->qdec_stream_id, NULL) == 0) {
        nghttp3_conn_bind_qpack_streams(c->h3conn, c->qenc_stream_id, c->qdec_stream_id);
    }
    return 0;
}

/* ngtcp2 callbacks */
static int q_handshake_completed(ngtcp2_conn *conn, void *user_data) {
    (void)conn;
    apex_quic_conn_t *c = user_data;
    c->handshake_done = true;
    h3_setup_streams(c);
    return 0;
}

static int q_recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                              uint64_t offset, const uint8_t *data, size_t datalen,
                              void *user_data, void *stream_user_data) {
    (void)conn; (void)offset; (void)stream_user_data;
    apex_quic_conn_t *c = user_data;
    int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
    if (c->h3conn != NULL) {
        nghttp3_ssize nconsumed = nghttp3_conn_read_stream(c->h3conn, stream_id, data, datalen, fin);
        if (nconsumed < 0) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        ngtcp2_conn_extend_max_stream_offset(c->qconn, stream_id, (size_t)nconsumed);
        ngtcp2_conn_extend_max_offset(c->qconn, (size_t)nconsumed);
    }
    return 0;
}

static int q_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                      uint64_t offset, uint64_t datalen, void *user_data, void *stream_user_data) {
    (void)conn; (void)offset; (void)stream_user_data;
    apex_quic_conn_t *c = user_data;
    if (c->h3conn != NULL) {
        nghttp3_conn_add_ack_offset(c->h3conn, stream_id, (size_t)datalen);
    }
    return 0;
}

static int q_stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                          uint64_t app_error_code, void *user_data, void *stream_user_data) {
    (void)conn; (void)flags; (void)stream_user_data;
    apex_quic_conn_t *c = user_data;
    if (c->h3conn != NULL) {
        nghttp3_conn_close_stream(c->h3conn, stream_id, app_error_code);
    }
    return 0;
}

static void apex_quic_conn_send(apex_quic_conn_t *conn) {
    ngtcp2_tstamp ts = quic_get_tstamp();
    while (1) {
        int64_t stream_id = -1;
        int fin = 0;
        nghttp3_vec h3vec[16];
        nghttp3_ssize h3veccnt = 0;

        if (conn->h3conn != NULL) {
            h3veccnt = nghttp3_conn_writev_stream(conn->h3conn, &stream_id, &fin, h3vec, 16);
            if (h3veccnt < 0) {
                break;
            }
        }

        uint8_t outbuf[QUIC_OUTPUT_PKT_SIZE];
        ngtcp2_ssize nwrite = 0;

        if (h3veccnt > 0 || stream_id >= 0) {
            ngtcp2_vec qvec[16];
            for (int i = 0; i < h3veccnt; i++) {
                qvec[i].base = h3vec[i].base;
                qvec[i].len = h3vec[i].len;
            }
            uint32_t flags = fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : NGTCP2_WRITE_STREAM_FLAG_NONE;
            ngtcp2_ssize pdatalen = 0;
            nwrite = ngtcp2_conn_writev_stream(conn->qconn, &conn->path, NULL,
                                               outbuf, sizeof(outbuf), &pdatalen,
                                               flags, stream_id, qvec, (size_t)h3veccnt, ts);
            if (nwrite > 0 && pdatalen >= 0) {
                nghttp3_conn_add_write_offset(conn->h3conn, stream_id, (size_t)pdatalen);
            }
        } else {
            nwrite = ngtcp2_conn_write_pkt(conn->qconn, &conn->path, NULL,
                                           outbuf, sizeof(outbuf), ts);
        }

        if (nwrite <= 0) {
            break;
        }

        const ngtcp2_path *active_path = ngtcp2_conn_get_path(conn->qconn);
        const struct sockaddr *dest_addr = (active_path && active_path->remote.addr)
                                           ? (const struct sockaddr *)active_path->remote.addr
                                           : (const struct sockaddr *)&conn->peer_addr;
        socklen_t dest_len = (active_path && active_path->remote.addr)
                             ? (socklen_t)active_path->remote.addrlen
                             : conn->peer_addrlen;

        ssize_t sent = sendto(conn->server->udp_fd, outbuf, (size_t)nwrite, 0,
                              dest_addr, dest_len);
        if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
    }
}

int apex_quic_init(void) {
    static bool initialized = false;
    if (!initialized) {
        ngtcp2_crypto_ossl_init();
        initialized = true;
    }
    return 0;
}

apex_quic_server_t *apex_quic_server_create(worker_arg_t *worker, int udp_fd,
                                           const apex_listener_endpoint_t *ep) {
    if (worker == NULL || udp_fd < 0 || ep == NULL) {
        return NULL;
    }

    apex_quic_init();

    apex_quic_server_t *server = calloc(1, sizeof(*server));
    if (server == NULL) {
        return NULL;
    }
    server->worker = worker;
    server->udp_fd = udp_fd;
    server->port = ep->port;

    /* Use existing generation SSL_CTX if available */
    if (worker->generation != NULL && worker->generation->tls_context != NULL) {
        server->ssl_ctx = worker->generation->tls_context;
    }

    return server;
}

void apex_quic_server_destroy(apex_quic_server_t *server) {
    if (server == NULL) {
        return;
    }
    apex_quic_conn_t *c = server->all_conns;
    while (c != NULL) {
        apex_quic_conn_t *next = c->all_next;
        quic_conn_destroy(server, c);
        c = next;
    }
    free(server);
}

void apex_quic_process_read(apex_quic_server_t *server) {
    if (server == NULL || server->udp_fd < 0) {
        return;
    }

    /* Refresh ssl_ctx from generation if needed */
    if (server->worker->generation != NULL && server->worker->generation->tls_context != NULL) {
        server->ssl_ctx = server->worker->generation->tls_context;
    }
    if (server->ssl_ctx == NULL) {
        return;
    }

    while (1) {
        uint8_t pkt[4096];
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof(peer);
        ssize_t nread = recvfrom(server->udp_fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&peer, &peer_len);
        if (nread <= 0) {
            break;
        }

        ngtcp2_version_cid vcid;
        int dres = ngtcp2_pkt_decode_version_cid(&vcid, pkt, (size_t)nread, 16);
        if (dres < 0) {
            continue;
        }

        apex_quic_conn_t *conn = quic_find_conn(server, vcid.dcid, vcid.dcidlen);
        if (conn != NULL) {
            ngtcp2_path pkt_path = {
                .local = conn->path.local,
                .remote = {
                    .addr = (struct sockaddr *)&peer,
                    .addrlen = peer_len
                }
            };
            (void)ngtcp2_conn_read_pkt(conn->qconn, &pkt_path, NULL, pkt, (size_t)nread, quic_get_tstamp());
            apex_quic_conn_send(conn);
            continue;
        }

        /* Not found: check if it is a new Initial packet */
        ngtcp2_pkt_hd hd;
        int arv = ngtcp2_accept(&hd, pkt, (size_t)nread);
        if (arv < 0 || hd.type != NGTCP2_PKT_INITIAL) {
            continue;
        }

        conn = calloc(1, sizeof(*conn));
        if (conn == NULL) {
            continue;
        }
        conn->server = server;
        memcpy(&conn->peer_addr, &peer, peer_len);
        conn->peer_addrlen = peer_len;

        struct sockaddr_storage saddr;
        socklen_t saddr_len = sizeof(saddr);
        getsockname(server->udp_fd, (struct sockaddr *)&saddr, &saddr_len);
        memcpy(&conn->local_addr, &saddr, saddr_len);
        conn->local_addrlen = saddr_len;

        conn->path.local.addr = (struct sockaddr *)&conn->local_addr;
        conn->path.local.addrlen = conn->local_addrlen;
        conn->path.remote.addr = (struct sockaddr *)&conn->peer_addr;
        conn->path.remote.addrlen = conn->peer_addrlen;

        conn->ssl = SSL_new(server->ssl_ctx);
        if (conn->ssl == NULL) {
            free(conn);
            continue;
        }
        SSL_set_accept_state(conn->ssl);
        conn->conn_ref.get_conn = quic_conn_ref_get_conn;
        conn->conn_ref.user_data = conn;
        SSL_set_app_data(conn->ssl, &conn->conn_ref);
        ngtcp2_crypto_ossl_configure_server_session(conn->ssl);
        ngtcp2_crypto_ossl_ctx_new(&conn->ossl_ctx, conn->ssl);

        ngtcp2_callbacks cb = {
            .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
            .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
            .handshake_completed = q_handshake_completed,
            .encrypt = ngtcp2_crypto_encrypt_cb,
            .decrypt = ngtcp2_crypto_decrypt_cb,
            .hp_mask = ngtcp2_crypto_hp_mask_cb,
            .recv_stream_data = q_recv_stream_data,
            .acked_stream_data_offset = q_acked_stream_data_offset,
            .stream_close = q_stream_close,
            .rand = quic_rand,
            .get_new_connection_id = quic_get_new_cid,
            .update_key = ngtcp2_crypto_update_key_cb,
            .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
            .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
            .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
            .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
        };

        ngtcp2_settings settings;
        ngtcp2_settings_default(&settings);
        settings.initial_ts = quic_get_tstamp();

        ngtcp2_transport_params params;
        ngtcp2_transport_params_default(&params);
        params.initial_max_streams_bidi = 100;
        params.initial_max_streams_uni = 100;
        params.initial_max_data = 1024 * 1024 * 10;
        params.initial_max_stream_data_bidi_local = 1024 * 1024 * 2;
        params.initial_max_stream_data_bidi_remote = 1024 * 1024 * 2;
        params.initial_max_stream_data_uni = 1024 * 1024 * 2;
        params.active_connection_id_limit = 4;
        params.original_dcid = hd.dcid;
        params.original_dcid_present = 1;

        conn->dcid = hd.dcid;
        conn->scid.datalen = 16;
        RAND_bytes(conn->scid.data, 16);

        int crv = ngtcp2_conn_server_new(&conn->qconn, &hd.scid, &conn->scid,
                                         &conn->path, hd.version,
                                         &cb, &settings, &params, NULL, conn);
        if (crv != 0) {
            SSL_set_app_data(conn->ssl, NULL);
            SSL_free(conn->ssl);
            ngtcp2_crypto_ossl_ctx_del(conn->ossl_ctx);
            free(conn);
            continue;
        }

        ngtcp2_conn_set_tls_native_handle(conn->qconn, conn->ossl_ctx);
        conn->all_next = server->all_conns;
        server->all_conns = conn;
        server->connection_count++;

        quic_insert_cid(server, conn, conn->scid.data, conn->scid.datalen);
        quic_insert_cid(server, conn, hd.dcid.data, hd.dcid.datalen);

        (void)ngtcp2_conn_read_pkt(conn->qconn, &conn->path, NULL, pkt, (size_t)nread, quic_get_tstamp());
        apex_quic_conn_send(conn);
    }
}
