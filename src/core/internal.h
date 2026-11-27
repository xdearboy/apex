#ifndef APEX_INTERNAL_H
#define APEX_INTERNAL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "apex.h"
#include "apex/module.h"
#include "apex/static.h"
#include "apex/pool.h"
#include "apex/buf.h"
#include "apex/metrics.h"
#include "apex/file_cache.h"
#include "apex/proxy.h"
#include "apex/http_util.h"
#include "apex/websocket.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/sendfile.h>
#endif

#include <openssl/ssl.h>

#if defined(APEX_HAVE_URING)
#include <liburing.h>
#include <poll.h>
#endif

#define MAX_FDS 65536
#define MAX_EVENTS 512
#define BUF_SIZE 16384
#define MAX_ROUTES 128
#define APEX_CONFIG_MAX_LISTENERS 16

typedef struct apex_listener_endpoint {
    char host[APEX_CONFIG_HOST_MAX];
    uint16_t port;
    bool tls;
    char certificate[APEX_CONFIG_PATH_MAX];
    char private_key[APEX_CONFIG_PATH_MAX];
    struct sockaddr_storage address;
    socklen_t address_length;
} apex_listener_endpoint_t;

typedef struct {
    apex_listener_endpoint_t endpoints[APEX_CONFIG_MAX_LISTENERS];
    size_t count;
} apex_listener_set_t;

typedef struct {
    int fd;
    int udp_fd;
    uint16_t port;
    bool tls;
    struct apex_quic_server *quic_server;
} apex_worker_listener_t;

typedef enum { APEX_TRANSPORT_PLAIN, APEX_TRANSPORT_TLS } transport_kind_t;
typedef enum { APEX_TLS_HANDSHAKE, APEX_TLS_READY } tls_phase_t;

typedef struct conn {
    int fd;
    uint8_t active;
    uint8_t conn_state; /* 0: READING, 1: WRITING, 2: WAITING */
    uint32_t read_length;
    uint32_t write_length;
    uint32_t write_offset;
    uint8_t close_after_write;
    uint8_t epollout_active;
    transport_kind_t transport;
    SSL *ssl;
    tls_phase_t tls_phase;
    uint8_t tls_want_write;
    uint8_t alpn_h2;
    struct h2_conn *h2;
    char read_buffer[BUF_SIZE];
    char write_buffer[BUF_SIZE];
    char *aux_buffer;
    size_t aux_length;
    size_t aux_offset;
    size_t aux_capacity;
    int sendfile_fd;
    off_t sendfile_offset;
    size_t sendfile_remain;
    uint8_t corked;
    uint8_t is_virtual;
    uint64_t last_activity_ms;
    uint64_t request_count;
    apex_pool_t *pool;
    uint16_t listener_port;
    uint8_t is_tls;
    void *sendfile_cache_entry;
    char *trailers_buffer;
    size_t trailers_length;
} conn_t;

extern apex_server_stats_t g_apex_stats;

static inline void apex_record_status(int status) {
    if (status >= 200 && status < 300) {
        atomic_fetch_add_explicit(&g_apex_stats.responses_2xx, 1, memory_order_relaxed);
    } else if (status >= 300 && status < 400) {
        atomic_fetch_add_explicit(&g_apex_stats.responses_3xx, 1, memory_order_relaxed);
    } else if (status >= 400 && status < 500) {
        atomic_fetch_add_explicit(&g_apex_stats.responses_4xx, 1, memory_order_relaxed);
    } else if (status >= 500 && status < 600) {
        atomic_fetch_add_explicit(&g_apex_stats.responses_5xx, 1, memory_order_relaxed);
    }
}

void apex_conn_write(conn_t *connection, const void *data, size_t length);
void apex_conn_sendfile(conn_t *connection, int file_fd, off_t offset, size_t length);
void apex_conn_sendfile_cached(conn_t *connection, int file_fd, off_t offset, size_t length, void *cache_entry);
void router_send_error(conn_t *connection, const apex_server_config_t *server,
                       const char *request, size_t request_length,
                       int status, const char *reason, const char *message);
void router_send_error_ex(conn_t *connection, const apex_server_config_t *server,
                          const char *request, size_t request_length,
                          int status, const char *reason, const char *message,
                          const char *extra_headers, size_t extra_headers_len);

struct apex_res {
    conn_t *conn;
    int last_status;
    size_t last_body_bytes;
    char last_upstream_addr[64];
    int last_upstream_status;
    uint64_t last_upstream_time_us;
};

typedef struct {
    char method[8];
    char pattern[128];
    size_t pattern_len;
    int is_param;
    size_t prefix_len;
    apex_handler_t handler;
} apex_route_t;

typedef struct {
    _Atomic unsigned references;
    apex_config_t *config;
    apex_runtime_t *runtime;
    SSL_CTX *tls_context;
} apex_generation_t;

apex_generation_t *apex_generation_create(apex_config_t *config, apex_config_error_t *error);
void apex_generation_retain(apex_generation_t *generation);
void apex_generation_release(apex_generation_t *generation);

/* TLS transport (src/tls.c). A generation owns its SSL_CTX when the
 * configuration enables a TLS listener; plaintext configurations keep NULL. */
SSL_CTX *apex_tls_context_create(const apex_config_t *config, const apex_server_config_t *server,
                                 apex_config_error_t *error);
void apex_tls_context_destroy(SSL_CTX *context);
bool apex_tls_config_has_listener(const apex_config_t *config);
bool apex_tls_validate_config(const apex_config_t *config, apex_config_error_t *error);
bool apex_tls_reload_context(SSL_CTX *context, const char *cert_path, const char *key_path,
                             char *err_buf, size_t err_cap);
SSL_CTX *apex_tls_context_create_from_files(const char *cert_path, const char *key_path,
                                           char *err_buf, size_t err_cap);

typedef struct worker_arg worker_arg_t;

struct apex_app {
    apex_route_t routes[MAX_ROUTES];
    size_t route_count;
    apex_handler_t fast_get_root;
    apex_handler_t fast_get_user_id;
    apex_handler_t fast_post_user;
    apex_generation_t *generation;
    _Atomic bool running;
    worker_arg_t *workers;
    size_t worker_count;
};

void apex_dispatch(apex_app_t *app, const char *req_buf, size_t header_len, const char *body, size_t body_len,
                   apex_res_t *res);
void apex_dispatch_runtime(apex_app_t *app, const apex_runtime_t *runtime, const char *req_buf, size_t header_len,
                           const char *body, size_t body_len, apex_res_t *res);
void apex_router_thread_cleanup(void);

int apex_http1_parse_chunked(const char *src, size_t src_len, size_t *out_decoded_len, size_t *out_wire_len);
void apex_http1_decode_chunked_inplace(char *buf, size_t wire_len, size_t *out_len);

/* Worker event-loop plumbing shared by core.c and h2.c. */
enum { WORKERS_RUNNING, WORKERS_DRAINING, WORKERS_STOPPING };

typedef struct {
    _Atomic int shutdown;
    int status_fd;
} run_control_t;

struct worker_arg {
    pthread_t thread;
    int cpu;
    int epoll_fd;
    int listen_fd;
    apex_worker_listener_t listeners[APEX_CONFIG_MAX_LISTENERS];
    size_t listener_count;
    int wake_fd;
    int highest_fd;
    size_t connection_count;
    bool listener_tls;
    conn_t *connections;
    apex_app_t *app;
    run_control_t *control;
    apex_generation_t *generation;
    _Atomic(apex_generation_t *) pending_generation;
    _Atomic int error;
    _Atomic bool finished;
    apex_worker_metrics_t metrics;
#if defined(APEX_HAVE_URING)
    bool use_uring;
    struct io_uring ring;
#endif
} __attribute__((aligned(64)));

void apex_worker_set_current(worker_arg_t *worker);
apex_worker_metrics_t *apex_worker_get_current_metrics(void);
void apex_metrics_aggregate(const worker_arg_t *workers, size_t worker_count,
                            const apex_server_stats_t *stats, apex_aggregated_metrics_t *out);

/* Transport and connection helpers exported for the HTTP/2 session layer. */
int apex_transport_write(conn_t *connection, const void *data, size_t length);
ssize_t apex_transport_read(conn_t *connection);
void apex_close_connection(worker_arg_t *worker, conn_t *connection);
void apex_arm_connection_output(worker_arg_t *worker, conn_t *connection);

/* HTTP/2 session layer (src/h2.c), reached via ALPN on TLS connections. */
int h2_connection_create(conn_t *connection, worker_arg_t *worker);
void h2_connection_destroy(conn_t *connection);
void h2_read(worker_arg_t *worker, conn_t *connection);
void h2_flush(worker_arg_t *worker, conn_t *connection);
bool h2_has_pending_output(conn_t *connection);
void h2_drain(worker_arg_t *worker, conn_t *connection);
int h2_start_prior_knowledge(worker_arg_t *worker, conn_t *connection);
ssize_t h2_feed_data(conn_t *connection, const uint8_t *data, size_t length);

#endif /* APEX_INTERNAL_H */
