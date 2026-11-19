#ifndef APEX_INTERNAL_H
#define APEX_INTERNAL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "apex.h"
#include "apex/module.h"
#include "apex/static.h"

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

#define MAX_FDS 65536
#define MAX_EVENTS 512
#define BUF_SIZE 4096
#define MAX_ROUTES 128

typedef enum { APEX_TRANSPORT_PLAIN, APEX_TRANSPORT_TLS } transport_kind_t;
typedef enum { APEX_TLS_HANDSHAKE, APEX_TLS_READY } tls_phase_t;

typedef struct conn {
    int fd;
    uint8_t active;
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
    int sendfile_fd;
    off_t sendfile_offset;
    size_t sendfile_remain;
    uint8_t corked;
} conn_t;

void apex_conn_write(conn_t *connection, const void *data, size_t length);
void apex_conn_sendfile(conn_t *connection, int file_fd, off_t offset, size_t length);
void router_send_error(conn_t *connection, const apex_server_config_t *server,
                       const char *request, size_t request_length,
                       int status, const char *reason, const char *message);
void router_send_error_ex(conn_t *connection, const apex_server_config_t *server,
                          const char *request, size_t request_length,
                          int status, const char *reason, const char *message,
                          const char *extra_headers, size_t extra_headers_len);
void apex_proxy_ws_tunnel(conn_t *client_conn, int upstream_fd, uint64_t timeout_ms);

struct apex_res {
    conn_t *conn;
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

struct apex_app {
    apex_route_t routes[MAX_ROUTES];
    size_t route_count;
    apex_handler_t fast_get_root;
    apex_handler_t fast_get_user_id;
    apex_handler_t fast_post_user;
    apex_generation_t *generation;
    _Atomic bool running;
};

void apex_dispatch(apex_app_t *app, const char *req_buf, size_t header_len, const char *body, size_t body_len,
                   apex_res_t *res);
void apex_dispatch_runtime(apex_app_t *app, const apex_runtime_t *runtime, const char *req_buf, size_t header_len,
                           const char *body, size_t body_len, apex_res_t *res);

/* Module lifecycle and pipeline execution (src/module.c) */
int apex_module_registry_init(apex_runtime_t *runtime, const apex_config_t *config, apex_config_error_t *error);
void apex_module_registry_destroy(apex_runtime_t *runtime);
apex_action_t apex_pipeline_run_phase(apex_pipeline_ctx_t *ctx, apex_phase_t phase);

/* Worker event-loop plumbing shared by core.c and h2.c. */
enum { WORKERS_RUNNING, WORKERS_DRAINING, WORKERS_STOPPING };

typedef struct {
    _Atomic int shutdown;
    int status_fd;
} run_control_t;

typedef struct {
    pthread_t thread;
    int cpu;
    int epoll_fd;
    int listen_fd;
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
} worker_arg_t;

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

#endif /* APEX_INTERNAL_H */
