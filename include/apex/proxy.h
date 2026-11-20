#ifndef APEX_PROXY_H
#define APEX_PROXY_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define APEX_UPSTREAM_MAX_SERVERS 64u
#define APEX_PROXY_POOL_CAPACITY 64u
#define APEX_PROXY_DEFAULT_KEEPALIVE 32u
#define APEX_PROXY_DEFAULT_MAX_HEADER_BYTES (64u * 1024u)
#define APEX_PROXY_DEFAULT_MAX_BODY_BYTES (32u * 1024u * 1024u)
#define APEX_PROXY_DEFAULT_CONNECT_TIMEOUT_MS 2000u
#define APEX_PROXY_DEFAULT_IO_TIMEOUT_MS 10000u
#define APEX_PROXY_DEFAULT_IDLE_TIMEOUT_MS 60000u
#define APEX_PROXY_MAX_REQUEST_BYTES (64u * 1024u * 1024u)
#define APEX_PROXY_MAX_TRAILER_BYTES (64u * 1024u)

typedef enum {
    APEX_BALANCE_ROUND_ROBIN = 0,
    APEX_BALANCE_P2C = 1,
    APEX_BALANCE_LEAST_CONN = 2,
    APEX_BALANCE_IP_HASH = 3,
} apex_balance_policy_t;

typedef enum {
    APEX_PROXY_OK = 0,
    APEX_PROXY_ERR_INVALID = -1,
    APEX_PROXY_ERR_NO_UPSTREAM = -2,
    APEX_PROXY_ERR_CONNECT = -3,
    APEX_PROXY_ERR_TIMEOUT = -4,
    APEX_PROXY_ERR_IO = -5,
    APEX_PROXY_ERR_PROTOCOL = -6,
    APEX_PROXY_ERR_TOO_LARGE = -7,
    APEX_PROXY_ERR_ALLOC = -8,
} apex_proxy_error_t;

#define APEX_NEXT_UPSTREAM_NONE           0u
#define APEX_NEXT_UPSTREAM_ERROR          (1u << 0)
#define APEX_NEXT_UPSTREAM_TIMEOUT        (1u << 1)
#define APEX_NEXT_UPSTREAM_INVALID_HEADER (1u << 2)
#define APEX_NEXT_UPSTREAM_HTTP_500       (1u << 3)
#define APEX_NEXT_UPSTREAM_HTTP_502       (1u << 4)
#define APEX_NEXT_UPSTREAM_HTTP_503       (1u << 5)
#define APEX_NEXT_UPSTREAM_HTTP_504       (1u << 6)
#define APEX_NEXT_UPSTREAM_HTTP_403       (1u << 7)
#define APEX_NEXT_UPSTREAM_HTTP_404       (1u << 8)
#define APEX_NEXT_UPSTREAM_HTTP_429       (1u << 9)
#define APEX_NEXT_UPSTREAM_NON_IDEMPOTENT (1u << 10)
#define APEX_NEXT_UPSTREAM_OFF            (1u << 11)

#define APEX_NEXT_UPSTREAM_DEFAULT        (APEX_NEXT_UPSTREAM_ERROR | APEX_NEXT_UPSTREAM_TIMEOUT)

typedef struct {
    uint32_t conditions;
    uint32_t tries;
    uint64_t timeout_ms;
    bool has_conditions;
    bool has_tries;
    bool has_timeout;
} apex_next_upstream_config_t;

typedef struct {
    char ip[64];
    uint16_t port;
    uint32_t weight;
    bool is_backup;
    bool is_down;
    bool use_ssl;
    bool use_ssl_sni;
    char ssl_server_name[128];
    _Atomic int64_t active_conns;
    _Atomic uint64_t total_requests;
    _Atomic uint64_t failed_requests;
    _Atomic uint64_t bytes_sent;
    _Atomic uint64_t bytes_received;
    _Atomic bool healthy;
    _Atomic uint32_t consecutive_failures;
    _Atomic uint32_t consecutive_successes;
    _Atomic uint64_t last_failure_time_ms;
    struct sockaddr_storage address;
    socklen_t address_len;
} upstream_server_t;

typedef struct {
    upstream_server_t servers[APEX_UPSTREAM_MAX_SERVERS];
    size_t server_count;
    apex_balance_policy_t policy;
    uint32_t keepalive_capacity;
    uint32_t max_header_bytes;
    uint32_t max_body_bytes;
    uint64_t connect_timeout_ms;
    uint64_t io_timeout_ms;
    uint64_t idle_timeout_ms;
    uint32_t max_fails;
    uint64_t fail_timeout_ms;
    uint32_t max_retries;
    bool health_check_enabled;
    char health_check_uri[128];
    uint64_t health_check_interval_ms;
    uint64_t health_check_timeout_ms;
    uint32_t health_check_fall;
    uint32_t health_check_rise;
    bool use_ssl;
    bool use_ssl_sni;
    char ssl_server_name[128];
    _Atomic uint32_t round_robin_cursor;
} upstream_group_t;

/* headers is an optional CRLF-delimited block without the request line.
 * keep_alive asks the upstream to retain the connection for reuse. */
typedef struct {
    const char *method;
    const char *target;
    const char *host;
    const char *client_ip;
    const char *headers;
    size_t headers_len;
    const void *body;
    size_t body_len;
    bool keep_alive;
    bool use_ssl;
    const char *ssl_server_name;
    uint32_t next_upstream_conditions;
    uint32_t next_upstream_tries;
    uint64_t next_upstream_timeout_ms;
} apex_proxy_request_t;

/* headers holds the raw status line and header block; body is de-chunked.
 * keep_alive reports whether the upstream socket was actually cached. */
typedef struct {
    int status;
    char *headers;
    size_t headers_len;
    void *body;
    size_t body_len;
    bool chunked;
    bool keep_alive;
    size_t server_index;
    uint64_t elapsed_us;
    int upstream_fd;
    char *leftover_data;
    size_t leftover_len;
} apex_proxy_response_t;
typedef struct {
    size_t idle_connections;
    size_t capacity;
    size_t total_created;
    size_t total_reused;
    size_t total_closed;
} apex_proxy_pool_stats_t;

struct apex_resolver_config_s;

void apex_upstream_group_init(upstream_group_t *group);
int apex_upstream_add_server(upstream_group_t *group, const char *host, uint16_t port, uint32_t weight);
int apex_upstream_add_server_ex(upstream_group_t *group, const char *host, uint16_t port, uint32_t weight,
                                bool is_backup, bool is_down);
int apex_upstream_add_server_resolver(upstream_group_t *group, const char *host, uint16_t port, uint32_t weight,
                                      bool is_backup, bool is_down, const struct apex_resolver_config_s *resolver);
void apex_dns_cache_flush(void);
void apex_upstream_set_policy(upstream_group_t *group, apex_balance_policy_t policy);
ssize_t apex_upstream_select(upstream_group_t *group);
ssize_t apex_upstream_select_excluding(upstream_group_t *group, uint64_t excluded_mask);
ssize_t apex_upstream_select_request(upstream_group_t *group, uint64_t excluded_mask, const char *client_ip);
void apex_upstream_record_success(upstream_group_t *group, size_t server_index);
void apex_upstream_record_failure(upstream_group_t *group, size_t server_index);

int apex_health_prober_start(upstream_group_t *groups, size_t group_count);
void apex_health_prober_stop(void);

void apex_proxy_response_init(apex_proxy_response_t *response);
void apex_proxy_response_free(apex_proxy_response_t *response);

/* Blocking HTTP/1.1 exchange. The group may be shared between threads; each
 * calling thread owns its own idle connection cache. */
int apex_proxy_forward(upstream_group_t *group, const apex_proxy_request_t *request,
                       apex_proxy_response_t *response);

/* Operate on the calling thread's idle connection cache only. */
void apex_proxy_pool_reset(void);
void apex_proxy_pool_get_stats(apex_proxy_pool_stats_t *stats);

const char *apex_proxy_strerror(int error_code);

#ifdef __cplusplus
}
#endif

#endif /* APEX_PROXY_H */
