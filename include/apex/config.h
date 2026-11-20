#ifndef APEX_CONFIG_H
#define APEX_CONFIG_H

#include "apex/proxy.h"
#include "apex/compress.h"

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define APEX_CONFIG_NAME_MAX 96u
#define APEX_CONFIG_HOST_MAX 96u
#define APEX_CONFIG_PATH_MAX 512u
#define APEX_CONFIG_MESSAGE_MAX 256u
#define APEX_CONFIG_HINT_MAX 160u

#define APEX_CONFIG_MAX_UPSTREAM_SERVERS 64u
#define APEX_CONFIG_MAX_LOCATIONS 64u
#define APEX_CONFIG_MAX_SERVER_NAMES 32u
#define APEX_CONFIG_MAX_HEADERS 32u
#define APEX_CONFIG_MAX_MODULE_NAMES 32u
#define APEX_CONFIG_MAX_ACL_RULES 32u
#define APEX_CONFIG_MAX_RATE_ZONES 16u
#define APEX_CONFIG_MAX_CONN_ZONES 16u
#define APEX_CONFIG_MAX_INCLUDE_DEPTH 16u
#define APEX_CONFIG_MAX_FILE_BYTES (8u * 1024u * 1024u)
#define APEX_CONFIG_MAX_TOKENS (1024u * 1024u)

typedef struct {
    char name[64];
    char key_var[64];
    size_t size_bytes;
    uint32_t rate_r_s;
    double rate_per_sec;
} apex_rate_limit_zone_t;

typedef struct {
    char name[64];
    char key_var[64];
    size_t size_bytes;
} apex_conn_limit_zone_t;

typedef struct {
    int status_code;
    uint64_t valid_ms;
} apex_cache_valid_rule_t;

typedef struct {
    char name[64];
    char path[APEX_CONFIG_PATH_MAX];
    size_t keys_zone_size;
    size_t max_size;
    uint64_t inactive_ms;
} apex_cache_zone_config_t;

typedef struct {
    bool allow;   /* true for allow, false for deny */
    bool is_all;  /* true if matches all */
    bool is_ipv6;
    struct in_addr addr4;
    struct in_addr mask4;
    struct in6_addr addr6;
    struct in6_addr mask6;
} apex_acl_rule_t;

#define APEX_CONFIG_MAX_LOG_FORMATS 16
#define APEX_CONFIG_MAX_REAL_IP_RULES 32

typedef struct {
    bool is_all;
    bool is_ipv6;
    struct in_addr addr4;
    struct in_addr mask4;
    struct in6_addr addr6;
    struct in6_addr mask6;
} apex_real_ip_rule_t;

typedef struct {
    char name[64];
    char format[512];
} apex_log_format_config_t;

typedef struct {
    bool off;
    char path[APEX_CONFIG_PATH_MAX];
    char format_name[64];
    size_t buffer_size;
    uint64_t flush_ms;
} apex_access_log_config_t;

typedef enum {
    APEX_CONFIG_OK = 0,
    APEX_CONFIG_ERR_IO = -1,
    APEX_CONFIG_ERR_SYNTAX = -2,
    APEX_CONFIG_ERR_SEMANTIC = -3,
    APEX_CONFIG_ERR_MEMORY = -4,
    APEX_CONFIG_ERR_RUNTIME = -5,
} apex_config_status_t;

typedef struct {
    apex_config_status_t code;
    char file[APEX_CONFIG_PATH_MAX];
    int line;
    int column;
    char message[APEX_CONFIG_MESSAGE_MAX];
    char hint[APEX_CONFIG_HINT_MAX];
} apex_config_error_t;

typedef struct {
    char *name;
    char *value;
    int line;
} apex_config_header_t;

typedef struct {
    char *name;
    char *value;
    bool always;
    int line;
} apex_add_header_t;

typedef enum {
    APEX_SERVER_TOKENS_OFF = 0,
    APEX_SERVER_TOKENS_ON = 1,
    APEX_SERVER_TOKENS_CUSTOM = 2,
} apex_server_tokens_mode_t;

typedef struct {
    apex_server_tokens_mode_t mode;
    char custom_value[128];
    bool set;
} apex_server_tokens_config_t;

typedef struct {
    char *key;
    char *value;
    bool is_wildcard_prefix;
    bool is_wildcard_suffix;
} apex_map_entry_t;

typedef struct {
    char source_var[64];
    char target_var[64];
    char default_value[256];
    apex_map_entry_t *entries;
    size_t entry_count;
    size_t entry_capacity;
} apex_map_t;

typedef struct {
    char domain[APEX_CONFIG_HOST_MAX];
    char replacement[APEX_CONFIG_HOST_MAX];
} apex_cookie_domain_rule_t;

typedef struct {
    char path[APEX_CONFIG_PATH_MAX];
    char replacement[APEX_CONFIG_PATH_MAX];
} apex_cookie_path_rule_t;

typedef struct {
    char match[256];
    char replacement[256];
} apex_sub_filter_rule_t;

typedef struct {
    apex_sub_filter_rule_t *rules;
    size_t rule_count;
    size_t rule_capacity;
    bool once;
    char **types;
    size_t type_count;
    size_t type_capacity;
    bool is_set;
} apex_sub_filter_config_t;

typedef struct apex_resolver_config_s {
    char servers[4][APEX_CONFIG_HOST_MAX];
    size_t server_count;
    uint32_t valid_ms;
    uint32_t timeout_ms;
    bool is_set;
} apex_resolver_config_t;

typedef enum {
    APEX_OTEL_CTX_OFF = 0,
    APEX_OTEL_CTX_ON,
    APEX_OTEL_CTX_PROPAGATE,
} apex_otel_ctx_mode_t;

typedef struct {
    bool enabled;
    apex_otel_ctx_mode_t context_mode;
    char span_name[128];
    bool is_set;
} apex_otel_config_t;

typedef struct {
    bool enabled;
    bool write_enabled;
} apex_api_config_t;

typedef struct {
    int status_code;
    char *path;
    int line;
} apex_error_page_config_t;

typedef enum {
    APEX_PROXY_TARGET_NONE = 0,
    APEX_PROXY_TARGET_UPSTREAM,
    APEX_PROXY_TARGET_ENDPOINT,
} apex_proxy_target_t;

typedef struct {
    char *path;
    bool exact;
    int line;

    apex_proxy_target_t target;
    char *upstream_name;
    size_t upstream_index;
    char *endpoint_host;
    uint16_t endpoint_port;

    char *root;
    char **indices;
    size_t index_count;
    size_t index_capacity;
    char **try_files;
    size_t try_files_count;
    size_t try_files_capacity;
    bool sendfile;
    bool etag;
    bool precompressed;

    int return_code;
    char return_url[APEX_CONFIG_PATH_MAX * 2];

    apex_acl_rule_t acl_rules[APEX_CONFIG_MAX_ACL_RULES];
    size_t acl_rule_count;

    apex_config_header_t *headers;
    size_t header_count;
    size_t header_capacity;

    bool has_connect_timeout;
    uint64_t connect_timeout_ms;
    bool has_read_timeout;
    uint64_t read_timeout_ms;

    char limit_req_zone[64];
    uint32_t limit_req_burst;
    bool limit_req_nodelay;
    int limit_req_status;

    char limit_conn_zone[64];
    uint32_t limit_conn_max;
    int limit_conn_status;

    bool stub_status;
    bool metrics;

    char proxy_cache[64];
    char proxy_cache_key[128];
    char proxy_cache_bypass[64];
    apex_cache_valid_rule_t cache_valid_rules[8];
    size_t cache_valid_rule_count;
    apex_access_log_config_t access_log;
    bool has_access_log;

    apex_real_ip_rule_t real_ip_rules[APEX_CONFIG_MAX_REAL_IP_RULES];
    size_t real_ip_rule_count;
    char real_ip_header[64];
    bool real_ip_recursive;
    bool has_real_ip_header;
    bool has_real_ip_recursive;

    char fastcgi_pass[APEX_CONFIG_PATH_MAX];
    char fastcgi_index[64];
    apex_config_header_t *fastcgi_params;
    size_t fastcgi_param_count;
    size_t fastcgi_param_capacity;

    int http_version;
    apex_add_header_t *add_headers;
    size_t add_header_count;
    size_t add_header_capacity;

    bool proxy_ssl_server_name;
    char proxy_ssl_name[APEX_CONFIG_HOST_MAX];
    bool proxy_pass_ssl;
    bool proxy_pass_dynamic;
    char proxy_pass_raw[APEX_CONFIG_PATH_MAX];
    apex_compress_config_t compress;
    bool has_compress;

    apex_error_page_config_t *error_pages;
    size_t error_page_count;
    size_t error_page_capacity;
    apex_next_upstream_config_t next_upstream;
    bool has_next_upstream;
    bool proxy_intercept_errors;
    bool has_proxy_intercept_errors;

    apex_cookie_domain_rule_t *cookie_domains;
    size_t cookie_domain_count;
    size_t cookie_domain_capacity;
    bool cookie_domain_off;

    apex_cookie_path_rule_t *cookie_paths;
    size_t cookie_path_count;
    size_t cookie_path_capacity;
    bool cookie_path_off;

    apex_sub_filter_config_t sub_filter;

    apex_resolver_config_t resolver;
    apex_otel_config_t otel;
    apex_api_config_t api;
} apex_location_config_t;

typedef struct {
    char host[APEX_CONFIG_HOST_MAX];
    uint16_t port;
    uint32_t weight;
    uint32_t max_conns;
    bool is_backup;
    bool is_down;
    int line;
} apex_upstream_server_config_t;

typedef struct {
    char *name;
    int line;
    apex_upstream_server_config_t *servers;
    size_t server_count;
    size_t server_capacity;
    apex_balance_policy_t policy;
    uint32_t keepalive;
    uint64_t connect_timeout_ms;
    uint64_t read_timeout_ms;
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
} apex_upstream_config_t;

typedef enum {
    APEX_TLS_CLIENT_AUTH_OFF = 0,
    APEX_TLS_CLIENT_AUTH_OPTIONAL,
    APEX_TLS_CLIENT_AUTH_REQUIRED,
} apex_tls_client_auth_t;

typedef struct {
    bool enabled;
    char *certificate;
    char *private_key;
    char *ciphers;
    char **protocols;
    size_t protocol_count;
    size_t protocol_capacity;
    apex_tls_client_auth_t client_auth;
} apex_tls_config_t;

typedef struct {
    char listen_host[APEX_CONFIG_HOST_MAX];
    uint16_t listen_port;
    bool listen_tls;
    char **server_names;
    size_t server_name_count;
    size_t server_name_capacity;
    apex_tls_config_t tls;
    char *root;
    apex_location_config_t *locations;
    size_t location_count;
    size_t location_capacity;
    apex_error_page_config_t *error_pages;
    size_t error_page_count;
    size_t error_page_capacity;
    int return_code;
    char return_url[APEX_CONFIG_PATH_MAX * 2];
    apex_acl_rule_t acl_rules[APEX_CONFIG_MAX_ACL_RULES];
    size_t acl_rule_count;
    char limit_req_zone[64];
    uint32_t limit_req_burst;
    bool limit_req_nodelay;
    int limit_req_status;
    char limit_conn_zone[64];
    uint32_t limit_conn_max;
    int limit_conn_status;
    char proxy_cache[64];
    char proxy_cache_key[128];
    char proxy_cache_bypass[64];
    apex_cache_valid_rule_t cache_valid_rules[8];
    size_t cache_valid_rule_count;
    apex_access_log_config_t access_log;
    bool has_access_log;
    apex_real_ip_rule_t real_ip_rules[APEX_CONFIG_MAX_REAL_IP_RULES];
    size_t real_ip_rule_count;
    char real_ip_header[64];
    bool real_ip_recursive;
    bool has_real_ip_header;
    bool has_real_ip_recursive;
    apex_add_header_t *add_headers;
    size_t add_header_count;
    size_t add_header_capacity;
    apex_server_tokens_config_t server_tokens;
    apex_compress_config_t compress;
    bool has_compress;
    apex_next_upstream_config_t next_upstream;
    bool has_next_upstream;
    bool proxy_intercept_errors;
    bool has_proxy_intercept_errors;
    apex_cookie_domain_rule_t *cookie_domains;
    size_t cookie_domain_count;
    size_t cookie_domain_capacity;
    bool cookie_domain_off;
    apex_cookie_path_rule_t *cookie_paths;
    size_t cookie_path_count;
    size_t cookie_path_capacity;
    bool cookie_path_off;
    apex_sub_filter_config_t sub_filter;
    apex_resolver_config_t resolver;
    apex_otel_config_t otel;
    apex_api_config_t api;
    int line;
} apex_server_config_t;

typedef struct {
    uint32_t worker_connections;
    uint64_t keepalive_timeout_ms;
    uint64_t client_header_timeout_ms;
    uint64_t client_body_timeout_ms;
    apex_server_tokens_config_t server_tokens;
    apex_rate_limit_zone_t rate_zones[APEX_CONFIG_MAX_RATE_ZONES];
    size_t rate_zone_count;
    apex_conn_limit_zone_t conn_zones[APEX_CONFIG_MAX_CONN_ZONES];
    size_t conn_zone_count;
    apex_cache_zone_config_t cache_zones[APEX_CONFIG_MAX_RATE_ZONES];
    size_t cache_zone_count;
    apex_log_format_config_t log_formats[APEX_CONFIG_MAX_LOG_FORMATS];
    size_t log_format_count;
    apex_access_log_config_t access_log;
    bool has_access_log;
    apex_real_ip_rule_t real_ip_rules[APEX_CONFIG_MAX_REAL_IP_RULES];
    size_t real_ip_rule_count;
    char real_ip_header[64];
    bool real_ip_recursive;
    bool has_real_ip_header;
    bool has_real_ip_recursive;
    apex_add_header_t *add_headers;
    size_t add_header_count;
    size_t add_header_capacity;
    apex_map_t *maps;
    size_t map_count;
    size_t map_capacity;
    apex_compress_config_t compress;
    bool has_compress;
    apex_next_upstream_config_t next_upstream;
    bool has_next_upstream;
    bool proxy_intercept_errors;
    bool has_proxy_intercept_errors;
    apex_cookie_domain_rule_t *cookie_domains;
    size_t cookie_domain_count;
    size_t cookie_domain_capacity;
    bool cookie_domain_off;
    apex_cookie_path_rule_t *cookie_paths;
    size_t cookie_path_count;
    size_t cookie_path_capacity;
    bool cookie_path_off;
    apex_sub_filter_config_t sub_filter;
    apex_resolver_config_t resolver;
    apex_otel_config_t otel;
} apex_http_config_t;

typedef struct {
    apex_http_config_t http;
    apex_upstream_config_t *upstreams;
    size_t upstream_count;
    size_t upstream_capacity;
    apex_server_config_t *servers;
    size_t server_count;
    size_t server_capacity;
    char **modules;
    size_t module_count;
    size_t module_capacity;
    char source[APEX_CONFIG_PATH_MAX];
} apex_config_t;

typedef struct {
    const apex_location_config_t *location;
    upstream_group_t group;
} apex_endpoint_group_t;

struct apex_module_registry;

typedef struct {
    const apex_config_t *config;
    upstream_group_t *groups;
    size_t group_count;
    apex_endpoint_group_t *endpoint_groups;
    size_t endpoint_group_count;
    struct apex_module_registry *module_registry;
    void *rate_limiter;
    void *cache_manager;
    void *log_manager;
} apex_runtime_t;

typedef struct {
    const apex_server_config_t *server;
    const apex_location_config_t *location;
    const upstream_group_t *group;
    size_t upstream_index;
} apex_config_route_t;

int apex_config_parse_file(const char *path, apex_config_t **config, apex_config_error_t *error);
int apex_config_parse_string(const char *name, const char *text, size_t length, apex_config_t **config,
                             apex_config_error_t *error);
int apex_config_check_file(const char *path, apex_config_error_t *error);
void apex_config_free(apex_config_t *config);
const char *apex_config_strerror(apex_config_status_t code);
const apex_upstream_config_t *apex_config_find_upstream(const apex_config_t *config, const char *name);
int apex_config_first_listen_port(const apex_config_t *config);

apex_runtime_t *apex_runtime_create(const apex_config_t *config, apex_config_error_t *error);
void apex_runtime_destroy(apex_runtime_t *runtime);
const upstream_group_t *apex_runtime_upstream(const apex_runtime_t *runtime, size_t index);
const upstream_group_t *apex_runtime_endpoint_group(const apex_runtime_t *runtime,
                                                    const apex_location_config_t *location);
bool apex_runtime_match(const apex_runtime_t *runtime, const char *host, size_t host_length, const char *path,
                        size_t path_length, apex_config_route_t *route);

bool apex_rate_limit_check(const apex_runtime_t *runtime, const char *zone_name, const char *client_ip,
                           uint32_t burst, bool nodelay, uint32_t *retry_after_sec);
bool apex_conn_limit_acquire(const apex_runtime_t *runtime, const char *zone_name, const char *client_ip,
                             uint32_t max_conns);
void apex_conn_limit_release(const apex_runtime_t *runtime, const char *zone_name, const char *client_ip);
const char *apex_map_lookup(const apex_config_t *config, const char *target_var, const char *source_val);
const apex_compress_config_t *apex_config_get_compress(const apex_server_config_t *server,
                                                       const apex_location_config_t *location,
                                                       const apex_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* APEX_CONFIG_H */
