#ifndef APEX_CONFIG_H
#define APEX_CONFIG_H

#include "apex/proxy.h"

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
#define APEX_CONFIG_MAX_INCLUDE_DEPTH 16u
#define APEX_CONFIG_MAX_FILE_BYTES (8u * 1024u * 1024u)
#define APEX_CONFIG_MAX_TOKENS (1024u * 1024u)

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

    apex_config_header_t *headers;
    size_t header_count;
    size_t header_capacity;

    bool has_connect_timeout;
    uint64_t connect_timeout_ms;
    bool has_read_timeout;
    uint64_t read_timeout_ms;

    int http_version;
} apex_location_config_t;

typedef struct {
    char host[APEX_CONFIG_HOST_MAX];
    uint16_t port;
    uint32_t weight;
    uint32_t max_conns;
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
    int status_code;
    char *path;
    int line;
} apex_error_page_config_t;

typedef struct {
    char listen_host[APEX_CONFIG_HOST_MAX];
    uint16_t listen_port;
    bool listen_tls;
    char **server_names;
    size_t server_name_count;
    size_t server_name_capacity;
    apex_tls_config_t tls;
    apex_location_config_t *locations;
    size_t location_count;
    size_t location_capacity;
    apex_error_page_config_t *error_pages;
    size_t error_page_count;
    size_t error_page_capacity;
    int line;
} apex_server_config_t;

typedef struct {
    uint32_t worker_connections;
    uint64_t keepalive_timeout_ms;
    uint64_t client_header_timeout_ms;
    uint64_t client_body_timeout_ms;
    bool server_tokens;
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

typedef struct {
    const apex_config_t *config;
    upstream_group_t *groups;
    size_t group_count;
    apex_endpoint_group_t *endpoint_groups;
    size_t endpoint_group_count;
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

#ifdef __cplusplus
}
#endif

#endif /* APEX_CONFIG_H */
