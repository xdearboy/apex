#ifndef APEX_LOG_H
#define APEX_LOG_H

#include "apex/config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    APEX_LOG_VAR_REMOTE_ADDR,
    APEX_LOG_VAR_REMOTE_USER,
    APEX_LOG_VAR_TIME_LOCAL,
    APEX_LOG_VAR_TIME_ISO8601,
    APEX_LOG_VAR_REQUEST,
    APEX_LOG_VAR_REQUEST_METHOD,
    APEX_LOG_VAR_REQUEST_URI,
    APEX_LOG_VAR_SERVER_PROTOCOL,
    APEX_LOG_VAR_STATUS,
    APEX_LOG_VAR_BODY_BYTES_SENT,
    APEX_LOG_VAR_BYTES_SENT,
    APEX_LOG_VAR_HTTP_REFERER,
    APEX_LOG_VAR_HTTP_USER_AGENT,
    APEX_LOG_VAR_UPSTREAM_ADDR,
    APEX_LOG_VAR_UPSTREAM_STATUS,
    APEX_LOG_VAR_UPSTREAM_RESPONSE_TIME,
    APEX_LOG_VAR_REQUEST_TIME,
    APEX_LOG_VAR_REQUEST_ID,
    APEX_LOG_VAR_HTTP_CUSTOM,
    APEX_LOG_ITEM_LITERAL
} apex_log_item_type_t;

typedef struct {
    apex_log_item_type_t type;
    char literal[128];
    char custom_header[64];
} apex_log_item_t;

typedef struct {
    char name[64];
    apex_log_item_t *items;
    size_t item_count;
    size_t item_capacity;
} apex_log_format_t;

typedef struct {
    const char *client_ip;
    const char *method;
    size_t method_len;
    const char *uri;
    size_t uri_len;
    const char *protocol;
    const char *raw_request;
    size_t raw_request_len;
    int status;
    size_t bytes_sent;
    size_t body_bytes_sent;
    uint64_t start_time_us;
    uint64_t end_time_us;
    const char *upstream_addr;
    int upstream_status;
    uint64_t upstream_time_us;
    const char *request_id;
} apex_log_ctx_t;

int apex_log_manager_init(apex_runtime_t *runtime);
void apex_log_manager_destroy(apex_runtime_t *runtime);
int apex_log_format_compile(const char *name, const char *fmt_str, apex_log_format_t *out_fmt);
void apex_log_format_free(apex_log_format_t *fmt);
void apex_access_log_write(apex_runtime_t *runtime, const apex_location_config_t *location,
                           const apex_server_config_t *server, const apex_log_ctx_t *ctx);
void apex_access_log_flush_all(apex_runtime_t *runtime);

#ifdef __cplusplus
}
#endif

#endif /* APEX_LOG_H */
