#ifndef APEX_MODULE_H
#define APEX_MODULE_H

#include "apex/config.h"
#include "apex/pool.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define APEX_MODULE_ABI_VERSION 1u
#define APEX_MODULE_MAX_DATA_SLOTS 16u
#define APEX_MODULE_EXTRA_HEADERS_MAX 2048u

typedef enum {
    APEX_PHASE_PRE_ROUTING = 0,
    APEX_PHASE_TLS_HANDSHAKE,
    APEX_PHASE_HEADER_FILTER,
    APEX_PHASE_ACCESS_CONTROL,
    APEX_PHASE_CONTENT_HANDLER,
    APEX_PHASE_RESPONSE_FILTER,
    APEX_PHASE_LOGGING,
    APEX_PHASE_COUNT
} apex_phase_t;

typedef enum {
    APEX_ACTION_CONTINUE = 0,
    APEX_ACTION_DONE,
    APEX_ACTION_ERROR,
    APEX_ACTION_DENY
} apex_action_t;

typedef struct apex_pipeline_ctx apex_pipeline_ctx_t;
typedef struct apex_module apex_module_t;
typedef struct conn conn_t;
typedef struct apex_res apex_res_t;

struct apex_pipeline_ctx {
    const char *method;
    size_t method_len;
    const char *path;
    size_t path_len;
    const char *raw_request;
    size_t raw_request_len;
    const char *body;
    size_t body_len;

    conn_t *conn;
    apex_res_t *res;
    apex_pool_t *pool;
    const apex_server_config_t *server;
    const apex_location_config_t *location;
    const apex_runtime_t *runtime;

    int status_code;
    uint64_t start_time_us;

    char extra_headers[APEX_MODULE_EXTRA_HEADERS_MAX];
    size_t extra_headers_len;

    char request_id[36];

    void *module_data[APEX_MODULE_MAX_DATA_SLOTS];
};

struct apex_module {
    const char *name;
    const char *version;
    uint32_t abi_version;

    int (*init)(apex_runtime_t *runtime);
    void (*cleanup)(apex_runtime_t *runtime);

    apex_action_t (*on_pre_routing)(apex_pipeline_ctx_t *ctx);
    apex_action_t (*on_tls_handshake)(apex_pipeline_ctx_t *ctx);
    apex_action_t (*on_header_filter)(apex_pipeline_ctx_t *ctx);
    apex_action_t (*on_access_control)(apex_pipeline_ctx_t *ctx);
    apex_action_t (*on_content_handler)(apex_pipeline_ctx_t *ctx);
    apex_action_t (*on_response_filter)(apex_pipeline_ctx_t *ctx);
    void (*on_logging)(apex_pipeline_ctx_t *ctx);
};

#define APEX_MODULE_EXPORT(mod) const apex_module_t apex_module = mod

/* Pipeline context helper functions */
bool apex_pipeline_add_header(apex_pipeline_ctx_t *ctx, const char *name, const char *value);
bool apex_pipeline_find_header(const apex_pipeline_ctx_t *ctx, const char *name,
                               const char **value, size_t *value_len);

/* Module lifecycle and pipeline execution */
int apex_module_registry_init(apex_runtime_t *runtime, const apex_config_t *config, apex_config_error_t *error);
void apex_module_registry_destroy(apex_runtime_t *runtime);
apex_action_t apex_pipeline_run_phase(apex_pipeline_ctx_t *ctx, apex_phase_t phase);

#ifdef __cplusplus
}
#endif

#endif /* APEX_MODULE_H */
