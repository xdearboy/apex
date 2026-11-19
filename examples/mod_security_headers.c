#include "apex/module.h"

#include <stdio.h>
#include <string.h>

static int security_headers_init(apex_runtime_t *runtime) {
    (void)runtime;
    return 0;
}

static void security_headers_cleanup(apex_runtime_t *runtime) {
    (void)runtime;
}

static apex_action_t security_headers_access_control(apex_pipeline_ctx_t *ctx) {
    if (ctx != NULL && ctx->path != NULL) {
        if (ctx->path_len >= 13 && strncmp(ctx->path, "/mod-forbidden", 14) == 0) {
            return APEX_ACTION_DENY;
        }
    }
    return APEX_ACTION_CONTINUE;
}

static apex_action_t security_headers_response_filter(apex_pipeline_ctx_t *ctx) {
    if (ctx != NULL) {
        apex_pipeline_add_header(ctx, "X-Content-Type-Options", "nosniff");
        apex_pipeline_add_header(ctx, "X-Frame-Options", "DENY");
        apex_pipeline_add_header(ctx, "X-Apex-Module", "mod_security_headers");
    }
    return APEX_ACTION_CONTINUE;
}

static const apex_module_t s_security_headers_module = {
    .name = "mod_security_headers",
    .version = "1.0.0",
    .abi_version = APEX_MODULE_ABI_VERSION,
    .init = security_headers_init,
    .cleanup = security_headers_cleanup,
    .on_pre_routing = NULL,
    .on_tls_handshake = NULL,
    .on_header_filter = NULL,
    .on_access_control = security_headers_access_control,
    .on_content_handler = NULL,
    .on_response_filter = security_headers_response_filter,
    .on_logging = NULL,
};

APEX_MODULE_EXPORT(s_security_headers_module);
