#include "apex/module.h"
#include "internal.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

typedef struct {
    int blocked;
    int status_code;
    int rule_id;
    char rule_msg[256];
} coraza_verdict_t;

extern int coraza_bridge_init(const char *directives);
extern void coraza_bridge_destroy(void);
extern int coraza_bridge_eval(const char *client_ip, const char *method, const char *uri,
                              const char *proto, const char *raw_headers, size_t headers_len,
                              const char *body, size_t body_len, coraza_verdict_t *out_verdict);

static int mod_coraza_init(apex_runtime_t *runtime) {
    (void)runtime;
    const char *rules_file = getenv("APEX_CORAZA_RULES");
    if (rules_file == NULL) {
        rules_file = "modules/mod_coraza/default_rules.conf";
    }
    return coraza_bridge_init(rules_file);
}

static void mod_coraza_cleanup(apex_runtime_t *runtime) {
    (void)runtime;
    coraza_bridge_destroy();
}

#define APEX_CORAZA_CACHE_SLOTS 1024
#define APEX_CORAZA_CACHE_TTL 2 /* seconds */

typedef struct {
    uint64_t hash;
    time_t expires_at;
    int is_clean;
} coraza_cache_entry_t;

typedef struct {
    coraza_cache_entry_t entries[APEX_CORAZA_CACHE_SLOTS];
} coraza_thread_cache_t;

static __thread coraza_thread_cache_t s_coraza_cache;

static inline uint64_t coraza_fnv1a_hash(const char *data, size_t len) {
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint8_t)data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static apex_action_t mod_coraza_access_control(apex_pipeline_ctx_t *ctx) {
    if (ctx == NULL) {
        return APEX_ACTION_CONTINUE;
    }

    time_t now = time(NULL);
    bool can_cache = (ctx->body == NULL || ctx->body_len == 0) &&
                     ((ctx->method_len == 3 && memcmp(ctx->method, "GET", 3) == 0) ||
                      (ctx->method_len == 4 && memcmp(ctx->method, "HEAD", 4) == 0));
    uint64_t req_hash = 0;
    uint32_t slot = 0;

    if (can_cache && ctx->raw_request != NULL && ctx->raw_request_len > 0) {
        req_hash = coraza_fnv1a_hash(ctx->raw_request, ctx->raw_request_len);
        slot = (uint32_t)(req_hash % APEX_CORAZA_CACHE_SLOTS);
        if (s_coraza_cache.entries[slot].is_clean &&
            s_coraza_cache.entries[slot].hash == req_hash &&
            now < s_coraza_cache.entries[slot].expires_at) {
            return APEX_ACTION_CONTINUE;
        }
    }

    char client_ip[64] = "127.0.0.1";
    if (ctx->conn != NULL && ctx->conn->fd >= 0) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        if (getpeername(ctx->conn->fd, (struct sockaddr *)&addr, &addr_len) == 0) {
            if (addr.ss_family == AF_INET) {
                struct sockaddr_in *s4 = (struct sockaddr_in *)&addr;
                inet_ntop(AF_INET, &s4->sin_addr, client_ip, sizeof(client_ip));
            } else if (addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&addr;
                inet_ntop(AF_INET6, &s6->sin6_addr, client_ip, sizeof(client_ip));
            }
        }
    }

    char method_buf[16] = {0};
    if (ctx->method != NULL && ctx->method_len > 0 && ctx->method_len < sizeof(method_buf)) {
        memcpy(method_buf, ctx->method, ctx->method_len);
    } else {
        snprintf(method_buf, sizeof(method_buf), "GET");
    }

    char uri_buf[APEX_CONFIG_PATH_MAX * 2] = {0};
    if (ctx->path != NULL && ctx->path_len > 0 && ctx->path_len < sizeof(uri_buf)) {
        memcpy(uri_buf, ctx->path, ctx->path_len);
    } else {
        snprintf(uri_buf, sizeof(uri_buf), "/");
    }

    coraza_verdict_t verdict = {0};
    int ret = coraza_bridge_eval(client_ip, method_buf, uri_buf, "HTTP/1.1",
                                 ctx->raw_request, ctx->raw_request_len,
                                 ctx->body, ctx->body_len, &verdict);

    if (ret != 0 || verdict.blocked != 0) {
        if (can_cache && req_hash != 0) {
            s_coraza_cache.entries[slot].is_clean = 0;
            s_coraza_cache.entries[slot].hash = 0;
        }
        ctx->status_code = verdict.status_code > 0 ? verdict.status_code : 403;
        char waf_header_val[128];
        snprintf(waf_header_val, sizeof(waf_header_val), "Blocked by Coraza (Rule %d)", verdict.rule_id);
        apex_pipeline_add_header(ctx, "X-Apex-WAF", waf_header_val);
        return APEX_ACTION_DENY;
    }

    if (can_cache && req_hash != 0) {
        s_coraza_cache.entries[slot].hash = req_hash;
        s_coraza_cache.entries[slot].expires_at = now + APEX_CORAZA_CACHE_TTL;
        s_coraza_cache.entries[slot].is_clean = 1;
    }

    return APEX_ACTION_CONTINUE;
}

static const apex_module_t s_mod_coraza = {
    .name = "mod_coraza",
    .version = "1.0.0",
    .abi_version = APEX_MODULE_ABI_VERSION,
    .init = mod_coraza_init,
    .cleanup = mod_coraza_cleanup,
    .on_pre_routing = NULL,
    .on_tls_handshake = NULL,
    .on_header_filter = NULL,
    .on_access_control = mod_coraza_access_control,
    .on_content_handler = NULL,
    .on_response_filter = NULL,
    .on_logging = NULL,
};

APEX_MODULE_EXPORT(s_mod_coraza);
