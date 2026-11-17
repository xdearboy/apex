#ifndef APEX_H
#define APEX_H

#include "apex/config.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct apex_req apex_req_t;
typedef struct apex_res apex_res_t;
typedef struct apex_app apex_app_t;

typedef void (*apex_handler_t)(apex_req_t *req, apex_res_t *res);

struct apex_req {
    const char *method;
    size_t method_len;
    const char *path;
    size_t path_len;
    const char *param;
    size_t param_len;
    const char *body;
    size_t body_len;
    void *user_data;
};

apex_app_t *apex_create(void);
void apex_destroy(apex_app_t *app);

void apex_get(apex_app_t *app, const char *pattern, apex_handler_t handler);
void apex_post(apex_app_t *app, const char *pattern, apex_handler_t handler);
void apex_route(apex_app_t *app, const char *method, const char *pattern, apex_handler_t handler);

void apex_res_send(apex_res_t *res, int status, const void *body, size_t body_len);
void apex_res_header(apex_res_t *res, const char *key, const char *value);

/* Attach configurations and register routes before running the app. On
 * successful attachment the app owns config; on failure the caller owns it. */
int apex_app_attach_config(apex_app_t *app, apex_config_t *config, apex_config_error_t *error);

/* These calls block until shutdown. SIGQUIT drains active requests and queued
 * responses; SIGINT/SIGTERM stop workers after their current handler returns.
 * Call from the main thread, before starting other application threads. */
int apex_run(apex_app_t *app, int port);

/* Run an attached configuration and reload config_path on SIGHUP. Failed
 * reloads preserve the active configuration. A listener change requires a
 * restart. The standalone core supports one plaintext listening endpoint. */
int apex_run_config(apex_app_t *app, const char *config_path);

#ifdef __cplusplus
}
#endif

#endif /* APEX_H */
