#ifndef APEX_H
#define APEX_H

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

int apex_run(apex_app_t *app, int port);

#ifdef __cplusplus
}
#endif

#endif /* APEX_H */
