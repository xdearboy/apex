#ifndef APEX_HTTP_API_H
#define APEX_HTTP_API_H

#include "apex/config.h"
#include "internal.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Handle dynamic upstream administration REST API requests (e.g. /api/upstreams).
 */
void apex_http_api_handle(conn_t *connection, const apex_runtime_t *runtime,
                          const apex_server_config_t *server,
                          const apex_location_config_t *location,
                          const char *req_buf, size_t req_buf_len,
                          const char *method, size_t method_len,
                          const char *path, size_t path_len,
                          const char *body, size_t body_len,
                          apex_res_t *res,
                          const char *extra_headers, size_t extra_headers_len,
                          const char *client_ip);

#ifdef __cplusplus
}
#endif

#endif /* APEX_HTTP_API_H */
