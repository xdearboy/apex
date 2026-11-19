#ifndef APEX_STATIC_H
#define APEX_STATIC_H

#include "apex/config.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct apex_res apex_res_t;

/* Comprehensive MIME detection based on file extension */
const char *apex_mime_type(const char *path);

/* HTTP Date / ETag formatting utilities (RFC 7231 / RFC 7232) */
void apex_static_format_etag(time_t mtime, off_t size, char *out, size_t out_size);
void apex_static_format_http_date(time_t time_val, char *out, size_t out_size);
bool apex_static_parse_http_date(const char *str, size_t len, time_t *out_time);

/* Core static file server: resolves path, indices, try_files, pre-compressed
 * twins (.br/.zst/.gz), ETag/304 Not Modified, Range requests (206), and
 * zero-copy sendfile(2) streaming. */
void apex_static_serve(const apex_server_config_t *server,
                         const apex_location_config_t *location,
                         const char *request, size_t request_len,
                         const char *path, size_t path_len,
                         bool head_request,
                         apex_res_t *res,
                         const char *extra_headers, size_t extra_headers_len);

void apex_static_cache_flush(void);

#ifdef __cplusplus
}
#endif

#endif /* APEX_STATIC_H */
