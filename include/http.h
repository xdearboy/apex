#ifndef HTTP_H
#define HTTP_H

#include "tachyon.h"

#define MAX_ROUTES 1024
#define MAX_URI_LEN 256
#define ROUTE_HASH_SIZE 2048   /* power of two, >= 2*MAX_ROUTES */

typedef struct {
    char   path[MAX_URI_LEN];
    size_t path_len;
    char  *response_buf;
    size_t response_len;
} http_route_t;

int http_init_routes(const char *root_dir);
void http_free_routes(void);
const http_route_t *http_find_route(const char *path, size_t path_len);
const char *http_get_404_response(size_t *len);

#endif /* HTTP_H */
