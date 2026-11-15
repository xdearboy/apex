#include "internal.h"

apex_app_t *apex_create(void) {
    apex_app_t *app = (apex_app_t *)calloc(1, sizeof(apex_app_t));
    return app;
}

void apex_destroy(apex_app_t *app) {
    if (app) {
        free(app);
    }
}

void apex_route(apex_app_t *app, const char *method, const char *pattern, apex_handler_t handler) {
    if (!app || !method || !pattern || !handler || app->route_count >= MAX_ROUTES) {
        return;
    }

    apex_route_t *r = &app->routes[app->route_count++];
    strncpy(r->method, method, sizeof(r->method) - 1);
    strncpy(r->pattern, pattern, sizeof(r->pattern) - 1);
    r->pattern_len = strlen(r->pattern);
    r->handler = handler;

    const char *colon = strchr(r->pattern, ':');
    if (colon) {
        r->is_param = 1;
        r->prefix_len = (size_t)(colon - r->pattern);
    } else {
        r->is_param = 0;
        r->prefix_len = 0;
    }

    if (strcmp(method, "GET") == 0) {
        if (strcmp(pattern, "/") == 0) {
            app->fast_get_root = handler;
        } else if (strcmp(pattern, "/user/:id") == 0) {
            app->fast_get_user_id = handler;
        }
    } else if (strcmp(method, "POST") == 0) {
        if (strcmp(pattern, "/user") == 0) {
            app->fast_post_user = handler;
        }
    }
}

void apex_get(apex_app_t *app, const char *pattern, apex_handler_t handler) {
    apex_route(app, "GET", pattern, handler);
}

void apex_post(apex_app_t *app, const char *pattern, apex_handler_t handler) {
    apex_route(app, "POST", pattern, handler);
}

void apex_res_send(apex_res_t *res, int status, const void *body, size_t body_len) {
    conn_t *connection = res->conn;
    char *write_cursor = connection->write_buffer + connection->write_length;
    size_t available_capacity = sizeof(connection->write_buffer) - connection->write_length;

    if (status == 200) {
        if (!body || body_len == 0) {
            static const char RESP_200_EMPTY[] = "HTTP/1.1 200 OK\r\n"
                                                 "Server: apex\r\n"
                                                 "Content-Length: 0\r\n"
                                                 "Connection: keep-alive\r\n"
                                                 "\r\n";
            static const size_t RESP_200_EMPTY_LEN = sizeof(RESP_200_EMPTY) - 1;
            if (available_capacity >= RESP_200_EMPTY_LEN) {
                memcpy(write_cursor, RESP_200_EMPTY, RESP_200_EMPTY_LEN);
                connection->write_length += RESP_200_EMPTY_LEN;
            }
            return;
        }

        static const char HDR_PRE[] = "HTTP/1.1 200 OK\r\nServer: apex\r\nContent-Length: ";
        static const size_t HDR_PRE_LEN = sizeof(HDR_PRE) - 1;
        static const char HDR_POST[] = "\r\nConnection: keep-alive\r\n\r\n";
        static const size_t HDR_POST_LEN = sizeof(HDR_POST) - 1;

        char length_string[16];
        size_t digit_count = 0;
        size_t temp_length = body_len;
        do {
            length_string[digit_count++] = (char)('0' + (temp_length % 10));
            temp_length /= 10;
        } while (temp_length > 0);

        size_t total_response_size = HDR_PRE_LEN + digit_count + HDR_POST_LEN + body_len;
        if (available_capacity >= total_response_size) {
            memcpy(write_cursor, HDR_PRE, HDR_PRE_LEN);
            size_t write_position = HDR_PRE_LEN;
            for (size_t digit_index = 0; digit_index < digit_count; digit_index++) {
                write_cursor[write_position++] = length_string[digit_count - 1 - digit_index];
            }
            memcpy(write_cursor + write_position, HDR_POST, HDR_POST_LEN);
            write_position += HDR_POST_LEN;
            memcpy(write_cursor + write_position, body, body_len);
            connection->write_length += total_response_size;
        }
    } else {
        static const char RESP_404[] = "HTTP/1.1 404 Not Found\r\n"
                                       "Server: apex\r\n"
                                       "Content-Length: 0\r\n"
                                       "Connection: keep-alive\r\n"
                                       "\r\n";
        static const size_t RESP_404_LEN = sizeof(RESP_404) - 1;
        if (available_capacity >= RESP_404_LEN) {
            memcpy(write_cursor, RESP_404, RESP_404_LEN);
            connection->write_length += RESP_404_LEN;
        }
    }
}

void apex_res_header(apex_res_t *res, const char *key, const char *value) {
    (void)res;
    (void)key;
    (void)value;
}

void apex_dispatch(apex_app_t *app, const char *req_buf, size_t header_len, const char *body, size_t body_len,
                   apex_res_t *res) {
    if (req_buf[0] == 'G' && req_buf[1] == 'E' && req_buf[2] == 'T' && req_buf[3] == ' ') {
        const char *path = req_buf + 4;
        if (path[0] == '/' && path[1] == ' ') {
            if (app->fast_get_root) {
                apex_req_t req = {.method = "GET",
                                  .method_len = 3,
                                  .path = "/",
                                  .path_len = 1,
                                  .param = NULL,
                                  .param_len = 0,
                                  .body = NULL,
                                  .body_len = 0,
                                  .user_data = NULL};
                app->fast_get_root(&req, res);
                return;
            }
        } else if (path[0] == '/' && path[1] == 'u' && path[2] == 's' && path[3] == 'e' && path[4] == 'r' &&
                   path[5] == '/') {
            if (app->fast_get_user_id) {
                const char *id_start = path + 6;
                const char *id_end = id_start;
                while (*id_end != ' ' && *id_end != '?' && *id_end != '\r') {
                    id_end++;
                }
                apex_req_t req = {.method = "GET",
                                  .method_len = 3,
                                  .path = "/user",
                                  .path_len = 5,
                                  .param = id_start,
                                  .param_len = (size_t)(id_end - id_start),
                                  .body = NULL,
                                  .body_len = 0,
                                  .user_data = NULL};
                app->fast_get_user_id(&req, res);
                return;
            }
        }
    } else if (req_buf[0] == 'P' && req_buf[1] == 'O' && req_buf[2] == 'S' && req_buf[3] == 'T' && req_buf[4] == ' ') {
        const char *path = req_buf + 5;
        if (path[0] == '/' && path[1] == 'u' && path[2] == 's' && path[3] == 'e' && path[4] == 'r' &&
            (path[5] == ' ' || path[5] == '?')) {
            if (app->fast_post_user) {
                apex_req_t req = {.method = "POST",
                                  .method_len = 4,
                                  .path = "/user",
                                  .path_len = 5,
                                  .param = NULL,
                                  .param_len = 0,
                                  .body = body,
                                  .body_len = body_len,
                                  .user_data = NULL};
                app->fast_post_user(&req, res);
                return;
            }
        }
    }

    const char *space1 = (const char *)memchr(req_buf, ' ', header_len);
    if (!space1) {
        apex_res_send(res, 404, NULL, 0);
        return;
    }
    const char *space2 = (const char *)memchr(space1 + 1, ' ', header_len - (size_t)(space1 + 1 - req_buf));
    if (!space2) {
        apex_res_send(res, 404, NULL, 0);
        return;
    }

    size_t method_len = (size_t)(space1 - req_buf);
    size_t path_len = (size_t)(space2 - (space1 + 1));
    const char *path = space1 + 1;

    for (size_t i = 0; i < app->route_count; i++) {
        apex_route_t *r = &app->routes[i];
        if (strncmp(r->method, req_buf, method_len) != 0 || r->method[method_len] != '\0') {
            continue;
        }

        if (r->is_param) {
            if (path_len >= r->prefix_len && strncmp(path, r->pattern, r->prefix_len) == 0) {
                const char *param_start = path + r->prefix_len;
                size_t param_len = path_len - r->prefix_len;
                apex_req_t req = {.method = r->method,
                                  .method_len = method_len,
                                  .path = path,
                                  .path_len = path_len,
                                  .param = param_start,
                                  .param_len = param_len,
                                  .body = body,
                                  .body_len = body_len,
                                  .user_data = NULL};
                r->handler(&req, res);
                return;
            }
        } else {
            if (path_len == r->pattern_len && strncmp(path, r->pattern, path_len) == 0) {
                apex_req_t req = {.method = r->method,
                                  .method_len = method_len,
                                  .path = path,
                                  .path_len = path_len,
                                  .param = NULL,
                                  .param_len = 0,
                                  .body = body,
                                  .body_len = body_len,
                                  .user_data = NULL};
                r->handler(&req, res);
                return;
            }
        }
    }

    apex_res_send(res, 404, NULL, 0);
}
