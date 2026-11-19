#include "internal.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <poll.h>
#include <strings.h>
#include <sys/stat.h>

static const char *router_determine_content_type(const char *path);


typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} router_buffer_t;

static bool router_buffer_append(router_buffer_t *buffer, const void *data, size_t length) {
    if (length == 0) {
        return true;
    }
    if (length > SIZE_MAX - buffer->length - 1u) {
        return false;
    }
    size_t needed = buffer->length + length + 1u;
    if (needed > buffer->capacity) {
        size_t capacity = buffer->capacity ? buffer->capacity * 2u : 256u;
        while (capacity < needed) {
            if (capacity > SIZE_MAX / 2u) {
                capacity = needed;
                break;
            }
            capacity *= 2u;
        }
        char *grown = realloc(buffer->data, capacity);
        if (grown == NULL) {
            return false;
        }
        buffer->data = grown;
        buffer->capacity = capacity;
    }
    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    buffer->data[buffer->length] = '\0';
    return true;
}

static bool router_buffer_append_string(router_buffer_t *buffer, const char *text) {
    return router_buffer_append(buffer, text, strlen(text));
}

static void router_buffer_free(router_buffer_t *buffer) {
    free(buffer->data);
    buffer->data = NULL;
    buffer->length = 0;
    buffer->capacity = 0;
}

static const char *router_find_crlf(const char *data, size_t length) {
    if (length < 2u) {
        return NULL;
    }
    for (size_t index = 0; index + 1u < length; index++) {
        if (data[index] == '\r' && data[index + 1u] == '\n') {
            return data + index;
        }
    }
    return NULL;
}

static bool router_header_name_equal(const char *name, size_t name_length, const char *expected) {
    size_t expected_length = strlen(expected);
    return name_length == expected_length && strncasecmp(name, expected, expected_length) == 0;
}

static bool router_find_header(const char *buffer, size_t length, const char *name, const char **value,
                               size_t *value_length) {
    const char *first_end = router_find_crlf(buffer, length);
    if (first_end == NULL) {
        return false;
    }

    size_t position = (size_t)(first_end - buffer) + 2u;
    while (position < length) {
        const char *line = buffer + position;
        const char *line_end = router_find_crlf(line, length - position);
        if (line_end == NULL) {
            return false;
        }
        size_t line_length = (size_t)(line_end - line);
        if (line_length == 0) {
            return false;
        }

        const char *colon = memchr(line, ':', line_length);
        if (colon != NULL) {
            size_t field_length = (size_t)(colon - line);
            while (field_length > 0 && (line[field_length - 1u] == ' ' || line[field_length - 1u] == '\t')) {
                field_length--;
            }
            if (router_header_name_equal(line, field_length, name)) {
                const char *start = colon + 1;
                const char *end = line + line_length;
                while (start < end && (start[0] == ' ' || start[0] == '\t')) {
                    start++;
                }
                while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
                    end--;
                }
                *value = start;
                *value_length = (size_t)(end - start);
                return true;
            }
        }

        position += line_length + 2u;
    }
    return false;
}

static bool router_header_is_overridden(const char *line, size_t line_length,
                                        const apex_location_config_t *location) {
    const char *colon = memchr(line, ':', line_length);
    if (colon == NULL) {
        return false;
    }
    size_t name_length = (size_t)(colon - line);
    while (name_length > 0 && (line[name_length - 1u] == ' ' || line[name_length - 1u] == '\t')) {
        name_length--;
    }
    for (size_t index = 0; index < location->header_count; index++) {
        if (router_header_name_equal(line, name_length, location->headers[index].name)) {
            return true;
        }
    }
    return false;
}

static bool conn_get_peer_ip(const conn_t *connection, char *ip_buf, size_t ip_buf_len) {
    if (connection == NULL || connection->fd < 0 || ip_buf == NULL || ip_buf_len == 0) {
        return false;
    }
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    if (getpeername(connection->fd, (struct sockaddr *)&ss, &slen) != 0) {
        return false;
    }
    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        return inet_ntop(AF_INET, &sin->sin_addr, ip_buf, (socklen_t)ip_buf_len) != NULL;
    } else if (ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            return inet_ntop(AF_INET, &sin6->sin6_addr.s6_addr[12], ip_buf, (socklen_t)ip_buf_len) != NULL;
        }
        return inet_ntop(AF_INET6, &sin6->sin6_addr, ip_buf, (socklen_t)ip_buf_len) != NULL;
    }
    return false;
}

static bool acl_rule_matches(const apex_acl_rule_t *rule, const struct sockaddr_storage *ss) {
    if (rule->is_all) {
        return true;
    }
    if (ss->ss_family == AF_INET && !rule->is_ipv6) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)ss;
        return (sin->sin_addr.s_addr & rule->mask4.s_addr) == rule->addr4.s_addr;
    }
    if (ss->ss_family == AF_INET6 && rule->is_ipv6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ss;
        for (int i = 0; i < 16; i++) {
            if ((sin6->sin6_addr.s6_addr[i] & rule->mask6.s6_addr[i]) != rule->addr6.s6_addr[i]) {
                return false;
            }
        }
        return true;
    }
    if (ss->ss_family == AF_INET6 && !rule->is_ipv6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ss;
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            uint32_t ip4 = *(const uint32_t *)&sin6->sin6_addr.s6_addr[12];
            return (ip4 & rule->mask4.s_addr) == rule->addr4.s_addr;
        }
    }
    return false;
}

static bool router_check_acl(const apex_acl_rule_t *rules, size_t rule_count, int fd) {
    if (rules == NULL || rule_count == 0) {
        return true;
    }
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    if (getpeername(fd, (struct sockaddr *)&ss, &slen) != 0) {
        return true;
    }
    for (size_t i = 0; i < rule_count; i++) {
        if (acl_rule_matches(&rules[i], &ss)) {
            return rules[i].allow;
        }
    }
    return true;
}

static void router_expand_string(const char *src, char *dst, size_t dst_len,
                                 const char *host, size_t host_len,
                                 const char *uri, size_t uri_len,
                                 const char *remote_addr, size_t remote_addr_len,
                                 const char *scheme, size_t scheme_len,
                                 const char *existing_xff, size_t existing_xff_len,
                                 const char *upgrade, size_t upgrade_len,
                                 const char *connection, size_t connection_len) {
    if (dst == NULL || dst_len == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    size_t out_idx = 0;
    size_t src_len = strlen(src);
    for (size_t i = 0; i < src_len && out_idx + 1 < dst_len;) {
        if (src[i] == '$') {
            const char *var = src + i + 1;
            bool braced = false;
            if (*var == '{') {
                braced = true;
                var++;
            }
            size_t var_len = 0;
            while (var[var_len] != '\0' && (isalnum((unsigned char)var[var_len]) || var[var_len] == '_')) {
                var_len++;
            }
            size_t skip = 1 + (braced ? 1 : 0) + var_len + (braced && var[var_len] == '}' ? 1 : 0);

            const char *subst = NULL;
            size_t subst_len = 0;
            char xff_buf[512];

            if (var_len == 4 && strncmp(var, "host", 4) == 0) {
                subst = host;
                subst_len = host_len;
            } else if (var_len == 9 && strncmp(var, "http_host", 9) == 0) {
                subst = host;
                subst_len = host_len;
            } else if (var_len == 11 && strncmp(var, "request_uri", 11) == 0) {
                subst = uri;
                subst_len = uri_len;
            } else if (var_len == 11 && strncmp(var, "remote_addr", 11) == 0) {
                subst = remote_addr;
                subst_len = remote_addr_len;
            } else if (var_len == 6 && strncmp(var, "scheme", 6) == 0) {
                subst = scheme;
                subst_len = scheme_len;
            } else if (var_len == 12 && strncmp(var, "http_upgrade", 12) == 0) {
                subst = upgrade;
                subst_len = upgrade_len;
            } else if (var_len == 15 && strncmp(var, "http_connection", 15) == 0) {
                subst = connection;
                subst_len = connection_len;
            } else if (var_len == 26 && strncmp(var, "proxy_add_x_forwarded_for", 26) == 0) {
                if (existing_xff != NULL && existing_xff_len > 0) {
                    int w = snprintf(xff_buf, sizeof(xff_buf), "%.*s, %.*s",
                                     (int)existing_xff_len, existing_xff,
                                     (int)remote_addr_len, remote_addr);
                    if (w > 0 && (size_t)w < sizeof(xff_buf)) {
                        subst = xff_buf;
                        subst_len = (size_t)w;
                    }
                } else {
                    subst = remote_addr;
                    subst_len = remote_addr_len;
                }
            }

            if (subst != NULL) {
                size_t copy_len = subst_len;
                if (out_idx + copy_len >= dst_len) {
                    copy_len = dst_len - 1 - out_idx;
                }
                memcpy(dst + out_idx, subst, copy_len);
                out_idx += copy_len;
                i += skip;
                continue;
            }
        }
        dst[out_idx++] = src[i++];
    }
    dst[out_idx] = '\0';
}

static void router_send_redirect(conn_t *connection, int status_code, const char *location_url,
                                 const char *extra_headers, size_t extra_headers_len) {
    if (connection == NULL || connection->fd < 0) {
        return;
    }
    const char *reason = "Moved Permanently";
    switch (status_code) {
    case 301: reason = "Moved Permanently"; break;
    case 302: reason = "Found"; break;
    case 303: reason = "See Other"; break;
    case 307: reason = "Temporary Redirect"; break;
    case 308: reason = "Permanent Redirect"; break;
    case 200: reason = "OK"; break;
    default:
        if (status_code >= 300 && status_code < 400) {
            reason = "Redirect";
        } else if (status_code >= 400 && status_code < 500) {
            reason = "Client Error";
        } else {
            reason = "Server Response";
        }
        break;
    }

    char header[1024];
    int written = 0;
    if (status_code >= 300 && status_code < 400) {
        written = snprintf(header, sizeof(header),
                           "HTTP/1.1 %d %s\r\n"
                           "Location: %s\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: %s\r\n",
                           status_code, reason, location_url ? location_url : "/",
                           connection->close_after_write ? "close" : "keep-alive");
    } else {
        size_t body_len = location_url ? strlen(location_url) : 0;
        written = snprintf(header, sizeof(header),
                           "HTTP/1.1 %d %s\r\n"
                           "Content-Type: text/plain\r\n"
                           "Content-Length: %zu\r\n"
                           "Connection: %s\r\n",
                           status_code, reason, body_len,
                           connection->close_after_write ? "close" : "keep-alive");
    }

    if (written > 0 && (size_t)written < sizeof(header)) {
        apex_conn_write(connection, header, (size_t)written);
        if (extra_headers != NULL && extra_headers_len > 0) {
            apex_conn_write(connection, extra_headers, extra_headers_len);
        }
        apex_conn_write(connection, "\r\n", 2u);
        if (status_code < 300 || status_code >= 400) {
            if (location_url != NULL && location_url[0] != '\0') {
                apex_conn_write(connection, location_url, strlen(location_url));
            }
        }
    }
}

static bool router_location_has_header(const apex_location_config_t *location, const char *name) {
    if (location == NULL) {
        return false;
    }
    for (size_t i = 0; i < location->header_count; i++) {
        if (strcasecmp(location->headers[i].name, name) == 0) {
            return true;
        }
    }
    return false;
}

static bool build_request_headers(const char *request, size_t request_length,
                                  const apex_location_config_t *location,
                                  conn_t *connection, const char *host,
                                  const char *target, size_t target_len,
                                  char **headers, size_t *headers_length) {
    *headers = NULL;
    *headers_length = 0;

    char client_ip[INET6_ADDRSTRLEN];
    if (!conn_get_peer_ip(connection, client_ip, sizeof(client_ip))) {
        strcpy(client_ip, "127.0.0.1");
    }
    size_t client_ip_len = strlen(client_ip);

    const char *scheme = (connection != NULL && connection->transport == APEX_TRANSPORT_TLS) ? "https" : "http";
    size_t scheme_len = strlen(scheme);

    const char *host_val = host != NULL ? host : "";
    size_t host_val_len = strlen(host_val);

    const char *uri_val = target != NULL ? target : "/";
    size_t uri_val_len = target_len ? target_len : strlen(uri_val);

    const char *existing_xff = NULL;
    size_t existing_xff_len = 0;
    router_find_header(request, request_length, "X-Forwarded-For", &existing_xff, &existing_xff_len);

    const char *upgrade_val = NULL;
    size_t upgrade_val_len = 0;
    bool has_upgrade = router_find_header(request, request_length, "Upgrade", &upgrade_val, &upgrade_val_len);

    const char *conn_val = NULL;
    size_t conn_val_len = 0;
    router_find_header(request, request_length, "Connection", &conn_val, &conn_val_len);

    bool is_ws = has_upgrade && (upgrade_val_len == 9 && strncasecmp(upgrade_val, "websocket", 9) == 0);

    router_buffer_t buffer = {0};
    const char *first_end = router_find_crlf(request, request_length);
    if (first_end != NULL) {
        size_t position = (size_t)(first_end - request) + 2u;
        while (position < request_length) {
            const char *line = request + position;
            const char *line_end = router_find_crlf(line, request_length - position);
            if (line_end == NULL) {
                break;
            }
            size_t line_length = (size_t)(line_end - line);
            if (line_length == 0) {
                break;
            }

            const char *colon = memchr(line, ':', line_length);
            bool skip_header = false;
            if (colon != NULL) {
                size_t name_len = (size_t)(colon - line);
                while (name_len > 0 && (line[name_len - 1u] == ' ' || line[name_len - 1u] == '\t')) {
                    name_len--;
                }
                /* Skip client-provided X-Forwarded-* and X-Real-IP so we inject authoritative ones */
                if (router_header_name_equal(line, name_len, "X-Real-IP") ||
                    router_header_name_equal(line, name_len, "X-Forwarded-For") ||
                    router_header_name_equal(line, name_len, "X-Forwarded-Proto") ||
                    router_header_name_equal(line, name_len, "X-Forwarded-Host")) {
                    skip_header = true;
                }
            }

            if (!skip_header && !router_header_is_overridden(line, line_length, location)) {
                if (!router_buffer_append(&buffer, line, line_length) ||
                    !router_buffer_append_string(&buffer, "\r\n")) {
                    router_buffer_free(&buffer);
                    return false;
                }
            }
            position += line_length + 2u;
        }
    }

    /* Standard Proxy Headers (if not overridden in location) */
    if (!router_location_has_header(location, "X-Real-IP")) {
        if (!router_buffer_append_string(&buffer, "X-Real-IP: ") ||
            !router_buffer_append_string(&buffer, client_ip) ||
            !router_buffer_append_string(&buffer, "\r\n")) {
            router_buffer_free(&buffer);
            return false;
        }
    }

    if (!router_location_has_header(location, "X-Forwarded-For")) {
        if (!router_buffer_append_string(&buffer, "X-Forwarded-For: ")) {
            router_buffer_free(&buffer);
            return false;
        }
        if (existing_xff != NULL && existing_xff_len > 0) {
            if (!router_buffer_append(&buffer, existing_xff, existing_xff_len) ||
                !router_buffer_append_string(&buffer, ", ")) {
                router_buffer_free(&buffer);
                return false;
            }
        }
        if (!router_buffer_append_string(&buffer, client_ip) ||
            !router_buffer_append_string(&buffer, "\r\n")) {
            router_buffer_free(&buffer);
            return false;
        }
    }

    if (!router_location_has_header(location, "X-Forwarded-Proto")) {
        if (!router_buffer_append_string(&buffer, "X-Forwarded-Proto: ") ||
            !router_buffer_append_string(&buffer, scheme) ||
            !router_buffer_append_string(&buffer, "\r\n")) {
            router_buffer_free(&buffer);
            return false;
        }
    }

    if (host_val[0] != '\0' && !router_location_has_header(location, "X-Forwarded-Host")) {
        if (!router_buffer_append_string(&buffer, "X-Forwarded-Host: ") ||
            !router_buffer_append_string(&buffer, host_val) ||
            !router_buffer_append_string(&buffer, "\r\n")) {
            router_buffer_free(&buffer);
            return false;
        }
    }

    /* Custom location headers with variable expansion */
    if (location != NULL) {
        for (size_t index = 0; index < location->header_count; index++) {
            const apex_config_header_t *header = &location->headers[index];
            char expanded_val[1024];
            router_expand_string(header->value, expanded_val, sizeof(expanded_val),
                                 host_val, host_val_len,
                                 uri_val, uri_val_len,
                                 client_ip, client_ip_len,
                                 scheme, scheme_len,
                                 existing_xff, existing_xff_len,
                                 upgrade_val, upgrade_val_len,
                                 conn_val, conn_val_len);
            if (!router_buffer_append_string(&buffer, header->name) ||
                !router_buffer_append_string(&buffer, ": ") ||
                !router_buffer_append_string(&buffer, expanded_val) ||
                !router_buffer_append_string(&buffer, "\r\n")) {
                router_buffer_free(&buffer);
                return false;
            }
        }
    }

    /* For WebSocket, ensure Upgrade and Connection headers reach upstream if not already present */
    if (is_ws) {
        if (!router_location_has_header(location, "Upgrade")) {
            if (!router_buffer_append_string(&buffer, "Upgrade: websocket\r\n")) {
                router_buffer_free(&buffer);
                return false;
            }
        }
        if (!router_location_has_header(location, "Connection")) {
            if (!router_buffer_append_string(&buffer, "Connection: Upgrade\r\n")) {
                router_buffer_free(&buffer);
                return false;
            }
        }
    }

    if (buffer.length > 0) {
        *headers = buffer.data;
        *headers_length = buffer.length;
    } else {
        router_buffer_free(&buffer);
    }
    return true;
}

static const char APEX_ERROR_HTML_TEMPLATE[] =
    "<!DOCTYPE html>\n"
    "<html lang=\"en\">\n"
    "<head>\n"
    "  <meta charset=\"utf-8\">\n"
    "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
    "  <title>apex — %d</title>\n"
    "  <style>\n"
    "    * { box-sizing: border-box; margin: 0; padding: 0; }\n"
    "    body {\n"
    "      background: #000000;\n"
    "      color: #ededed;\n"
    "      font-family: -apple-system, BlinkMacSystemFont, \"SF Pro Text\", \"Inter\", \"Segoe UI\", sans-serif;\n"
    "      -webkit-font-smoothing: antialiased;\n"
    "      min-height: 100vh;\n"
    "      display: flex;\n"
    "      flex-direction: column;\n"
    "      align-items: center;\n"
    "      justify-content: center;\n"
    "      text-align: center;\n"
    "      text-transform: lowercase;\n"
    "      user-select: none;\n"
    "      padding: 24px;\n"
    "    }\n"
    "    .container { max-width: 440px; }\n"
    "    .brand-mark {\n"
    "      font-family: ui-monospace, \"SF Mono\", Menlo, monospace;\n"
    "      font-size: 14px;\n"
    "      color: #555555;\n"
    "      letter-spacing: 0.08em;\n"
    "      margin-bottom: 24px;\n"
    "      display: flex;\n"
    "      align-items: center;\n"
    "      justify-content: center;\n"
    "      gap: 9px;\n"
    "    }\n"
    "    .brand-mark svg { width: 17px; height: 17px; fill: currentColor; }\n"
    "    .code {\n"
    "      font-size: 80px;\n"
    "      font-weight: 200;\n"
    "      letter-spacing: -0.06em;\n"
    "      line-height: 1;\n"
    "      color: #ffffff;\n"
    "      margin-bottom: 16px;\n"
    "    }\n"
    "    .title {\n"
    "      font-size: 19px;\n"
    "      font-weight: 400;\n"
    "      color: #cccccc;\n"
    "      letter-spacing: -0.02em;\n"
    "      margin-bottom: 10px;\n"
    "    }\n"
    "    .desc {\n"
    "      font-size: 14px;\n"
    "      font-weight: 400;\n"
    "      color: #555555;\n"
    "      line-height: 1.5;\n"
    "      letter-spacing: -0.01em;\n"
    "    }\n"
    "  </style>\n"
    "</head>\n"
    "<body>\n"
    "  <div class=\"container\">\n"
    "    <div class=\"brand-mark\">\n"
    "      <svg viewBox=\"0 0 32 32\"><path d=\"M4 8C14 8 26 14 28 26C20 22 14 18 10 14L4 8Z\" fill=\"currentColor\"/><path d=\"M12 20C17 21 21 23 24 26\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"round\" fill=\"none\"/></svg>\n"
    "      apex\n"
    "    </div>\n"
    "    <div class=\"code\">%d</div>\n"
    "    <div class=\"title\">%s</div>\n"
    "    <div class=\"desc\">%s</div>\n"
    "  </div>\n"
    "</body>\n"
    "</html>\n";

static void router_error_details(int status, const char *default_reason,
                                 const char **title_out, const char **desc_out) {
    switch (status) {
    case 400:
        *title_out = "bad request";
        *desc_out = "the request could not be understood by the server.";
        break;
    case 403:
        *title_out = "forbidden";
        *desc_out = "you don't have permission to access this resource.";
        break;
    case 404:
        *title_out = "not found";
        *desc_out = "this page could not be found.";
        break;
    case 405:
        *title_out = "method not allowed";
        *desc_out = "the request method is not supported for this route.";
        break;
    case 414:
        *title_out = "uri too long";
        *desc_out = "the request uri exceeds the maximum supported length.";
        break;
    case 500:
        *title_out = "internal error";
        *desc_out = "something went wrong on our end.";
        break;
    case 502:
        *title_out = "bad gateway";
        *desc_out = "temporarily unreachable. try again in a moment.";
        break;
    case 503:
        *title_out = "service unavailable";
        *desc_out = "the server is temporarily overloaded or down for maintenance.";
        break;
    case 504:
        *title_out = "gateway timeout";
        *desc_out = "the server took too long to respond.";
        break;
    default:
        *title_out = default_reason;
        *desc_out = "an unexpected error occurred.";
        break;
    }
}

void router_send_error_ex(conn_t *connection, const apex_server_config_t *server,
                          const char *request, size_t request_length,
                          int status, const char *reason, const char *message,
                          const char *extra_headers, size_t extra_headers_len) {
    if (connection == NULL || connection->fd < 0) {
        return;
    }

    const char *extra = (extra_headers != NULL && extra_headers_len > 0) ? extra_headers : "";
    int extra_len = (extra_headers != NULL && extra_headers_len > 0) ? (int)extra_headers_len : 0;

    /* 1. Custom error_page if configured */
    if (server != NULL && server->error_pages != NULL) {
        for (size_t i = 0; i < server->error_page_count; i++) {
            if (server->error_pages[i].status_code == status) {
                const char *path = server->error_pages[i].path;
                int file_fd = open(path, O_RDONLY | O_CLOEXEC);
                if (file_fd >= 0) {
                    struct stat st;
                    if (fstat(file_fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
                        st.st_size <= 2u * 1024u * 1024u) {
                        size_t file_size = (size_t)st.st_size;
                        char *file_buf = malloc(file_size);
                        if (file_buf != NULL) {
                            ssize_t n = read(file_fd, file_buf, file_size);
                            close(file_fd);
                            if (n == (ssize_t)file_size) {
                                const char *content_type = router_determine_content_type(path);
                                char header[1024];
                                int written = snprintf(header, sizeof(header),
                                                       "HTTP/1.1 %d %s\r\n"
                                                       "Server: apex\r\n"
                                                       "Content-Type: %s\r\n"
                                                       "Content-Length: %zu\r\n"
                                                       "Connection: %s\r\n"
                                                       "%.*s"
                                                       "\r\n",
                                                       status, reason, content_type, file_size,
                                                       connection->close_after_write ? "close" : "keep-alive",
                                                       extra_len, extra);
                                if (written > 0 && (size_t)written < sizeof(header)) {
                                    apex_conn_write(connection, header, (size_t)written);
                                    apex_conn_write(connection, file_buf, file_size);
                                    free(file_buf);
                                    return;
                                }
                            }
                            free(file_buf);
                        } else {
                            close(file_fd);
                        }
                    } else {
                        close(file_fd);
                    }
                }
                break;
            }
        }
    }

    const char *title = NULL;
    const char *desc = NULL;
    router_error_details(status, reason, &title, &desc);

    /* 2. Check for Accept: application/json */
    const char *accept_val = NULL;
    size_t accept_len = 0;
    bool client_wants_json = false;
    if (request != NULL && request_length > 0) {
        if (router_find_header(request, request_length, "Accept", &accept_val, &accept_len)) {
            if (accept_val != NULL && memmem(accept_val, accept_len, "application/json", 16) != NULL) {
                client_wants_json = true;
            }
        }
    }

    if (client_wants_json) {
        char json_body[256];
        int body_len = snprintf(json_body, sizeof(json_body),
                                "{\"error\":%d,\"status\":\"%s\",\"message\":\"%s\"}\n",
                                status, title, desc);
        if (body_len > 0) {
            char header[1024];
            int written = snprintf(header, sizeof(header),
                                   "HTTP/1.1 %d %s\r\n"
                                   "Server: apex\r\n"
                                   "Content-Type: application/json\r\n"
                                   "Content-Length: %d\r\n"
                                   "Connection: %s\r\n"
                                   "%.*s"
                                   "\r\n",
                                   status, reason, body_len,
                                   connection->close_after_write ? "close" : "keep-alive",
                                   extra_len, extra);
            if (written > 0 && (size_t)written < sizeof(header)) {
                apex_conn_write(connection, header, (size_t)written);
                apex_conn_write(connection, json_body, (size_t)body_len);
                return;
            }
        }
    }

    /* 3. Built-in Razor Wing HTML template */
    char html_body[2048];
    int body_written = snprintf(html_body, sizeof(html_body), APEX_ERROR_HTML_TEMPLATE,
                                status, status, title, desc);
    if (body_written <= 0 || (size_t)body_written >= sizeof(html_body)) {
        size_t message_length = strlen(message);
        char header[1024];
        int written = snprintf(header, sizeof(header),
                               "HTTP/1.1 %d %s\r\n"
                               "Server: apex\r\n"
                               "Content-Type: text/plain\r\n"
                               "Content-Length: %zu\r\n"
                               "Connection: %s\r\n"
                               "%.*s"
                               "\r\n",
                               status, reason, message_length,
                               connection->close_after_write ? "close" : "keep-alive",
                               extra_len, extra);
        if (written > 0 && (size_t)written < sizeof(header)) {
            apex_conn_write(connection, header, (size_t)written);
            apex_conn_write(connection, message, message_length);
        }
        return;
    }

    char header[1024];
    int written = snprintf(header, sizeof(header),
                           "HTTP/1.1 %d %s\r\n"
                           "Server: apex\r\n"
                           "Content-Type: text/html; charset=utf-8\r\n"
                           "Content-Length: %d\r\n"
                           "Connection: %s\r\n"
                           "%.*s"
                           "\r\n",
                           status, reason, body_written,
                           connection->close_after_write ? "close" : "keep-alive",
                           extra_len, extra);
    if (written < 0 || (size_t)written >= sizeof(header)) {
        connection->close_after_write = 1;
        return;
    }
    apex_conn_write(connection, header, (size_t)written);
    apex_conn_write(connection, html_body, (size_t)body_written);
}

void router_send_error(conn_t *connection, const apex_server_config_t *server,
                       const char *request, size_t request_length,
                       int status, const char *reason, const char *message) {
    router_send_error_ex(connection, server, request, request_length, status, reason, message, NULL, 0);
}

static void router_write_proxy_response(conn_t *connection, const apex_server_config_t *server,
                                        const char *request, size_t request_length,
                                        const apex_proxy_response_t *response,
                                        bool head_request,
                                        const char *extra_headers, size_t extra_headers_len) {
    const char *headers = response->headers;
    size_t headers_length = response->headers_len;
    int status = response->status;

    const char *status_end = router_find_crlf(headers, headers_length);
    if (status_end == NULL) {
        router_send_error(connection, server, request, request_length, 502, "Bad Gateway", "upstream returned an invalid response\n");
        return;
    }

    apex_conn_write(connection, headers, (size_t)(status_end - headers));
    apex_conn_write(connection, "\r\n", 2u);

    bool no_body = status == 204 || status == 304 || (status >= 100 && status < 200);
    bool no_content_length = true;

    size_t position = (size_t)(status_end - headers) + 2u;
    while (position < headers_length) {
        const char *line = headers + position;
        const char *line_end = router_find_crlf(line, headers_length - position);
        if (line_end == NULL) {
            break;
        }
        size_t line_length = (size_t)(line_end - line);
        if (line_length == 0) {
            break;
        }

        const char *colon = memchr(line, ':', line_length);
        bool skip = false;
        if (colon != NULL) {
            size_t name_length = (size_t)(colon - line);
            while (name_length > 0 && (line[name_length - 1u] == ' ' || line[name_length - 1u] == '\t')) {
                name_length--;
            }
            if (status != 101 && (router_header_name_equal(line, name_length, "Transfer-Encoding") ||
                                  router_header_name_equal(line, name_length, "Connection") ||
                                  router_header_name_equal(line, name_length, "Keep-Alive") ||
                                  router_header_name_equal(line, name_length, "Proxy-Connection"))) {
                skip = true;
            } else if (status == 101 && (router_header_name_equal(line, name_length, "Transfer-Encoding") ||
                                         router_header_name_equal(line, name_length, "Keep-Alive") ||
                                         router_header_name_equal(line, name_length, "Proxy-Connection"))) {
                skip = true;
            } else if (router_header_name_equal(line, name_length, "Content-Length")) {
                no_content_length = false;
                if (!head_request || no_body) {
                    skip = true;
                }
            }
        }

        if (!skip) {
            apex_conn_write(connection, line, line_length);
            apex_conn_write(connection, "\r\n", 2u);
        }
        position += line_length + 2u;
    }

    char length_header[64];
    if (!head_request && !no_body) {
        int written = snprintf(length_header, sizeof(length_header), "Content-Length: %zu\r\n",
                               response->body_len);
        if (written > 0 && (size_t)written < sizeof(length_header)) {
            apex_conn_write(connection, length_header, (size_t)written);
        }
    } else if (head_request && no_content_length && !no_body) {
        apex_conn_write(connection, "Content-Length: 0\r\n", 19u);
    }

    if (status != 101) {
        const char *connection_header = connection->close_after_write ? "Connection: close\r\n"
                                                                      : "Connection: keep-alive\r\n";
        apex_conn_write(connection, connection_header, strlen(connection_header));
    }
    if (extra_headers != NULL && extra_headers_len > 0) {
        apex_conn_write(connection, extra_headers, extra_headers_len);
    }
    apex_conn_write(connection, "\r\n", 2u);

    if (!head_request && !no_body && response->body != NULL && response->body_len > 0) {
        apex_conn_write(connection, response->body, response->body_len);
    }
}

void apex_proxy_ws_tunnel(conn_t *client_conn, int upstream_fd, uint64_t timeout_ms) {
    if (client_conn == NULL || client_conn->fd < 0 || upstream_fd < 0) {
        if (upstream_fd >= 0) {
            close(upstream_fd);
        }
        return;
    }

    if (timeout_ms == 0) {
        timeout_ms = 60000u;
    }

    int client_fd = client_conn->fd;
    char buffer[16384];
    struct pollfd fds[2];

    int flags = fcntl(upstream_fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(upstream_fd, F_SETFL, flags | O_NONBLOCK);
    }

    int poll_timeout = (timeout_ms > INT_MAX) ? INT_MAX : (int)timeout_ms;

    for (;;) {
        fds[0].fd = client_fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        fds[1].fd = upstream_fd;
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        bool client_has_pending = false;
        if (client_conn->transport == APEX_TRANSPORT_TLS && client_conn->ssl != NULL) {
            if (SSL_pending(client_conn->ssl) > 0) {
                client_has_pending = true;
            }
        }

        int timeout = client_has_pending ? 0 : poll_timeout;
        int ret = poll(fds, 2, timeout);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (ret == 0 && !client_has_pending) {
            break;
        }

        /* 1. Client -> Upstream */
        if (client_has_pending || (fds[0].revents & (POLLIN | POLLERR | POLLHUP | POLLRDHUP))) {
            ssize_t nread = 0;
            if (client_conn->transport == APEX_TRANSPORT_TLS && client_conn->ssl != NULL) {
                int r = SSL_read(client_conn->ssl, buffer, sizeof(buffer));
                if (r > 0) {
                    nread = r;
                } else {
                    int err = SSL_get_error(client_conn->ssl, r);
                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                        nread = -1;
                        errno = EAGAIN;
                    } else {
                        nread = 0;
                    }
                }
            } else {
                nread = recv(client_fd, buffer, sizeof(buffer), 0);
            }

            if (nread > 0) {
                size_t total_sent = 0;
                while (total_sent < (size_t)nread) {
                    ssize_t sent = send(upstream_fd, buffer + total_sent, (size_t)nread - total_sent, MSG_NOSIGNAL);
                    if (sent > 0) {
                        total_sent += (size_t)sent;
                    } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        struct pollfd out_fd = { .fd = upstream_fd, .events = POLLOUT, .revents = 0 };
                        if (poll(&out_fd, 1, 5000) <= 0) {
                            goto tunnel_done;
                        }
                    } else if (sent < 0 && errno == EINTR) {
                        continue;
                    } else {
                        goto tunnel_done;
                    }
                }
            } else if (nread == 0 || (nread < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                goto tunnel_done;
            }
        }

        /* 2. Upstream -> Client */
        if (fds[1].revents & (POLLIN | POLLERR | POLLHUP | POLLRDHUP)) {
            ssize_t nread = recv(upstream_fd, buffer, sizeof(buffer), 0);
            if (nread > 0) {
                size_t total_sent = 0;
                while (total_sent < (size_t)nread) {
                    ssize_t sent = 0;
                    if (client_conn->transport == APEX_TRANSPORT_TLS && client_conn->ssl != NULL) {
                        int w = SSL_write(client_conn->ssl, buffer + total_sent, (int)((size_t)nread - total_sent));
                        if (w > 0) {
                            sent = w;
                        } else {
                            int err = SSL_get_error(client_conn->ssl, w);
                            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                                sent = -1;
                                errno = EAGAIN;
                            } else {
                                goto tunnel_done;
                            }
                        }
                    } else {
                        sent = send(client_fd, buffer + total_sent, (size_t)nread - total_sent, MSG_NOSIGNAL);
                    }

                    if (sent > 0) {
                        total_sent += (size_t)sent;
                    } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        struct pollfd out_fd = { .fd = client_fd, .events = POLLOUT, .revents = 0 };
                        if (poll(&out_fd, 1, 5000) <= 0) {
                            goto tunnel_done;
                        }
                    } else if (sent < 0 && errno == EINTR) {
                        continue;
                    } else {
                        goto tunnel_done;
                    }
                }
            } else if (nread == 0 || (nread < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                goto tunnel_done;
            }
        }
    }

tunnel_done:
    close(upstream_fd);
    client_conn->close_after_write = 1;
    client_conn->read_length = 0;
}

static void router_forward_request(apex_config_route_t *route, const char *request, size_t request_length,
                                   const char *method, size_t method_length, const char *target,
                                   size_t target_length, const char *body, size_t body_length, apex_res_t *res,
                                   const char *extra_headers, size_t extra_headers_len) {
    conn_t *connection = res->conn;
    const apex_server_config_t *server = route ? route->server : NULL;
    if (route->group == NULL) {
        router_send_error(connection, server, request, request_length, 502, "Bad Gateway", "no upstream group for location\n");
        return;
    }

    char method_text[16];
    if (method_length == 0 || method_length >= sizeof(method_text)) {
        router_send_error(connection, server, request, request_length, 400, "Bad Request", "invalid request method\n");
        return;
    }
    memcpy(method_text, method, method_length);
    method_text[method_length] = '\0';

    if (target_length == 0 || target_length > APEX_PROXY_MAX_REQUEST_BYTES) {
        router_send_error(connection, server, request, request_length, 400, "Bad Request", "invalid request target\n");
        return;
    }

    char *target_text = malloc(target_length + 1u);
    if (target_text == NULL) {
        router_send_error(connection, server, request, request_length, 500, "Internal Server Error", "out of memory\n");
        return;
    }
    memcpy(target_text, target, target_length);
    target_text[target_length] = '\0';

    char host[256];
    host[0] = '\0';
    const char *host_value = NULL;
    size_t host_length = 0;
    if (router_find_header(request, request_length, "Host", &host_value, &host_length)) {
        if (host_length >= sizeof(host)) {
            free(target_text);
            router_send_error(connection, server, request, request_length, 400, "Bad Request", "host header is too long\n");
            return;
        }
        memcpy(host, host_value, host_length);
        host[host_length] = '\0';
    }

    char *headers = NULL;
    size_t headers_length = 0;
    if (!build_request_headers(request, request_length, route->location, connection, host,
                               target_text, target_length, &headers, &headers_length)) {
        free(target_text);
        router_send_error(connection, server, request, request_length, 500, "Internal Server Error", "out of memory\n");
        return;
    }

    apex_proxy_request_t proxy_request = {
        .method = method_text,
        .target = target_text,
        .host = host[0] != '\0' ? host : NULL,
        .headers = headers,
        .headers_len = headers_length,
        .body = body,
        .body_len = body_length,
        .keep_alive = connection->close_after_write == 0,
    };

    apex_proxy_response_t proxy_response;
    int result = apex_proxy_forward((upstream_group_t *)(uintptr_t)route->group, &proxy_request, &proxy_response);

    free(headers);
    free(target_text);

    if (result != APEX_PROXY_OK) {
        int status = result == APEX_PROXY_ERR_TIMEOUT ? 504 : 502;
        const char *reason = status == 504 ? "Gateway Timeout" : "Bad Gateway";
        char message[160];
        snprintf(message, sizeof(message), "upstream error: %s\n", apex_proxy_strerror(result));
        router_send_error(connection, server, request, request_length, status, reason, message);
        return;
    }

    router_write_proxy_response(connection, server, request, request_length, &proxy_response,
                                strcasecmp(method_text, "HEAD") == 0, extra_headers, extra_headers_len);

    if (proxy_response.status == 101 && proxy_response.upstream_fd >= 0) {
        /* Flush written 101 response headers to client socket */
        while (connection->write_length > connection->write_offset) {
            int sent = apex_transport_write(connection, connection->write_buffer + connection->write_offset,
                                            connection->write_length - connection->write_offset);
            if (sent > 0) {
                connection->write_offset += (uint32_t)sent;
                if (connection->write_offset == connection->write_length) {
                    connection->write_offset = 0;
                    connection->write_length = 0;
                }
            } else if (sent == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                struct pollfd pfd = { .fd = connection->fd, .events = POLLOUT, .revents = 0 };
                poll(&pfd, 1, 5000);
            } else {
                break;
            }
        }

        /* Forward any leftover bytes from upstream to client */
        if (proxy_response.leftover_len > 0 && proxy_response.leftover_data != NULL) {
            size_t sent_leftover = 0;
            while (sent_leftover < proxy_response.leftover_len) {
                int sent = apex_transport_write(connection, proxy_response.leftover_data + sent_leftover,
                                                proxy_response.leftover_len - sent_leftover);
                if (sent > 0) {
                    sent_leftover += (size_t)sent;
                } else if (sent == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    struct pollfd pfd = { .fd = connection->fd, .events = POLLOUT, .revents = 0 };
                    poll(&pfd, 1, 5000);
                } else {
                    break;
                }
            }
        }

        /* Forward any unparsed client pipelined data to upstream */
        const char *consumed_end = request + request_length + body_length;
        const char *buf_end = connection->read_buffer + connection->read_length;
        if (consumed_end < buf_end) {
            size_t unparsed = (size_t)(buf_end - consumed_end);
            size_t sent_client = 0;
            while (sent_client < unparsed) {
                ssize_t s = send(proxy_response.upstream_fd, consumed_end + sent_client, unparsed - sent_client, MSG_NOSIGNAL);
                if (s > 0) {
                    sent_client += (size_t)s;
                } else {
                    break;
                }
            }
        }

        /* Run full-duplex tunnel until closure or idle timeout */
        uint64_t timeout_ms = (route->location != NULL && route->location->has_read_timeout)
                              ? route->location->read_timeout_ms : 60000u;
        apex_proxy_ws_tunnel(connection, proxy_response.upstream_fd, timeout_ms);
        proxy_response.upstream_fd = -1;
    }

    apex_proxy_response_free(&proxy_response);
}


apex_app_t *apex_create(void) {
    apex_app_t *app = (apex_app_t *)calloc(1, sizeof(apex_app_t));
    if (app != NULL) {
        atomic_init(&app->running, false);
    }
    return app;
}

apex_generation_t *apex_generation_create(apex_config_t *config, apex_config_error_t *error) {
    apex_runtime_t *runtime = apex_runtime_create(config, error);
    if (runtime == NULL) {
        return NULL;
    }

    apex_generation_t *generation = malloc(sizeof(*generation));
    if (generation == NULL) {
        apex_runtime_destroy(runtime);
        if (error != NULL) {
            memset(error, 0, sizeof(*error));
            error->code = APEX_CONFIG_ERR_MEMORY;
            snprintf(error->message, sizeof(error->message), "cannot allocate configuration generation");
        }
        return NULL;
    }
    atomic_init(&generation->references, 1u);
    generation->config = config;
    generation->runtime = runtime;
    generation->tls_context = NULL;

    /* The standalone core serves exactly one listening endpoint shared by all
     * virtual hosts, so the endpoint must not mix TLS and plaintext servers:
     * a single connection could not speak both. Build one SSL_CTX up front. */
    bool tls_listener = false;
    for (size_t index = 0; index < config->server_count; index++) {
        if (config->servers[index].listen_tls != config->servers[0].listen_tls) {
            if (error != NULL) {
                memset(error, 0, sizeof(*error));
                error->code = APEX_CONFIG_ERR_SEMANTIC;
                error->line = config->servers[index].line;
                snprintf(error->file, sizeof(error->file), "%s", config->source);
                snprintf(error->message, sizeof(error->message),
                         "cannot mix tls and plaintext servers on one listen endpoint");
            }
            free(generation);
            apex_runtime_destroy(runtime);
            return NULL;
        }
        tls_listener = tls_listener || config->servers[index].listen_tls;
    }
    if (tls_listener) {
        generation->tls_context = apex_tls_context_create(config, &config->servers[0], error);
        if (generation->tls_context == NULL) {
            free(generation);
            apex_runtime_destroy(runtime);
            return NULL;
        }
    }

    return generation;
}

void apex_generation_retain(apex_generation_t *generation) {
    if (generation != NULL) {
        atomic_fetch_add_explicit(&generation->references, 1u, memory_order_relaxed);
    }
}

void apex_generation_release(apex_generation_t *generation) {
    if (generation != NULL &&
        atomic_fetch_sub_explicit(&generation->references, 1u, memory_order_acq_rel) == 1u) {
        apex_runtime_destroy(generation->runtime);
        apex_config_free(generation->config);
        apex_tls_context_destroy(generation->tls_context);
        free(generation);
    }
}

void apex_destroy(apex_app_t *app) {
    if (app) {
        apex_generation_release(app->generation);
        free(app);
    }
}

int apex_app_attach_config(apex_app_t *app, apex_config_t *config, apex_config_error_t *error) {
    if (app == NULL || config == NULL) {
        if (error != NULL) {
            memset(error, 0, sizeof(*error));
            error->code = APEX_CONFIG_ERR_IO;
            snprintf(error->message, sizeof(error->message), "invalid configuration attachment");
        }
        return -1;
    }

    if (atomic_load_explicit(&app->running, memory_order_acquire)) {
        if (error != NULL) {
            memset(error, 0, sizeof(*error));
            error->code = APEX_CONFIG_ERR_RUNTIME;
            snprintf(error->message, sizeof(error->message), "cannot attach a configuration while the app is running");
        }
        return -1;
    }
    if (app->generation != NULL && app->generation->config == config) {
        if (error != NULL) {
            memset(error, 0, sizeof(*error));
        }
        return 0;
    }

    apex_generation_t *generation = apex_generation_create(config, error);
    if (generation == NULL) {
        return -1;
    }
    apex_generation_release(app->generation);
    app->generation = generation;
    return 0;
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
    if (res == NULL || res->conn == NULL) {
        return;
    }
    conn_t *connection = res->conn;
    if (connection->fd < 0) {
        return;
    }

    if (status == 200) {
        if (!body || body_len == 0) {
            static const char RESP_200_EMPTY[] = "HTTP/1.1 200 OK\r\n"
                                                 "Server: apex\r\n"
                                                 "Content-Length: 0\r\n"
                                                 "Connection: keep-alive\r\n"
                                                 "\r\n";
            apex_conn_write(connection, RESP_200_EMPTY, sizeof(RESP_200_EMPTY) - 1u);
            return;
        }

        static const char HDR_PRE[] = "HTTP/1.1 200 OK\r\nServer: apex\r\nContent-Length: ";
        static const char HDR_POST[] = "\r\nConnection: keep-alive\r\n\r\n";

        char length_string[16];
        size_t digit_count = 0;
        size_t temp_length = body_len;
        do {
            length_string[digit_count++] = (char)('0' + (temp_length % 10));
            temp_length /= 10;
        } while (temp_length > 0);

        apex_conn_write(connection, HDR_PRE, sizeof(HDR_PRE) - 1u);
        char ordered[16];
        for (size_t digit_index = 0; digit_index < digit_count; digit_index++) {
            ordered[digit_index] = length_string[digit_count - 1u - digit_index];
        }
        apex_conn_write(connection, ordered, digit_count);
        apex_conn_write(connection, HDR_POST, sizeof(HDR_POST) - 1u);
        apex_conn_write(connection, body, body_len);
    } else {
        static const char RESP_404[] = "HTTP/1.1 404 Not Found\r\n"
                                       "Server: apex\r\n"
                                       "Content-Length: 0\r\n"
                                       "Connection: keep-alive\r\n"
                                       "\r\n";
        apex_conn_write(connection, RESP_404, sizeof(RESP_404) - 1u);
    }
}

void apex_res_header(apex_res_t *res, const char *key, const char *value) {
    (void)res;
    (void)key;
    (void)value;
}

static const char *router_determine_content_type(const char *path) {
    return apex_mime_type(path);
}

void apex_dispatch(apex_app_t *app, const char *req_buf, size_t header_len, const char *body, size_t body_len,
                   apex_res_t *res) {
    const apex_runtime_t *runtime = app->generation != NULL ? app->generation->runtime : NULL;
    apex_dispatch_runtime(app, runtime, req_buf, header_len, body, body_len, res);
}

void apex_dispatch_runtime(apex_app_t *app, const apex_runtime_t *runtime, const char *req_buf, size_t header_len,
                           const char *body, size_t body_len, apex_res_t *res) {
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

    if (runtime != NULL) {
        char host[256];
        size_t host_length = 0;
        const char *host_value = NULL;
        size_t host_value_length = 0;
        if (router_find_header(req_buf, header_len, "Host", &host_value, &host_value_length) &&
            host_value_length < sizeof(host)) {
            memcpy(host, host_value, host_value_length);
            host[host_value_length] = '\0';
            host_length = host_value_length;
        }

        size_t match_path_length = path_len;
        const char *query = memchr(path, '?', path_len);
        if (query != NULL) {
            match_path_length = (size_t)(query - path);
        }

        apex_pipeline_ctx_t ctx = {
            .method = req_buf,
            .method_len = method_len,
            .path = path,
            .path_len = path_len,
            .raw_request = req_buf,
            .raw_request_len = header_len,
            .body = body,
            .body_len = body_len,
            .conn = res != NULL ? res->conn : NULL,
            .res = res,
            .server = NULL,
            .location = NULL,
            .runtime = runtime,
            .status_code = 200,
            .start_time_us = 0,
            .extra_headers = {0},
            .extra_headers_len = 0,
            .module_data = {0},
        };

        /* Phase 1: PRE_ROUTING */
        apex_action_t action = apex_pipeline_run_phase(&ctx, APEX_PHASE_PRE_ROUTING);
        if (action == APEX_ACTION_DENY) {
            int deny_status = ctx.status_code >= 400 ? ctx.status_code : 403;
            router_send_error_ex(res->conn, NULL, req_buf, header_len,
                                 deny_status, "Forbidden", "Forbidden\n",
                                 ctx.extra_headers, ctx.extra_headers_len);
            apex_pipeline_run_phase(&ctx, APEX_PHASE_LOGGING);
            return;
        }
        if (action == APEX_ACTION_DONE) {
            return;
        }

        apex_config_route_t route;
        if (apex_runtime_match(runtime, host, host_length, path, match_path_length, &route)) {
            ctx.server = route.server;
            ctx.location = route.location;

            /* Server-level return redirect */
            if (route.server != NULL && route.server->return_code > 0) {
                char client_ip[INET6_ADDRSTRLEN];
                if (!conn_get_peer_ip(res->conn, client_ip, sizeof(client_ip))) {
                    strcpy(client_ip, "127.0.0.1");
                }
                const char *scheme = (res->conn != NULL && res->conn->transport == APEX_TRANSPORT_TLS) ? "https" : "http";
                char expanded[APEX_CONFIG_PATH_MAX * 2];
                router_expand_string(route.server->return_url, expanded, sizeof(expanded),
                                     host, host_length, path, path_len,
                                     client_ip, strlen(client_ip),
                                     scheme, strlen(scheme),
                                     NULL, 0, NULL, 0, NULL, 0);
                router_send_redirect(res->conn, route.server->return_code, expanded,
                                     ctx.extra_headers, ctx.extra_headers_len);
                apex_pipeline_run_phase(&ctx, APEX_PHASE_LOGGING);
                return;
            }

            /* Server-level ACL rules */
            if (route.server != NULL && route.server->acl_rule_count > 0 && res->conn != NULL) {
                if (!router_check_acl(route.server->acl_rules, route.server->acl_rule_count, res->conn->fd)) {
                    router_send_error(res->conn, route.server, req_buf, header_len, 403, "Forbidden", "Forbidden\n");
                    apex_pipeline_run_phase(&ctx, APEX_PHASE_LOGGING);
                    return;
                }
            }

            if (route.location != NULL) {
                /* Location-level return redirect */
                if (route.location->return_code > 0) {
                    char client_ip[INET6_ADDRSTRLEN];
                    if (!conn_get_peer_ip(res->conn, client_ip, sizeof(client_ip))) {
                        strcpy(client_ip, "127.0.0.1");
                    }
                    const char *scheme = (res->conn != NULL && res->conn->transport == APEX_TRANSPORT_TLS) ? "https" : "http";
                    char expanded[APEX_CONFIG_PATH_MAX * 2];
                    router_expand_string(route.location->return_url, expanded, sizeof(expanded),
                                         host, host_length, path, path_len,
                                         client_ip, strlen(client_ip),
                                         scheme, strlen(scheme),
                                         NULL, 0, NULL, 0, NULL, 0);
                    router_send_redirect(res->conn, route.location->return_code, expanded,
                                         ctx.extra_headers, ctx.extra_headers_len);
                    apex_pipeline_run_phase(&ctx, APEX_PHASE_LOGGING);
                    return;
                }

                /* Location-level ACL rules */
                if (route.location->acl_rule_count > 0 && res->conn != NULL) {
                    if (!router_check_acl(route.location->acl_rules, route.location->acl_rule_count, res->conn->fd)) {
                        router_send_error(res->conn, route.server, req_buf, header_len, 403, "Forbidden", "Forbidden\n");
                        apex_pipeline_run_phase(&ctx, APEX_PHASE_LOGGING);
                        return;
                    }
                }

                /* Phase 3: HEADER_FILTER */
                action = apex_pipeline_run_phase(&ctx, APEX_PHASE_HEADER_FILTER);
                if (action == APEX_ACTION_DENY) {
                    int deny_status = ctx.status_code >= 400 ? ctx.status_code : 403;
                    router_send_error_ex(res->conn, route.server, req_buf, header_len,
                                         deny_status, "Forbidden", "Forbidden\n",
                                         ctx.extra_headers, ctx.extra_headers_len);
                    apex_pipeline_run_phase(&ctx, APEX_PHASE_LOGGING);
                    return;
                }
                if (action == APEX_ACTION_DONE) {
                    return;
                }

                /* Phase 4: ACCESS_CONTROL */
                action = apex_pipeline_run_phase(&ctx, APEX_PHASE_ACCESS_CONTROL);
                if (action == APEX_ACTION_DENY) {
                    int deny_status = ctx.status_code >= 400 ? ctx.status_code : 403;
                    router_send_error_ex(res->conn, route.server, req_buf, header_len,
                                         deny_status, "Forbidden", "Access Denied by Policy\n",
                                         ctx.extra_headers, ctx.extra_headers_len);
                    apex_pipeline_run_phase(&ctx, APEX_PHASE_LOGGING);
                    return;
                }
                if (action == APEX_ACTION_DONE) {
                    return;
                }

                /* Phase 5: CONTENT_HANDLER */
                action = apex_pipeline_run_phase(&ctx, APEX_PHASE_CONTENT_HANDLER);
                if (action == APEX_ACTION_DONE) {
                    apex_pipeline_run_phase(&ctx, APEX_PHASE_RESPONSE_FILTER);
                    apex_pipeline_run_phase(&ctx, APEX_PHASE_LOGGING);
                    return;
                }

                /* Phase 6: RESPONSE_FILTER */
                apex_pipeline_run_phase(&ctx, APEX_PHASE_RESPONSE_FILTER);

                if (route.location->target != APEX_PROXY_TARGET_NONE) {
                    router_forward_request(&route, req_buf, header_len, req_buf, method_len, path, path_len, body,
                                           body_len, res, ctx.extra_headers, ctx.extra_headers_len);
                    apex_pipeline_run_phase(&ctx, APEX_PHASE_LOGGING);
                    return;
                }
                if (route.location->root != NULL) {
                    bool head_request = method_len == 4 && memcmp(req_buf, "HEAD", 4) == 0;
                    apex_static_serve(route.server, route.location, req_buf, header_len, path, match_path_length,
                                      head_request, res, ctx.extra_headers, ctx.extra_headers_len);
                    apex_pipeline_run_phase(&ctx, APEX_PHASE_LOGGING);
                    return;
                }
            }
        }

        if (runtime->config != NULL && runtime->config->server_count > 0) {
            router_send_error(res->conn, &runtime->config->servers[0], req_buf, header_len, 404, "Not Found",
                              "Not Found\n");
            apex_pipeline_run_phase(&ctx, APEX_PHASE_LOGGING);
            return;
        }
    }

    apex_res_send(res, 404, NULL, 0);
}
