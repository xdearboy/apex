#include "internal.h"
#include "apex/cache.h"
#include "apex/realip.h"
#include "apex/log.h"
#include "apex/fastcgi.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <poll.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/time.h>

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

static bool router_check_acl(const apex_acl_rule_t *rules, size_t rule_count, const char *client_ip, int fd) {
    if (rules == NULL || rule_count == 0) {
        return true;
    }
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    if (client_ip != NULL && client_ip[0] != '\0') {
        const char *eval_ip = client_ip;
        if (strncasecmp(eval_ip, "::ffff:", 7) == 0) {
            eval_ip += 7;
        }
        struct in_addr addr4;
        if (inet_pton(AF_INET, eval_ip, &addr4) == 1) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
            sin->sin_family = AF_INET;
            sin->sin_addr = addr4;
        } else {
            struct in6_addr addr6;
            if (inet_pton(AF_INET6, eval_ip, &addr6) == 1) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
                sin6->sin6_family = AF_INET6;
                sin6->sin6_addr = addr6;
            }
        }
    }
    if (ss.ss_family == 0 && fd >= 0) {
        socklen_t slen = sizeof(ss);
        if (getpeername(fd, (struct sockaddr *)&ss, &slen) != 0) {
            return true;
        }
    }
    for (size_t i = 0; i < rule_count; i++) {
        if (acl_rule_matches(&rules[i], &ss)) {
            return rules[i].allow;
        }
    }
    return true;
}

static const apex_server_tokens_config_t *router_get_server_tokens(const apex_runtime_t *runtime,
                                                                   const apex_server_config_t *server) {
    if (server != NULL && server->server_tokens.set) {
        return &server->server_tokens;
    }
    if (runtime != NULL && runtime->config != NULL && runtime->config->http.server_tokens.set) {
        return &runtime->config->http.server_tokens;
    }
    static const apex_server_tokens_config_t def_tokens = {
        .mode = APEX_SERVER_TOKENS_ON,
        .set = true,
        .custom_value = ""
    };
    return &def_tokens;
}

static size_t router_format_server_header(const apex_server_tokens_config_t *tokens, char *buf, size_t buf_cap) {
    if (tokens == NULL || tokens->mode == APEX_SERVER_TOKENS_ON) {
        return (size_t)snprintf(buf, buf_cap, "Server: apex\r\n");
    }
    if (tokens->mode == APEX_SERVER_TOKENS_CUSTOM) {
        return (size_t)snprintf(buf, buf_cap, "Server: %s\r\n", tokens->custom_value);
    }
    /* APEX_SERVER_TOKENS_OFF */
    if (buf_cap > 0) {
        buf[0] = '\0';
    }
    return 0;
}

static bool router_status_matches_add_header(int status, bool always) {
    if (always) {
        return true;
    }
    return (status == 200 || status == 201 || status == 204 || status == 206 ||
            status == 301 || status == 302 || status == 303 || status == 304 ||
            status == 307 || status == 308);
}

static _Thread_local char s_current_request_id[36] = {0};
static _Thread_local char s_current_otel_trace_id[33] = {0};
static _Thread_local char s_current_otel_span_id[17] = {0};
static _Thread_local char s_current_otel_parent_id[17] = {0};
static _Thread_local char s_current_otel_flags[3] = "01";
static _Thread_local char s_current_otel_tracestate[256] = {0};
static _Thread_local bool s_current_otel_active = false;

static void router_generate_hex(char *dst, size_t num_bytes) {
    if (dst == NULL || num_bytes == 0) return;
    uint8_t rand_bytes[32];
    if (num_bytes > sizeof(rand_bytes)) num_bytes = sizeof(rand_bytes);

    static _Thread_local uint64_t s_rng_state[2];
    static _Thread_local bool s_rng_inited = false;
    if (!s_rng_inited) {
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ssize_t rd = read(fd, s_rng_state, sizeof(s_rng_state));
            close(fd);
            if (rd == (ssize_t)sizeof(s_rng_state) && (s_rng_state[0] || s_rng_state[1])) {
                s_rng_inited = true;
            }
        }
        if (!s_rng_inited) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            s_rng_state[0] = ((uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec) ^ (uintptr_t)&s_rng_state;
            s_rng_state[1] = s_rng_state[0] * 6364136223846793005ULL + 1442695040888963407ULL;
            s_rng_inited = true;
        }
    }

    /* Fast xoroshiro128+ PRNG */
    size_t generated = 0;
    while (generated < num_bytes) {
        uint64_t s0 = s_rng_state[0];
        uint64_t s1 = s_rng_state[1];
        uint64_t result = s0 + s1;
        s1 ^= s0;
        s_rng_state[0] = ((s0 << 55) | (s0 >> 9)) ^ s1 ^ (s1 << 14);
        s_rng_state[1] = (s1 << 36) | (s1 >> 28);

        size_t chunk = (num_bytes - generated < sizeof(result)) ? (num_bytes - generated) : sizeof(result);
        memcpy(rand_bytes + generated, &result, chunk);
        generated += chunk;
    }

    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < num_bytes; i++) {
        dst[i * 2] = hex_chars[(rand_bytes[i] >> 4) & 0x0F];
        dst[i * 2 + 1] = hex_chars[rand_bytes[i] & 0x0F];
    }
    dst[num_bytes * 2] = '\0';
}

static void router_generate_request_id(char *dst, size_t dst_cap) {
    if (dst == NULL || dst_cap < 33) return;
    router_generate_hex(dst, 16);
}

static void router_otel_init(const char *request, size_t request_length, const apex_otel_config_t *otel_cfg) {
    s_current_otel_trace_id[0] = '\0';
    s_current_otel_span_id[0] = '\0';
    s_current_otel_parent_id[0] = '\0';
    strcpy(s_current_otel_flags, "01");
    s_current_otel_tracestate[0] = '\0';
    s_current_otel_active = false;

    if (otel_cfg == NULL || !otel_cfg->enabled) {
        return;
    }
    s_current_otel_active = true;

    const char *tp_val = NULL;
    size_t tp_len = 0;
    if (router_find_header(request, request_length, "traceparent", &tp_val, &tp_len) && tp_len >= 55) {
        if (tp_val[2] == '-' && tp_val[35] == '-' && tp_val[52] == '-') {
            char trace_id[33];
            memcpy(trace_id, tp_val + 3, 32);
            trace_id[32] = '\0';

            char parent_id[17];
            memcpy(parent_id, tp_val + 36, 16);
            parent_id[16] = '\0';

            char flags[3];
            memcpy(flags, tp_val + 53, 2);
            flags[2] = '\0';

            bool valid_trace = false;
            for (int i = 0; i < 32; i++) {
                if (trace_id[i] != '0') valid_trace = true;
            }
            if (valid_trace) {
                memcpy(s_current_otel_trace_id, trace_id, 33);
                memcpy(s_current_otel_parent_id, parent_id, 17);
                memcpy(s_current_otel_flags, flags, 3);
            }
        }
    }

    if (s_current_otel_trace_id[0] == '\0') {
        router_generate_hex(s_current_otel_trace_id, 16);
        s_current_otel_parent_id[0] = '\0';
    }
    router_generate_hex(s_current_otel_span_id, 8);

    const char *ts_val = NULL;
    size_t ts_len = 0;
    if (router_find_header(request, request_length, "tracestate", &ts_val, &ts_len)) {
        if (ts_len >= sizeof(s_current_otel_tracestate)) {
            ts_len = sizeof(s_current_otel_tracestate) - 1;
        }
        memcpy(s_current_otel_tracestate, ts_val, ts_len);
        s_current_otel_tracestate[ts_len] = '\0';
    }
}

static const char *router_resolve_source_var(const char *source_var,
                                             const char *host,
                                             const char *uri,
                                             const char *remote_addr,
                                             const char *scheme) {
    if (source_var == NULL || source_var[0] == '\0') {
        return host ? host : "";
    }
    if (strcmp(source_var, "request_id") == 0) {
        if (s_current_request_id[0] == '\0') {
            router_generate_request_id(s_current_request_id, sizeof(s_current_request_id));
        }
        return s_current_request_id;
    }
    if (strcmp(source_var, "otel_trace_id") == 0) {
        if (s_current_otel_trace_id[0] == '\0') {
            router_generate_hex(s_current_otel_trace_id, 16);
        }
        return s_current_otel_trace_id;
    }
    if (strcmp(source_var, "otel_span_id") == 0) {
        if (s_current_otel_span_id[0] == '\0') {
            router_generate_hex(s_current_otel_span_id, 8);
        }
        return s_current_otel_span_id;
    }
    if (strcmp(source_var, "otel_parent_id") == 0) {
        return s_current_otel_parent_id;
    }
    if (strcmp(source_var, "host") == 0 || strcmp(source_var, "http_host") == 0) {
        return host ? host : "";
    }
    if (strcmp(source_var, "uri") == 0 || strcmp(source_var, "request_uri") == 0) {
        return uri ? uri : "";
    }
    if (strcmp(source_var, "remote_addr") == 0) {
        return remote_addr ? remote_addr : "";
    }
    if (strcmp(source_var, "scheme") == 0) {
        return scheme ? scheme : "";
    }
    return host ? host : "";
}

static void router_expand_string_ex(const apex_runtime_t *runtime,
                                    const char *src, char *dst, size_t dst_len,
                                    const char *host, size_t host_len,
                                    const char *uri, size_t uri_len,
                                    const char *remote_addr, size_t remote_addr_len,
                                    const char *scheme, size_t scheme_len,
                                    const char *existing_xff, size_t existing_xff_len,
                                    const char *upgrade, size_t upgrade_len,
                                    const char *connection, size_t connection_len,
                                    int status_code, uint64_t upstream_time_us) {
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
            char status_buf[16];
            char urt_buf[32];

            if (var_len == 10 && strncmp(var, "request_id", 10) == 0) {
                if (s_current_request_id[0] == '\0') {
                    router_generate_request_id(s_current_request_id, sizeof(s_current_request_id));
                }
                subst = s_current_request_id;
                subst_len = strlen(s_current_request_id);
            } else if (var_len == 13 && strncmp(var, "otel_trace_id", 13) == 0) {
                if (s_current_otel_trace_id[0] == '\0') {
                    router_generate_hex(s_current_otel_trace_id, 16);
                }
                subst = s_current_otel_trace_id;
                subst_len = strlen(s_current_otel_trace_id);
            } else if (var_len == 12 && strncmp(var, "otel_span_id", 12) == 0) {
                if (s_current_otel_span_id[0] == '\0') {
                    router_generate_hex(s_current_otel_span_id, 8);
                }
                subst = s_current_otel_span_id;
                subst_len = strlen(s_current_otel_span_id);
            } else if (var_len == 14 && strncmp(var, "otel_parent_id", 14) == 0) {
                subst = s_current_otel_parent_id;
                subst_len = strlen(s_current_otel_parent_id);
            } else if (var_len == 4 && strncmp(var, "host", 4) == 0) {
                subst = host;
                subst_len = host_len;
            } else if (var_len == 9 && strncmp(var, "http_host", 9) == 0) {
                subst = host;
                subst_len = host_len;
            } else if (var_len == 11 && strncmp(var, "request_uri", 11) == 0) {
                subst = uri;
                subst_len = uri_len;
            } else if (var_len == 3 && strncmp(var, "uri", 3) == 0) {
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
            } else if (var_len == 6 && strncmp(var, "status", 6) == 0) {
                int w = snprintf(status_buf, sizeof(status_buf), "%d", status_code);
                if (w > 0 && (size_t)w < sizeof(status_buf)) {
                    subst = status_buf;
                    subst_len = (size_t)w;
                }
            } else if (var_len == 22 && strncmp(var, "upstream_response_time", 22) == 0) {
                int w = snprintf(urt_buf, sizeof(urt_buf), "%.3f", (double)upstream_time_us / 1000000.0);
                if (w > 0 && (size_t)w < sizeof(urt_buf)) {
                    subst = urt_buf;
                    subst_len = (size_t)w;
                }
            } else if (var_len == 12 && strncmp(var, "request_time", 12) == 0) {
                int w = snprintf(urt_buf, sizeof(urt_buf), "%.3f", (double)upstream_time_us / 1000000.0);
                if (w > 0 && (size_t)w < sizeof(urt_buf)) {
                    subst = urt_buf;
                    subst_len = (size_t)w;
                }
            } else if (var_len == 26 && strncmp(var, "proxy_add_x_forwarded_for", 26) == 0) {
                if (existing_xff != NULL && existing_xff_len > 0) {
                    int w = snprintf(xff_buf, sizeof(xff_buf), "%.*s, %.*s",
                                     (int)existing_xff_len, existing_xff,
                                     (int)remote_addr_len, remote_addr ? remote_addr : "");
                    if (w > 0 && (size_t)w < sizeof(xff_buf)) {
                        subst = xff_buf;
                        subst_len = (size_t)w;
                    }
                } else {
                    subst = remote_addr;
                    subst_len = remote_addr_len;
                }
            } else if (runtime != NULL && runtime->config != NULL) {
                char var_name[64];
                if (var_len < sizeof(var_name)) {
                    memcpy(var_name, var, var_len);
                    var_name[var_len] = '\0';
                    const apex_http_config_t *http = &runtime->config->http;
                    for (size_t m = 0; m < http->map_count; m++) {
                        if (strcmp(http->maps[m].target_var, var_name) == 0) {
                            const char *src_val = router_resolve_source_var(http->maps[m].source_var,
                                                                           host, uri, remote_addr, scheme);
                            const char *val = apex_map_lookup(runtime->config, var_name, src_val);
                            if (val != NULL && val[0] != '\0') {
                                subst = val;
                                subst_len = strlen(val);
                                break;
                            }
                        }
                    }
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

static void router_expand_string(const char *src, char *dst, size_t dst_len,
                                 const char *host, size_t host_len,
                                 const char *uri, size_t uri_len,
                                 const char *remote_addr, size_t remote_addr_len,
                                 const char *scheme, size_t scheme_len,
                                 const char *existing_xff, size_t existing_xff_len,
                                 const char *upgrade, size_t upgrade_len,
                                 const char *connection, size_t connection_len) {
    router_expand_string_ex(NULL, src, dst, dst_len, host, host_len, uri, uri_len,
                            remote_addr, remote_addr_len, scheme, scheme_len,
                            existing_xff, existing_xff_len, upgrade, upgrade_len,
                            connection, connection_len, 0, 0);
}

static size_t router_build_add_headers(const apex_runtime_t *runtime,
                                       const apex_server_config_t *server,
                                       const apex_location_config_t *location,
                                       int status_code,
                                       const char *host, size_t host_len,
                                       const char *uri, size_t uri_len,
                                       const char *remote_addr, size_t remote_addr_len,
                                       const char *scheme, size_t scheme_len,
                                       uint64_t upstream_time_us,
                                       char *out_buf, size_t out_buf_cap) {
    if (out_buf == NULL || out_buf_cap == 0) {
        return 0;
    }
    out_buf[0] = '\0';
    size_t out_len = 0;

    const apex_add_header_t *headers = NULL;
    size_t count = 0;
    if (location != NULL && location->add_header_count > 0) {
        headers = location->add_headers;
        count = location->add_header_count;
    } else if (server != NULL && server->add_header_count > 0) {
        headers = server->add_headers;
        count = server->add_header_count;
    } else if (runtime != NULL && runtime->config != NULL && runtime->config->http.add_header_count > 0) {
        headers = runtime->config->http.add_headers;
        count = runtime->config->http.add_header_count;
    }

    if (headers == NULL || count == 0) {
        return 0;
    }

    for (size_t i = 0; i < count; i++) {
        if (!router_status_matches_add_header(status_code, headers[i].always)) {
            continue;
        }
        char expanded_val[1024];
        router_expand_string_ex(runtime, headers[i].value, expanded_val, sizeof(expanded_val),
                                host, host_len, uri, uri_len,
                                remote_addr, remote_addr_len, scheme, scheme_len,
                                NULL, 0, NULL, 0, NULL, 0,
                                status_code, upstream_time_us);
        int written = snprintf(out_buf + out_len, out_buf_cap - out_len,
                               "%s: %s\r\n", headers[i].name, expanded_val);
        if (written > 0 && out_len + (size_t)written < out_buf_cap) {
            out_len += (size_t)written;
        }
    }
    return out_len;
}

static void router_send_redirect(conn_t *connection, const apex_server_config_t *server,
                                 int status_code, const char *location_url,
                                 const char *extra_headers, size_t extra_headers_len) {
    if (connection == NULL || connection->fd < 0) {
        return;
    }
    apex_record_status(status_code);
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

    const apex_server_tokens_config_t *tokens = router_get_server_tokens(NULL, server);
    char server_hdr[160];
    router_format_server_header(tokens, server_hdr, sizeof(server_hdr));

    char header[1024];
    int written = 0;
    if (status_code >= 300 && status_code < 400) {
        written = snprintf(header, sizeof(header),
                           "HTTP/1.1 %d %s\r\n"
                           "%s"
                           "Location: %s\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: %s\r\n",
                           status_code, reason, server_hdr, location_url ? location_url : "/",
                           connection->close_after_write ? "close" : "keep-alive");
    } else {
        size_t body_len = location_url ? strlen(location_url) : 0;
        written = snprintf(header, sizeof(header),
                           "HTTP/1.1 %d %s\r\n"
                           "%s"
                           "Content-Type: text/plain\r\n"
                           "Content-Length: %zu\r\n"
                           "Connection: %s\r\n",
                           status_code, reason, server_hdr, body_len,
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
                                  const char *effective_client_ip,
                                  char **headers, size_t *headers_length) {
    *headers = NULL;
    *headers_length = 0;

    char client_ip[INET6_ADDRSTRLEN];
    if (effective_client_ip != NULL && effective_client_ip[0] != '\0') {
        snprintf(client_ip, sizeof(client_ip), "%s", effective_client_ip);
    } else if (!conn_get_peer_ip(connection, client_ip, sizeof(client_ip))) {
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
                if (location != NULL && location->otel.enabled && location->otel.context_mode != APEX_OTEL_CTX_OFF) {
                    if (router_header_name_equal(line, name_len, "traceparent") ||
                        (router_header_name_equal(line, name_len, "tracestate") && s_current_otel_tracestate[0] != '\0')) {
                        skip_header = true;
                    }
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

    if (location != NULL && location->otel.enabled && location->otel.context_mode != APEX_OTEL_CTX_OFF) {
        char tp_buf[128];
        snprintf(tp_buf, sizeof(tp_buf), "traceparent: 00-%s-%s-%s\r\n",
                 s_current_otel_trace_id, s_current_otel_span_id, s_current_otel_flags);
        if (!router_buffer_append_string(&buffer, tp_buf)) {
            router_buffer_free(&buffer);
            return false;
        }
        if (s_current_otel_tracestate[0] != '\0') {
            if (!router_buffer_append_string(&buffer, "tracestate: ") ||
                !router_buffer_append_string(&buffer, s_current_otel_tracestate) ||
                !router_buffer_append_string(&buffer, "\r\n")) {
                router_buffer_free(&buffer);
                return false;
            }
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

static const char *router_find_error_page(const apex_server_config_t *server,
                                          const apex_location_config_t *location,
                                          int status) {
    if (location != NULL && location->error_pages != NULL) {
        for (size_t i = 0; i < location->error_page_count; i++) {
            if (location->error_pages[i].status_code == status) {
                return location->error_pages[i].path;
            }
        }
    }
    if (server != NULL && server->error_pages != NULL) {
        for (size_t i = 0; i < server->error_page_count; i++) {
            if (server->error_pages[i].status_code == status) {
                return server->error_pages[i].path;
            }
        }
    }
    return NULL;
}

static bool router_send_custom_error_page(conn_t *connection, const apex_server_config_t *server,
                                          const apex_location_config_t *location,
                                          int status, const char *reason,
                                          const char *extra_headers, size_t extra_headers_len) {
    const char *err_page_path = router_find_error_page(server, location, status);
    if (err_page_path == NULL) {
        return false;
    }
    int file_fd = open(err_page_path, O_RDONLY | O_CLOEXEC);
    if (file_fd < 0) {
        return false;
    }
    struct stat st;
    if (fstat(file_fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        st.st_size > 2u * 1024u * 1024u) {
        close(file_fd);
        return false;
    }
    size_t file_size = (size_t)st.st_size;
    char *file_buf = malloc(file_size);
    if (file_buf == NULL) {
        close(file_fd);
        return false;
    }
    ssize_t n = read(file_fd, file_buf, file_size);
    close(file_fd);
    if (n != (ssize_t)file_size) {
        free(file_buf);
        return false;
    }

    apex_record_status(status);
    const apex_server_tokens_config_t *tokens = router_get_server_tokens(NULL, server);
    char server_hdr[160];
    router_format_server_header(tokens, server_hdr, sizeof(server_hdr));

    char add_headers_buf[1024];
    size_t add_headers_len = router_build_add_headers(NULL, server, location, status,
                                                      NULL, 0, NULL, 0, NULL, 0, "http", 4,
                                                      0, add_headers_buf, sizeof(add_headers_buf));

    char combined_extra[1024];
    int extra_len = 0;
    if ((extra_headers != NULL && extra_headers_len > 0) || add_headers_len > 0) {
        extra_len = snprintf(combined_extra, sizeof(combined_extra), "%.*s%.*s",
                             (int)(extra_headers != NULL ? extra_headers_len : 0),
                             extra_headers != NULL ? extra_headers : "",
                             (int)add_headers_len, add_headers_buf);
        if (extra_len < 0 || (size_t)extra_len >= sizeof(combined_extra)) {
            extra_len = 0;
            combined_extra[0] = '\0';
        }
    } else {
        combined_extra[0] = '\0';
    }

    const char *content_type = router_determine_content_type(err_page_path);
    char header[1024];
    int written = snprintf(header, sizeof(header),
                           "HTTP/1.1 %d %s\r\n"
                           "%s"
                           "Content-Type: %s\r\n"
                           "Content-Length: %zu\r\n"
                           "Connection: %s\r\n"
                           "%.*s"
                           "\r\n",
                           status, reason ? reason : "Error", server_hdr, content_type, file_size,
                           connection->close_after_write ? "close" : "keep-alive",
                           extra_len, combined_extra);
    if (written > 0 && (size_t)written < sizeof(header)) {
        apex_conn_write(connection, header, (size_t)written);
        apex_conn_write(connection, file_buf, file_size);
        free(file_buf);
        return true;
    }
    free(file_buf);
    return false;
}

void router_send_error_ex(conn_t *connection, const apex_server_config_t *server,
                          const char *request, size_t request_length,
                          int status, const char *reason, const char *message,
                          const char *extra_headers, size_t extra_headers_len) {
    if (connection == NULL || connection->fd < 0) {
        return;
    }
    apex_record_status(status);

    const apex_server_tokens_config_t *tokens = router_get_server_tokens(NULL, server);
    char server_hdr[160];
    router_format_server_header(tokens, server_hdr, sizeof(server_hdr));

    char add_headers_buf[1024];
    size_t add_headers_len = router_build_add_headers(NULL, server, NULL, status,
                                                      NULL, 0, NULL, 0, NULL, 0, "http", 4,
                                                      0, add_headers_buf, sizeof(add_headers_buf));

    char combined_extra[1024];
    int extra_len = 0;
    if ((extra_headers != NULL && extra_headers_len > 0) || add_headers_len > 0) {
        extra_len = snprintf(combined_extra, sizeof(combined_extra), "%.*s%.*s",
                             (int)(extra_headers != NULL ? extra_headers_len : 0),
                             extra_headers != NULL ? extra_headers : "",
                             (int)add_headers_len, add_headers_buf);
        if (extra_len < 0 || (size_t)extra_len >= sizeof(combined_extra)) {
            extra_len = 0;
            combined_extra[0] = '\0';
        }
    } else {
        combined_extra[0] = '\0';
    }
    const char *extra = combined_extra;

    /* 1. Custom error_page if configured */
    if (router_send_custom_error_page(connection, server, NULL, status, reason, extra_headers, extra_headers_len)) {
        return;
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
                                   "%s"
                                   "Content-Type: application/json\r\n"
                                   "Content-Length: %d\r\n"
                                   "Connection: %s\r\n"
                                   "%.*s"
                                   "\r\n",
                                   status, reason, server_hdr, body_len,
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
                               "%s"
                               "Content-Type: text/plain\r\n"
                               "Content-Length: %zu\r\n"
                               "Connection: %s\r\n"
                               "%.*s"
                               "\r\n",
                               status, reason, server_hdr, message_length,
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
                           "%s"
                           "Content-Type: text/html; charset=utf-8\r\n"
                           "Content-Length: %d\r\n"
                           "Connection: %s\r\n"
                           "%.*s"
                           "\r\n",
                           status, reason, server_hdr, body_written,
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

static bool router_compress_response(const apex_compress_config_t *compress,
                                     const char *request, size_t request_len,
                                     const char *response_headers, size_t response_headers_len,
                                     int status,
                                     const void *in_body, size_t in_len,
                                     void **out_body, size_t *out_len,
                                     apex_compress_algo_t *out_algo) {
    if (compress == NULL || out_body == NULL || out_len == NULL || out_algo == NULL) {
        return false;
    }
    *out_body = NULL;
    *out_len = 0;
    *out_algo = APEX_COMPRESS_NONE;

    if (status == 204 || status == 304 || (status >= 100 && status < 200)) {
        return false;
    }
    if (in_body == NULL || in_len == 0) {
        return false;
    }

    const char *ae_val = NULL;
    size_t ae_len = 0;
    if (!router_find_header(request, request_len, "Accept-Encoding", &ae_val, &ae_len) || ae_len == 0) {
        return false;
    }

    const char *ce_val = NULL;
    size_t ce_len = 0;
    if (response_headers != NULL && response_headers_len > 0) {
        if (router_find_header(response_headers, response_headers_len, "Content-Encoding", &ce_val, &ce_len)) {
            return false; /* Upstream already encoded body */
        }
    }

    char ct_buf[128] = "text/plain";
    const char *ct_val = NULL;
    size_t ct_len = 0;
    if (response_headers != NULL && response_headers_len > 0) {
        if (router_find_header(response_headers, response_headers_len, "Content-Type", &ct_val, &ct_len)) {
            if (ct_len < sizeof(ct_buf)) {
                memcpy(ct_buf, ct_val, ct_len);
                ct_buf[ct_len] = '\0';
            }
        }
    }

    apex_compress_algo_t algo = apex_compress_negotiate(compress, ae_val, ae_len, ct_buf, in_len);
    if (algo == APEX_COMPRESS_NONE) {
        return false;
    }

    int comp_level = 0;
    if (algo == APEX_COMPRESS_ZSTD) comp_level = compress->zstd_comp_level;
    else if (algo == APEX_COMPRESS_BROTLI) comp_level = compress->brotli_comp_level;
    else if (algo == APEX_COMPRESS_GZIP) comp_level = compress->gzip_comp_level;

    if (!apex_compress_buffer(algo, comp_level, in_body, in_len, out_body, out_len)) {
        return false;
    }

    *out_algo = algo;
    return true;
}

static void router_get_cookie_rules(const apex_server_config_t *server,
                                    const apex_location_config_t *location,
                                    const apex_http_config_t *http,
                                    const apex_cookie_domain_rule_t **out_domains, size_t *out_domain_count,
                                    const apex_cookie_path_rule_t **out_paths, size_t *out_path_count) {
    *out_domains = NULL;
    *out_domain_count = 0;
    *out_paths = NULL;
    *out_path_count = 0;

    if (location != NULL && location->cookie_domain_off) {
        /* disabled in location */
    } else if (location != NULL && location->cookie_domain_count > 0) {
        *out_domains = location->cookie_domains;
        *out_domain_count = location->cookie_domain_count;
    } else if (server != NULL && server->cookie_domain_off) {
        /* disabled in server */
    } else if (server != NULL && server->cookie_domain_count > 0) {
        *out_domains = server->cookie_domains;
        *out_domain_count = server->cookie_domain_count;
    } else if (http != NULL && !http->cookie_domain_off && http->cookie_domain_count > 0) {
        *out_domains = http->cookie_domains;
        *out_domain_count = http->cookie_domain_count;
    }

    if (location != NULL && location->cookie_path_off) {
        /* disabled in location */
    } else if (location != NULL && location->cookie_path_count > 0) {
        *out_paths = location->cookie_paths;
        *out_path_count = location->cookie_path_count;
    } else if (server != NULL && server->cookie_path_off) {
        /* disabled in server */
    } else if (server != NULL && server->cookie_path_count > 0) {
        *out_paths = server->cookie_paths;
        *out_path_count = server->cookie_path_count;
    } else if (http != NULL && !http->cookie_path_off && http->cookie_path_count > 0) {
        *out_paths = http->cookie_paths;
        *out_path_count = http->cookie_path_count;
    }
}

static bool router_rewrite_cookie_line(const char *line, size_t line_length,
                                       const apex_cookie_domain_rule_t *domains, size_t domain_count,
                                       const apex_cookie_path_rule_t *paths, size_t path_count,
                                       char *out_buf, size_t out_capacity, size_t *out_len) {
    if ((domain_count == 0 && path_count == 0) || out_buf == NULL || out_capacity == 0) {
        return false;
    }

    const char *colon = memchr(line, ':', line_length);
    if (colon == NULL) {
        return false;
    }

    size_t name_len = (size_t)(colon - line);
    if (!router_header_name_equal(line, name_len, "Set-Cookie")) {
        return false;
    }

    const char *p = colon + 1;
    const char *end = line + line_length;
    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }

    size_t written = 0;
    int w = snprintf(out_buf, out_capacity, "Set-Cookie: ");
    if (w < 0 || (size_t)w >= out_capacity) return false;
    written += (size_t)w;

    bool modified = false;
    bool is_first = true;

    while (p < end) {
        const char *semi = memchr(p, ';', (size_t)(end - p));
        const char *attr_end = semi ? semi : end;

        const char *attr_start = p;
        while (attr_start < attr_end && (*attr_start == ' ' || *attr_start == '\t')) {
            attr_start++;
        }
        const char *attr_val_end = attr_end;
        while (attr_val_end > attr_start && (attr_val_end[-1] == ' ' || attr_val_end[-1] == '\t')) {
            attr_val_end--;
        }

        size_t attr_len = (size_t)(attr_val_end - attr_start);
        if (attr_len > 0) {
            if (!is_first) {
                if (written + 2 >= out_capacity) return false;
                memcpy(out_buf + written, "; ", 2);
                written += 2;
            }

            if (is_first) {
                if (written + attr_len >= out_capacity) return false;
                memcpy(out_buf + written, attr_start, attr_len);
                written += attr_len;
                is_first = false;
            } else {
                const char *eq = memchr(attr_start, '=', attr_len);
                if (eq != NULL) {
                    size_t key_len = (size_t)(eq - attr_start);
                    const char *val_start = eq + 1;
                    while (val_start < attr_val_end && (*val_start == ' ' || *val_start == '\t')) val_start++;
                    size_t val_len = (size_t)(attr_val_end - val_start);

                    char key_buf[32];
                    if (key_len < sizeof(key_buf)) {
                        memcpy(key_buf, attr_start, key_len);
                        key_buf[key_len] = '\0';
                    } else {
                        key_buf[0] = '\0';
                    }

                    if (strcasecmp(key_buf, "domain") == 0 && domain_count > 0) {
                        char dom_val[APEX_CONFIG_HOST_MAX];
                        if (val_len < sizeof(dom_val)) {
                            memcpy(dom_val, val_start, val_len);
                            dom_val[val_len] = '\0';
                        } else {
                            dom_val[0] = '\0';
                        }

                        bool dom_matched = false;
                        char new_dom[APEX_CONFIG_HOST_MAX * 2];
                        new_dom[0] = '\0';

                        for (size_t d = 0; d < domain_count; d++) {
                            const char *rule_dom = domains[d].domain;
                            const char *rep_dom = domains[d].replacement;
                            size_t rule_len = strlen(rule_dom);
                            size_t c_len = strlen(dom_val);

                            if (rule_dom[0] == '.') {
                                if (c_len >= rule_len && strcasecmp(dom_val + (c_len - rule_len), rule_dom) == 0) {
                                    size_t prefix_len = c_len - rule_len;
                                    snprintf(new_dom, sizeof(new_dom), "%.*s%s", (int)prefix_len, dom_val, rep_dom);
                                    dom_matched = true;
                                    break;
                                } else if (c_len + 1 == rule_len && strcasecmp(dom_val, rule_dom + 1) == 0) {
                                    snprintf(new_dom, sizeof(new_dom), "%s", rep_dom[0] == '.' ? rep_dom + 1 : rep_dom);
                                    dom_matched = true;
                                    break;
                                }
                            } else {
                                if (strcasecmp(dom_val, rule_dom) == 0) {
                                    snprintf(new_dom, sizeof(new_dom), "%s", rep_dom);
                                    dom_matched = true;
                                    break;
                                } else if (dom_val[0] == '.' && strcasecmp(dom_val + 1, rule_dom) == 0) {
                                    snprintf(new_dom, sizeof(new_dom), "%s%s", rep_dom[0] == '.' ? "" : ".", rep_dom);
                                    dom_matched = true;
                                    break;
                                }
                            }
                        }

                        if (dom_matched) {
                            modified = true;
                            int rw = snprintf(out_buf + written, out_capacity - written, "Domain=%s", new_dom);
                            if (rw < 0 || written + (size_t)rw >= out_capacity) return false;
                            written += (size_t)rw;
                        } else {
                            if (written + attr_len >= out_capacity) return false;
                            memcpy(out_buf + written, attr_start, attr_len);
                            written += attr_len;
                        }
                    } else if (strcasecmp(key_buf, "path") == 0 && path_count > 0) {
                        char path_val[APEX_CONFIG_PATH_MAX];
                        if (val_len < sizeof(path_val)) {
                            memcpy(path_val, val_start, val_len);
                            path_val[val_len] = '\0';
                        } else {
                            path_val[0] = '\0';
                        }

                        bool path_matched = false;
                        char new_path[APEX_CONFIG_PATH_MAX * 2];
                        new_path[0] = '\0';

                        for (size_t pidx = 0; pidx < path_count; pidx++) {
                            const char *rule_path = paths[pidx].path;
                            const char *rep_path = paths[pidx].replacement;
                            size_t rule_len = strlen(rule_path);

                            if (strncmp(path_val, rule_path, rule_len) == 0) {
                                snprintf(new_path, sizeof(new_path), "%s%s", rep_path, path_val + rule_len);
                                path_matched = true;
                                break;
                            }
                        }

                        if (path_matched) {
                            modified = true;
                            int rw = snprintf(out_buf + written, out_capacity - written, "Path=%s", new_path);
                            if (rw < 0 || written + (size_t)rw >= out_capacity) return false;
                            written += (size_t)rw;
                        } else {
                            if (written + attr_len >= out_capacity) return false;
                            memcpy(out_buf + written, attr_start, attr_len);
                            written += attr_len;
                        }
                    } else {
                        if (written + attr_len >= out_capacity) return false;
                        memcpy(out_buf + written, attr_start, attr_len);
                        written += attr_len;
                    }
                } else {
                    if (written + attr_len >= out_capacity) return false;
                    memcpy(out_buf + written, attr_start, attr_len);
                    written += attr_len;
                }
            }
        }

        if (semi != NULL) {
            p = semi + 1;
        } else {
            break;
        }
    }

    if (!modified) {
        return false;
    }

    *out_len = written;
    return true;
}

static const apex_sub_filter_config_t *router_get_sub_filter(const apex_server_config_t *server,
                                                             const apex_location_config_t *location,
                                                             const apex_http_config_t *http) {
    if (location != NULL && location->sub_filter.is_set) {
        return &location->sub_filter;
    }
    if (server != NULL && server->sub_filter.is_set) {
        return &server->sub_filter;
    }
    if (http != NULL && http->sub_filter.is_set) {
        return &http->sub_filter;
    }
    return NULL;
}

static bool router_apply_sub_filter(const apex_sub_filter_config_t *sub,
                                    const char *response_headers, size_t response_headers_len,
                                    int status,
                                    const void *in_body, size_t in_len,
                                    void **out_body, size_t *out_len) {
    if (sub == NULL || !sub->is_set || sub->rule_count == 0 || in_body == NULL || in_len == 0) {
        return false;
    }
    if (status == 204 || status == 304 || (status >= 100 && status < 200)) {
        return false;
    }

    const char *ct_val = NULL;
    size_t ct_len = 0;
    char ct_buf[128] = "text/html";
    if (response_headers != NULL && response_headers_len > 0) {
        if (router_find_header(response_headers, response_headers_len, "Content-Type", &ct_val, &ct_len)) {
            if (ct_len < sizeof(ct_buf)) {
                memcpy(ct_buf, ct_val, ct_len);
                ct_buf[ct_len] = '\0';
            }
        }
    }

    bool type_matches = false;
    if (sub->type_count == 0) {
        if (strncasecmp(ct_buf, "text/html", 9) == 0) {
            type_matches = true;
        }
    } else {
        for (size_t t = 0; t < sub->type_count; t++) {
            const char *expected = sub->types[t];
            if (strcmp(expected, "*") == 0) {
                type_matches = true;
                break;
            }
            if (strncasecmp(ct_buf, expected, strlen(expected)) == 0) {
                type_matches = true;
                break;
            }
        }
    }

    if (!type_matches) {
        return false;
    }

    const char *cur_data = (const char *)in_body;
    size_t cur_len = in_len;
    char *allocated_intermediate = NULL;

    for (size_t r = 0; r < sub->rule_count; r++) {
        const char *match = sub->rules[r].match;
        const char *repl = sub->rules[r].replacement;
        size_t match_len = strlen(match);
        size_t repl_len = strlen(repl);

        if (match_len == 0) continue;

        size_t match_count = 0;
        const char *scan = cur_data;
        const char *scan_end = cur_data + cur_len;
        while (scan <= scan_end - match_len) {
            if (memcmp(scan, match, match_len) == 0) {
                match_count++;
                if (sub->once) break;
                scan += match_len;
            } else {
                scan++;
            }
        }

        if (match_count == 0) continue;

        size_t new_len = cur_len + match_count * repl_len - match_count * match_len;
        char *new_buf = malloc(new_len ? new_len : 1u);
        if (new_buf == NULL) {
            free(allocated_intermediate);
            return false;
        }

        const char *src = cur_data;
        char *dst = new_buf;
        size_t replaced = 0;

        while (src <= scan_end - match_len) {
            if (memcmp(src, match, match_len) == 0 && (!sub->once || replaced == 0)) {
                if (repl_len > 0) {
                    memcpy(dst, repl, repl_len);
                    dst += repl_len;
                }
                src += match_len;
                replaced++;
            } else {
                *dst++ = *src++;
            }
        }
        while (src < scan_end) {
            *dst++ = *src++;
        }

        free(allocated_intermediate);
        allocated_intermediate = new_buf;
        cur_data = new_buf;
        cur_len = new_len;
    }

    if (allocated_intermediate == NULL) {
        return false;
    }

    *out_body = allocated_intermediate;
    *out_len = cur_len;
    return true;
}

static void router_write_proxy_response(conn_t *connection, const apex_runtime_t *runtime,
                                        const apex_server_config_t *server,
                                        const apex_location_config_t *location,
                                        const char *request, size_t request_length,
                                        const apex_proxy_response_t *response,
                                        bool head_request,
                                        const char *extra_headers, size_t extra_headers_len,
                                        apex_res_t *res) {
    const char *headers = response->headers;
    size_t headers_length = response->headers_len;
    int status = response->status;
    apex_record_status(status);

    const char *status_end = router_find_crlf(headers, headers_length);
    if (status_end == NULL) {
        router_send_error(connection, server, request, request_length, 502, "Bad Gateway", "upstream returned an invalid response\n");
        return;
    }

    bool no_body = status == 204 || status == 304 || (status >= 100 && status < 200);

    const apex_sub_filter_config_t *sub = router_get_sub_filter(server, location, runtime ? runtime->config ? &runtime->config->http : NULL : NULL);
    void *filtered_body = NULL;
    size_t filtered_body_len = 0;
    bool is_filtered = false;
    if (sub != NULL && !head_request && !no_body) {
        if (router_apply_sub_filter(sub, headers, headers_length, status,
                                    response->body, response->body_len,
                                    &filtered_body, &filtered_body_len)) {
            is_filtered = true;
        }
    }

    const void *active_body = is_filtered ? filtered_body : response->body;
    size_t active_body_len = is_filtered ? filtered_body_len : response->body_len;

    const apex_compress_config_t *compress = apex_config_get_compress(server, location, runtime ? runtime->config : NULL);
    void *compressed_body = NULL;
    size_t compressed_body_len = 0;
    apex_compress_algo_t comp_algo = APEX_COMPRESS_NONE;
    bool is_compressed = false;

    if (compress != NULL && !head_request && !no_body) {
        if (router_compress_response(compress, request, request_length,
                                     headers, headers_length,
                                     status, active_body, active_body_len,
                                     &compressed_body, &compressed_body_len, &comp_algo)) {
            is_compressed = true;
        }
    }

    const void *body_to_send = is_compressed ? compressed_body : active_body;
    size_t body_len_to_send = is_compressed ? compressed_body_len : active_body_len;

    apex_conn_write(connection, headers, (size_t)(status_end - headers));
    apex_conn_write(connection, "\r\n", 2u);

    bool no_content_length = true;
    bool seen_vary = false;

    const apex_cookie_domain_rule_t *cookie_domains = NULL;
    size_t cookie_domain_count = 0;
    const apex_cookie_path_rule_t *cookie_paths = NULL;
    size_t cookie_path_count = 0;
    router_get_cookie_rules(server, location, runtime ? runtime->config ? &runtime->config->http : NULL : NULL,
                            &cookie_domains, &cookie_domain_count,
                            &cookie_paths, &cookie_path_count);

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
        char rewritten_cookie[APEX_CONFIG_HOST_MAX * 4];
        size_t rewritten_cookie_len = 0;
        bool cookie_rewritten = false;

        if (colon != NULL) {
            size_t name_length = (size_t)(colon - line);
            while (name_length > 0 && (line[name_length - 1u] == ' ' || line[name_length - 1u] == '\t')) {
                name_length--;
            }
            if (router_header_name_equal(line, name_length, "Set-Cookie") &&
                (cookie_domain_count > 0 || cookie_path_count > 0)) {
                if (router_rewrite_cookie_line(line, line_length,
                                               cookie_domains, cookie_domain_count,
                                               cookie_paths, cookie_path_count,
                                               rewritten_cookie, sizeof(rewritten_cookie),
                                               &rewritten_cookie_len)) {
                    cookie_rewritten = true;
                }
            } else if (router_header_name_equal(line, name_length, "Server")) {
                skip = true;
            } else if (status != 101 && (router_header_name_equal(line, name_length, "Transfer-Encoding") ||
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
                if (!head_request || no_body || is_compressed || is_filtered) {
                    skip = true;
                }
            } else if (is_compressed && router_header_name_equal(line, name_length, "Content-Encoding")) {
                skip = true;
            } else if (router_header_name_equal(line, name_length, "Vary")) {
                seen_vary = true;
            }
        }

        if (!skip) {
            if (cookie_rewritten) {
                apex_conn_write(connection, rewritten_cookie, rewritten_cookie_len);
            } else {
                apex_conn_write(connection, line, line_length);
            }
            apex_conn_write(connection, "\r\n", 2u);
        }
        position += line_length + 2u;
    }

    char length_header[64];
    if (!head_request && !no_body) {
        int written = snprintf(length_header, sizeof(length_header), "Content-Length: %zu\r\n",
                               body_len_to_send);
        if (written > 0 && (size_t)written < sizeof(length_header)) {
            apex_conn_write(connection, length_header, (size_t)written);
        }
    } else if (head_request && no_content_length && !no_body) {
        apex_conn_write(connection, "Content-Length: 0\r\n", 19u);
    }

    if (is_compressed) {
        const char *algo_name = apex_compress_algo_name(comp_algo);
        char ce_hdr[64];
        int ce_written = snprintf(ce_hdr, sizeof(ce_hdr), "Content-Encoding: %s\r\n", algo_name);
        if (ce_written > 0) {
            apex_conn_write(connection, ce_hdr, (size_t)ce_written);
        }
        if (!seen_vary) {
            apex_conn_write(connection, "Vary: Accept-Encoding\r\n", 23);
        }
    }

    const apex_server_tokens_config_t *tokens = router_get_server_tokens(NULL, server);
    char server_hdr[160];
    size_t s_len = router_format_server_header(tokens, server_hdr, sizeof(server_hdr));
    if (s_len > 0) {
        apex_conn_write(connection, server_hdr, s_len);
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

    if (!head_request && !no_body && body_to_send != NULL && body_len_to_send > 0) {
        apex_conn_write(connection, body_to_send, body_len_to_send);
    }

    if (compressed_body != NULL) {
        free(compressed_body);
    }
    if (filtered_body != NULL) {
        free(filtered_body);
    }
    if (res != NULL && (is_compressed || is_filtered)) {
        res->last_body_bytes = body_len_to_send;
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
}

static void router_forward_request(const apex_runtime_t *runtime, apex_config_route_t *route,
                                   const char *request, size_t request_length,
                                   const char *method, size_t method_length, const char *target,
                                   size_t target_length, const char *body, size_t body_length, apex_res_t *res,
                                   const char *extra_headers, size_t extra_headers_len,
                                   const char *client_ip) {
    conn_t *connection = res->conn;
    const apex_server_config_t *server = route ? route->server : NULL;

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

    upstream_group_t dynamic_group;
    if (route->group == NULL) {
        if (route->location != NULL && route->location->proxy_pass_dynamic) {
            char raw_target[APEX_CONFIG_PATH_MAX];
            router_expand_string_ex(runtime, route->location->proxy_pass_raw, raw_target, sizeof(raw_target),
                                    host, strlen(host),
                                    target_text, strlen(target_text),
                                    client_ip, client_ip ? strlen(client_ip) : 0,
                                    "http", 4,
                                    NULL, 0, NULL, 0, NULL, 0,
                                    0, 0);
            if (raw_target[0] == '\0') {
                free(target_text);
                router_send_error(connection, server, request, request_length, 502, "Bad Gateway", "empty dynamic upstream target\n");
                return;
            }
            const char *target_ptr = raw_target;
            bool dyn_use_ssl = route->location->proxy_pass_ssl;
            uint16_t dyn_port = dyn_use_ssl ? 443 : 80;
            if (strncmp(target_ptr, "https://", 8) == 0) {
                dyn_use_ssl = true;
                dyn_port = 443;
                target_ptr += 8;
            } else if (strncmp(target_ptr, "http://", 7) == 0) {
                dyn_use_ssl = false;
                dyn_port = 80;
                target_ptr += 7;
            }
            char dyn_host[256];
            size_t host_idx = 0;
            while (*target_ptr != '\0' && *target_ptr != '/' && *target_ptr != ':' && host_idx + 1 < sizeof(dyn_host)) {
                dyn_host[host_idx++] = *target_ptr++;
            }
            dyn_host[host_idx] = '\0';
            if (*target_ptr == ':') {
                target_ptr++;
                dyn_port = (uint16_t)atoi(target_ptr);
            }
            if (dyn_host[0] == '\0') {
                free(target_text);
                router_send_error(connection, server, request, request_length, 502, "Bad Gateway", "invalid dynamic upstream host\n");
                return;
            }

            const upstream_group_t *matched_group = NULL;
            if (runtime != NULL && runtime->config != NULL) {
                for (size_t u = 0; u < runtime->config->upstream_count; u++) {
                    if (strcmp(runtime->config->upstreams[u].name, dyn_host) == 0) {
                        matched_group = apex_runtime_upstream(runtime, u);
                        break;
                    }
                }
            }

            if (matched_group != NULL) {
                route->group = matched_group;
            } else {
                memset(&dynamic_group, 0, sizeof(dynamic_group));
                apex_upstream_group_init(&dynamic_group);
                dynamic_group.policy = APEX_BALANCE_ROUND_ROBIN;
                dynamic_group.use_ssl = dyn_use_ssl;
                dynamic_group.use_ssl_sni = route->location->proxy_ssl_server_name;
                if (route->location->proxy_ssl_name[0] != '\0') {
                    router_expand_string_ex(runtime, route->location->proxy_ssl_name, dynamic_group.ssl_server_name,
                                            sizeof(dynamic_group.ssl_server_name),
                                            host, strlen(host),
                                            target_text, strlen(target_text),
                                            client_ip, client_ip ? strlen(client_ip) : 0,
                                            "http", 4,
                                            NULL, 0, NULL, 0, NULL, 0,
                                            0, 0);
                } else if (dynamic_group.use_ssl_sni) {
                    snprintf(dynamic_group.ssl_server_name, sizeof(dynamic_group.ssl_server_name), "%s", dyn_host);
                }

                const apex_resolver_config_t *res_cfg = (route->location != NULL && route->location->resolver.is_set)
                    ? &route->location->resolver
                    : (server != NULL && server->resolver.is_set ? &server->resolver : (runtime && runtime->config ? &runtime->config->http.resolver : NULL));
                if (apex_upstream_add_server_resolver(&dynamic_group, dyn_host, dyn_port, 1, false, false, res_cfg) != 0) {
                    free(target_text);
                    router_send_error(connection, server, request, request_length, 502, "Bad Gateway", "failed to resolve dynamic upstream host\n");
                    return;
                }
                dynamic_group.servers[0].use_ssl = dyn_use_ssl;
                if (dynamic_group.ssl_server_name[0] != '\0') {
                    snprintf(dynamic_group.servers[0].ssl_server_name, sizeof(dynamic_group.servers[0].ssl_server_name),
                             "%s", dynamic_group.ssl_server_name);
                }
                route->group = &dynamic_group;
            }
        } else {
            free(target_text);
            router_send_error(connection, server, request, request_length, 502, "Bad Gateway", "no upstream group for location\n");
            return;
        }
    }

    const char *cache_zone = (route->location != NULL && route->location->proxy_cache[0] != '\0')
        ? route->location->proxy_cache
        : (server != NULL ? server->proxy_cache : "");

    bool caching_enabled = (cache_zone[0] != '\0' && runtime != NULL && runtime->cache_manager != NULL);
    bool is_get = (method_length == 3 && memcmp(method, "GET", 3) == 0);
    bool is_head = (method_length == 4 && memcmp(method, "HEAD", 4) == 0);
    bool method_cacheable = (is_get || is_head);

    bool bypass = false;
    if (caching_enabled) {
        const char *bypass_cfg = (route->location != NULL && route->location->proxy_cache_bypass[0] != '\0')
            ? route->location->proxy_cache_bypass
            : (server != NULL ? server->proxy_cache_bypass : "");
        if (bypass_cfg[0] != '\0') {
            if (strstr(bypass_cfg, "$http_pragma") != NULL) {
                const char *prag = NULL; size_t prag_len = 0;
                if (router_find_header(request, request_length, "Pragma", &prag, &prag_len) &&
                    memmem(prag, prag_len, "no-cache", 8) != NULL) {
                    bypass = true;
                }
            }
            if (!bypass && strstr(bypass_cfg, "$http_authorization") != NULL) {
                const char *auth = NULL; size_t auth_len = 0;
                if (router_find_header(request, request_length, "Authorization", &auth, &auth_len)) {
                    bypass = true;
                }
            }
            if (!bypass && strstr(bypass_cfg, "$http_cache_control") != NULL) {
                const char *cc = NULL; size_t cc_len = 0;
                if (router_find_header(request, request_length, "Cache-Control", &cc, &cc_len) &&
                    memmem(cc, cc_len, "no-cache", 8) != NULL) {
                    bypass = true;
                }
            }
            if (!bypass && strstr(bypass_cfg, "$arg_nocache") != NULL) {
                if (memmem(target, target_length, "nocache=1", 9) != NULL ||
                    memmem(target, target_length, "nocache=true", 12) != NULL) {
                    bypass = true;
                }
            }
            if (!bypass && strstr(bypass_cfg, "$cookie_nocache") != NULL) {
                const char *ck = NULL; size_t ck_len = 0;
                if (router_find_header(request, request_length, "Cookie", &ck, &ck_len) &&
                    memmem(ck, ck_len, "nocache", 7) != NULL) {
                    bypass = true;
                }
            }
        }
    }

    char cache_key[256];
    if (caching_enabled && method_cacheable) {
        const char *scheme = (connection != NULL && connection->transport == APEX_TRANSPORT_TLS) ? "https" : "http";
        snprintf(cache_key, sizeof(cache_key), "%s:%s:%s:%s", scheme, method_text, host[0] ? host : "localhost", target_text);

        if (!bypass) {
            apex_cached_response_t cached = {0};
            if (apex_cache_lookup((apex_cache_manager_t *)runtime->cache_manager, cache_zone, cache_key, &cached)) {
                atomic_fetch_add_explicit(&g_apex_stats.cache_hits, 1, memory_order_relaxed);
                char add_hdr_buf[1024];
                size_t add_hdr_len = router_build_add_headers(runtime, server, route->location, cached.status,
                                                              host, strlen(host), target_text, strlen(target_text),
                                                              client_ip, client_ip ? strlen(client_ip) : 0,
                                                              "http", 4, 0, add_hdr_buf, sizeof(add_hdr_buf));
                char hit_extra[1024];
                snprintf(hit_extra, sizeof(hit_extra), "%sX-Cache: HIT\r\n%.*s",
                         extra_headers != NULL ? extra_headers : "",
                         (int)add_hdr_len, add_hdr_buf);
                apex_proxy_response_t cached_proxy_resp = {
                    .status = cached.status,
                    .headers = cached.headers,
                    .headers_len = cached.headers_len,
                    .body = cached.body,
                    .body_len = cached.body_len,
                    .upstream_fd = -1,
                };
                if (res != NULL) {
                    res->last_status = cached.status;
                    res->last_body_bytes = cached.body_len;
                    strncpy(res->last_upstream_addr, "cache", sizeof(res->last_upstream_addr) - 1);
                }
                router_write_proxy_response(connection, runtime, server, route ? route->location : NULL,
                                            request, request_length, &cached_proxy_resp,
                                            is_head, hit_extra, strlen(hit_extra), res);
                apex_cached_response_free(&cached);
                free(target_text);
                return;
            } else {
                atomic_fetch_add_explicit(&g_apex_stats.cache_misses, 1, memory_order_relaxed);
            }
        } else {
            atomic_fetch_add_explicit(&g_apex_stats.cache_bypasses, 1, memory_order_relaxed);
        }
    }

    char *headers = NULL;
    size_t headers_length = 0;
    if (!build_request_headers(request, request_length, route->location, connection, host,
                               target_text, target_length, client_ip, &headers, &headers_length)) {
        free(target_text);
        router_send_error(connection, server, request, request_length, 500, "Internal Server Error", "out of memory\n");
        return;
    }

    char fallback_ip[INET6_ADDRSTRLEN];
    const char *eff_ip = client_ip;
    if (eff_ip == NULL || eff_ip[0] == '\0') {
        if (!conn_get_peer_ip(connection, fallback_ip, sizeof(fallback_ip))) {
            strcpy(fallback_ip, "127.0.0.1");
        }
        eff_ip = fallback_ip;
    }

    uint32_t next_conditions = APEX_NEXT_UPSTREAM_DEFAULT;
    uint32_t next_tries = 0;
    uint64_t next_timeout_ms = 0;
    bool intercept_errors = false;

    if (route->location != NULL) {
        if (route->location->next_upstream.has_conditions) {
            next_conditions = route->location->next_upstream.conditions;
        }
        if (route->location->next_upstream.has_tries) {
            next_tries = route->location->next_upstream.tries;
        }
        if (route->location->next_upstream.has_timeout) {
            next_timeout_ms = route->location->next_upstream.timeout_ms;
        }
        if (route->location->has_proxy_intercept_errors) {
            intercept_errors = route->location->proxy_intercept_errors;
        }
    } else if (route->server != NULL) {
        if (route->server->next_upstream.has_conditions) {
            next_conditions = route->server->next_upstream.conditions;
        }
        if (route->server->next_upstream.has_tries) {
            next_tries = route->server->next_upstream.tries;
        }
        if (route->server->next_upstream.has_timeout) {
            next_timeout_ms = route->server->next_upstream.timeout_ms;
        }
        if (route->server->has_proxy_intercept_errors) {
            intercept_errors = route->server->proxy_intercept_errors;
        }
    }

    apex_proxy_request_t proxy_request = {
        .method = method_text,
        .target = target_text,
        .host = host[0] != '\0' ? host : NULL,
        .client_ip = eff_ip,
        .headers = headers,
        .headers_len = headers_length,
        .body = body,
        .body_len = body_length,
        .keep_alive = connection->close_after_write == 0,
        .use_ssl = (route->group != NULL && route->group->use_ssl),
        .next_upstream_conditions = next_conditions,
        .next_upstream_tries = next_tries,
        .next_upstream_timeout_ms = next_timeout_ms,
    };
    char ssl_sni_buf[128] = {0};
    if (route->location != NULL && route->location->proxy_ssl_name[0] != '\0') {
        router_expand_string_ex(runtime, route->location->proxy_ssl_name, ssl_sni_buf,
                                sizeof(ssl_sni_buf),
                                host, strlen(host), target_text, strlen(target_text),
                                client_ip, client_ip ? strlen(client_ip) : 0, "http", 4,
                                NULL, 0, NULL, 0, NULL, 0, 0, 0);
    } else if (route->group != NULL && route->group->ssl_server_name[0] != '\0') {
        snprintf(ssl_sni_buf, sizeof(ssl_sni_buf), "%s", route->group->ssl_server_name);
    } else if ((route->location != NULL && route->location->proxy_ssl_server_name) ||
               (route->group != NULL && route->group->use_ssl_sni)) {
        snprintf(ssl_sni_buf, sizeof(ssl_sni_buf), "%s", host[0] ? host : "");
    }
    if (ssl_sni_buf[0] != '\0') {
        proxy_request.ssl_server_name = ssl_sni_buf;
    }

    apex_proxy_response_t proxy_response;
    int result = apex_proxy_forward((upstream_group_t *)(uintptr_t)route->group, &proxy_request, &proxy_response);

    free(headers);

    if (result != APEX_PROXY_OK) {
        int status = result == APEX_PROXY_ERR_TIMEOUT ? 504 : 502;
        const char *reason = status == 504 ? "Gateway Timeout" : "Bad Gateway";
        char message[160];
        snprintf(message, sizeof(message), "upstream error: %s\n", apex_proxy_strerror(result));
        if (!router_send_custom_error_page(connection, server, route->location, status, reason, NULL, 0)) {
            router_send_error(connection, server, request, request_length, status, reason, message);
        }
        free(target_text);
        return;
    }

    if (intercept_errors && proxy_response.status >= 300) {
        const char *title = NULL;
        const char *desc = NULL;
        router_error_details(proxy_response.status, NULL, &title, &desc);
        const char *reason = title ? title : "Error";
        if (router_send_custom_error_page(connection, server, route->location,
                                          proxy_response.status, reason,
                                          extra_headers, extra_headers_len)) {
            if (res != NULL) {
                res->last_status = proxy_response.status;
                res->last_body_bytes = 0;
                res->last_upstream_status = proxy_response.status;
                res->last_upstream_time_us = proxy_response.elapsed_us;
                if (route->group != NULL && proxy_response.server_index < route->group->server_count) {
                    snprintf(res->last_upstream_addr, sizeof(res->last_upstream_addr), "%s:%u",
                             route->group->servers[proxy_response.server_index].ip,
                             (unsigned)route->group->servers[proxy_response.server_index].port);
                }
            }
            apex_proxy_response_free(&proxy_response);
            free(target_text);
            return;
        }
    }

    if (res != NULL) {
        res->last_status = proxy_response.status;
        res->last_body_bytes = proxy_response.body_len;
        res->last_upstream_status = proxy_response.status;
        res->last_upstream_time_us = proxy_response.elapsed_us;
        if (route->group != NULL && proxy_response.server_index < route->group->server_count) {
            snprintf(res->last_upstream_addr, sizeof(res->last_upstream_addr), "%s:%u",
                     route->group->servers[proxy_response.server_index].ip,
                     (unsigned)route->group->servers[proxy_response.server_index].port);
        }
    }

    char add_headers_buf[1024];
    size_t add_headers_len = router_build_add_headers(runtime, server, route->location,
                                                      proxy_response.status,
                                                      host, strlen(host),
                                                      target_text, strlen(target_text),
                                                      client_ip, client_ip ? strlen(client_ip) : 0,
                                                      "http", 4,
                                                      proxy_response.elapsed_us,
                                                      add_headers_buf, sizeof(add_headers_buf));

    char combined_extra[1024];
    if (caching_enabled) {
        const char *status_str = bypass ? "BYPASS" : "MISS";
        snprintf(combined_extra, sizeof(combined_extra), "%sX-Cache: %s\r\n%.*s",
                 extra_headers != NULL ? extra_headers : "", status_str,
                 (int)add_headers_len, add_headers_buf);
    } else if ((extra_headers != NULL && extra_headers_len > 0) || add_headers_len > 0) {
        snprintf(combined_extra, sizeof(combined_extra), "%s%.*s",
                 extra_headers != NULL ? extra_headers : "",
                 (int)add_headers_len, add_headers_buf);
    } else {
        combined_extra[0] = '\0';
    }

    if (caching_enabled && !bypass && method_cacheable) {
        const apex_cache_valid_rule_t *rules = route->location->cache_valid_rules;
        size_t rule_count = route->location->cache_valid_rule_count;
        if (rule_count == 0 && server != NULL) {
            rules = server->cache_valid_rules;
            rule_count = server->cache_valid_rule_count;
        }
        uint64_t valid_ms = apex_cache_evaluate_validity(proxy_response.headers, proxy_response.headers_len,
                                                         proxy_response.status, rules, rule_count);
        if (valid_ms > 0) {
            apex_cache_store((apex_cache_manager_t *)runtime->cache_manager, cache_zone, cache_key,
                             proxy_response.status, proxy_response.headers, proxy_response.headers_len,
                             proxy_response.body, proxy_response.body_len, valid_ms);
        }
    }

    router_write_proxy_response(connection, runtime, server, route ? route->location : NULL,
                                request, request_length, &proxy_response,
                                strcasecmp(method_text, "HEAD") == 0, combined_extra, strlen(combined_extra), res);

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

    free(target_text);
    apex_proxy_response_free(&proxy_response);
}

static void router_forward_fastcgi(const apex_runtime_t *runtime, apex_config_route_t *route,
                                   const char *request, size_t request_length,
                                   const char *method, size_t method_length,
                                   const char *path, size_t path_length,
                                   const char *body, size_t body_length,
                                   apex_res_t *res,
                                   const char *extra_headers, size_t extra_headers_len,
                                   const char *client_ip) {
    (void)runtime;
    conn_t *connection = res->conn;
    const apex_server_config_t *server = route ? route->server : NULL;
    const apex_location_config_t *location = route ? route->location : NULL;

    if (location == NULL || location->fastcgi_pass[0] == '\0') {
        router_send_error(connection, server, request, request_length, 502, "Bad Gateway", "fastcgi_pass not configured\n");
        return;
    }

    char host[256];
    host[0] = '\0';
    const char *host_value = NULL;
    size_t host_length = 0;
    if (router_find_header(request, request_length, "Host", &host_value, &host_length)) {
        if (host_length < sizeof(host)) {
            memcpy(host, host_value, host_length);
            host[host_length] = '\0';
        }
    }

    char path_buf[APEX_CONFIG_PATH_MAX];
    char query_buf[APEX_CONFIG_PATH_MAX];
    path_buf[0] = '\0';
    query_buf[0] = '\0';

    const char *qmark = memchr(path, '?', path_length);
    if (qmark != NULL) {
        size_t plen = (size_t)(qmark - path);
        if (plen >= sizeof(path_buf)) plen = sizeof(path_buf) - 1;
        memcpy(path_buf, path, plen);
        path_buf[plen] = '\0';

        size_t qlen = path_length - plen - 1;
        if (qlen >= sizeof(query_buf)) qlen = sizeof(query_buf) - 1;
        memcpy(query_buf, qmark + 1, qlen);
        query_buf[qlen] = '\0';
    } else {
        size_t plen = path_length < sizeof(path_buf) ? path_length : sizeof(path_buf) - 1;
        memcpy(path_buf, path, plen);
        path_buf[plen] = '\0';
    }

    char script_filename[APEX_CONFIG_PATH_MAX * 2];
    const char *doc_root = (location && location->root) ? location->root : "";
    if (path_buf[0] == '/' && path_buf[1] == '\0' && location->fastcgi_index[0] != '\0') {
        snprintf(script_filename, sizeof(script_filename), "%s/%s", doc_root, location->fastcgi_index);
    } else {
        snprintf(script_filename, sizeof(script_filename), "%s%s", doc_root, path_buf);
    }

    char method_buf[16];
    size_t mlen = method_length < sizeof(method_buf) ? method_length : sizeof(method_buf) - 1;
    memcpy(method_buf, method, mlen);
    method_buf[mlen] = '\0';

    apex_fastcgi_request_t fcgi_req = {
        .target = location->fastcgi_pass,
        .method = method_buf,
        .uri = path_buf,
        .script_filename = script_filename,
        .script_name = path_buf,
        .query_string = query_buf,
        .document_root = doc_root,
        .client_ip = client_ip,
        .client_port = 0,
        .server_addr = server ? server->listen_host : "127.0.0.1",
        .server_port = server ? server->listen_port : 80,
        .server_name = host[0] ? host : "localhost",
        .raw_request = request,
        .raw_request_len = request_length,
        .body = body,
        .body_len = body_length,
        .connect_timeout_ms = location->has_connect_timeout ? location->connect_timeout_ms : 5000,
        .read_timeout_ms = location->has_read_timeout ? location->read_timeout_ms : 30000,
    };

    apex_fastcgi_response_t fcgi_resp;
    int rc = apex_fastcgi_forward(&fcgi_req, &fcgi_resp);
    if (rc != 0) {
        router_send_error(connection, server, request, request_length, 502, "Bad Gateway", "FastCGI backend connection failed\n");
        return;
    }

    if (res != NULL) {
        res->last_status = fcgi_resp.status;
        res->last_body_bytes = fcgi_resp.body_len;
        res->last_upstream_status = fcgi_resp.status;
        res->last_upstream_time_us = fcgi_resp.elapsed_us;
        snprintf(res->last_upstream_addr, sizeof(res->last_upstream_addr), "%s", location->fastcgi_pass);
    }

    const apex_compress_config_t *compress = apex_config_get_compress(server, location, runtime ? runtime->config : NULL);
    void *compressed_body = NULL;
    size_t compressed_body_len = 0;
    apex_compress_algo_t comp_algo = APEX_COMPRESS_NONE;
    bool is_compressed = false;
    bool is_head = strcasecmp(method_buf, "HEAD") == 0;

    if (compress != NULL && !is_head && fcgi_resp.body != NULL && fcgi_resp.body_len > 0) {
        if (router_compress_response(compress, request, request_length,
                                     fcgi_resp.headers, fcgi_resp.headers_len,
                                     fcgi_resp.status, fcgi_resp.body, fcgi_resp.body_len,
                                     &compressed_body, &compressed_body_len, &comp_algo)) {
            is_compressed = true;
        }
    }

    const void *body_to_send = is_compressed ? compressed_body : fcgi_resp.body;
    size_t body_len_to_send = is_compressed ? compressed_body_len : fcgi_resp.body_len;

    char status_line[128];
    int slen = snprintf(status_line, sizeof(status_line), "HTTP/1.1 %d %s\r\n",
                        fcgi_resp.status, fcgi_resp.status_text[0] ? fcgi_resp.status_text : "OK");
    if (slen > 0) apex_conn_write(connection, status_line, (size_t)slen);

    const apex_server_tokens_config_t *tokens = router_get_server_tokens(runtime, server);
    char server_hdr[160];
    size_t s_len = router_format_server_header(tokens, server_hdr, sizeof(server_hdr));
    if (s_len > 0) apex_conn_write(connection, server_hdr, s_len);

    char conn_hdr[64];
    int chlen = snprintf(conn_hdr, sizeof(conn_hdr), "Connection: %s\r\n",
                         connection->close_after_write ? "close" : "keep-alive");
    if (chlen > 0) apex_conn_write(connection, conn_hdr, (size_t)chlen);

    char clen_hdr[64];
    int clen = snprintf(clen_hdr, sizeof(clen_hdr), "Content-Length: %zu\r\n", body_len_to_send);
    if (clen > 0) apex_conn_write(connection, clen_hdr, (size_t)clen);

    if (is_compressed) {
        const char *algo_name = apex_compress_algo_name(comp_algo);
        char ce_hdr[64];
        int ce_written = snprintf(ce_hdr, sizeof(ce_hdr), "Content-Encoding: %s\r\n", algo_name);
        if (ce_written > 0) apex_conn_write(connection, ce_hdr, (size_t)ce_written);
        apex_conn_write(connection, "Vary: Accept-Encoding\r\n", 23);
    }

    if (extra_headers != NULL && extra_headers_len > 0) {
        apex_conn_write(connection, extra_headers, extra_headers_len);
    }

    char add_headers_buf[1024];
    size_t add_headers_len = router_build_add_headers(runtime, server, location,
                                                      fcgi_resp.status,
                                                      host, strlen(host),
                                                      path, path_length,
                                                      client_ip, client_ip ? strlen(client_ip) : 0,
                                                      "http", 4,
                                                      fcgi_resp.elapsed_us,
                                                      add_headers_buf, sizeof(add_headers_buf));
    if (add_headers_len > 0) {
        apex_conn_write(connection, add_headers_buf, add_headers_len);
    }

    if (fcgi_resp.headers != NULL && fcgi_resp.headers_len > 0) {
        apex_conn_write(connection, fcgi_resp.headers, fcgi_resp.headers_len);
    }

    apex_conn_write(connection, "\r\n", 2);

    if (!is_head && body_to_send != NULL && body_len_to_send > 0) {
        apex_conn_write(connection, body_to_send, body_len_to_send);
    }

    if (compressed_body != NULL) {
        free(compressed_body);
    }
    if (res != NULL && is_compressed) {
        res->last_body_bytes = body_len_to_send;
    }

    apex_record_status(fcgi_resp.status);
    apex_fastcgi_response_free(&fcgi_resp);
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
    apex_record_status(status);

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

static void router_trigger_logging(apex_pipeline_ctx_t *ctx, int fallback_status, size_t fallback_bytes,
                                   const char *client_ip) {
    if (ctx == NULL) return;

    int status = fallback_status;
    size_t body_bytes = fallback_bytes;
    const char *upstream_addr = NULL;
    int upstream_status = 0;
    uint64_t upstream_time_us = 0;

    if (ctx->res != NULL) {
        if (ctx->res->last_status > 0) {
            status = ctx->res->last_status;
            body_bytes = ctx->res->last_body_bytes;
        }
        if (ctx->res->last_upstream_addr[0] != '\0') {
            upstream_addr = ctx->res->last_upstream_addr;
        }
        upstream_status = ctx->res->last_upstream_status;
        upstream_time_us = ctx->res->last_upstream_time_us;
    }

    ctx->status_code = status;
    apex_pipeline_run_phase(ctx, APEX_PHASE_LOGGING);

    if (ctx->runtime != NULL && ctx->runtime->log_manager != NULL) {
        uint64_t now_us = 0;
        struct timeval tv;
        if (gettimeofday(&tv, NULL) == 0) {
            now_us = (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
        }

        const char *effective_ip = (client_ip && client_ip[0]) ? client_ip : "127.0.0.1";

        apex_log_ctx_t log_ctx = {
            .client_ip = effective_ip,
            .method = ctx->method,
            .method_len = ctx->method_len,
            .uri = ctx->path,
            .uri_len = ctx->path_len,
            .protocol = (ctx->conn != NULL && ctx->conn->transport == APEX_TRANSPORT_TLS) ? "HTTP/1.1" : "HTTP/1.1",
            .raw_request = ctx->raw_request,
            .raw_request_len = ctx->raw_request_len,
            .status = status,
            .bytes_sent = body_bytes + 150,
            .body_bytes_sent = body_bytes,
            .start_time_us = ctx->start_time_us ? ctx->start_time_us : now_us,
            .end_time_us = now_us,
            .upstream_addr = upstream_addr,
            .upstream_status = upstream_status,
            .upstream_time_us = upstream_time_us,
            .request_id = ctx->request_id,
        };

        apex_access_log_write((apex_runtime_t *)ctx->runtime, ctx->location, ctx->server, &log_ctx);
    }
}

static bool json_find_string(const char *json, size_t json_len, const char *key, char *out, size_t out_cap) {
    if (json == NULL || key == NULL || out == NULL || out_cap == 0) return false;
    char search_pattern[128];
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\"", key);
    const char *found = memmem(json, json_len, search_pattern, strlen(search_pattern));
    if (found == NULL) return false;
    const char *colon = memchr(found + strlen(search_pattern), ':', json_len - (size_t)(found + strlen(search_pattern) - json));
    if (colon == NULL) return false;
    const char *p = colon + 1;
    while (p < json + json_len && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    if (p >= json + json_len || *p != '"') return false;
    p++;
    const char *val_start = p;
    while (p < json + json_len && *p != '"') p++;
    if (p >= json + json_len) return false;
    size_t val_len = (size_t)(p - val_start);
    if (val_len >= out_cap) val_len = out_cap - 1;
    memcpy(out, val_start, val_len);
    out[val_len] = '\0';
    return true;
}

static void append_json(char *buf, size_t buf_size, size_t *offset, const char *fmt, ...) {
    if (buf == NULL || buf_size == 0 || *offset >= buf_size - 1) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(buf + *offset, buf_size - *offset, fmt, args);
    va_end(args);
    if (written > 0) {
        size_t n = (size_t)written;
        if (n >= buf_size - *offset) {
            *offset = buf_size - 1;
            buf[buf_size - 1] = '\0';
        } else {
            *offset += n;
        }
    }
}

static bool json_find_int(const char *json, size_t json_len, const char *key, int *out) {
    if (json == NULL || key == NULL || out == NULL) return false;
    char search_pattern[128];
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\"", key);
    const char *found = memmem(json, json_len, search_pattern, strlen(search_pattern));
    if (found == NULL) return false;
    const char *after = found + strlen(search_pattern);
    const char *colon = memchr(after, ':', json_len - (size_t)(after - json));
    if (colon == NULL) return false;
    const char *p = colon + 1;
    while (p < json + json_len && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    if (p >= json + json_len) return false;
    char num_buf[32];
    size_t num_len = 0;
    if (*p == '-' || *p == '+') {
        num_buf[num_len++] = *p++;
    }
    while (p < json + json_len && *p >= '0' && *p <= '9' && num_len + 1 < sizeof(num_buf)) {
        num_buf[num_len++] = *p++;
    }
    if (num_len == 0 || (num_len == 1 && (num_buf[0] == '-' || num_buf[0] == '+'))) {
        return false;
    }
    num_buf[num_len] = '\0';
    *out = atoi(num_buf);
    return true;
}

static int b64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static bool base64_decode(const char *in, size_t in_len, char *out, size_t out_cap, size_t *out_len) {
    if (in == NULL || out == NULL || out_cap == 0) return false;
    size_t i = 0, o = 0;
    while (i < in_len) {
        while (i < in_len && (in[i] == ' ' || in[i] == '\t' || in[i] == '\r' || in[i] == '\n')) i++;
        if (i >= in_len || in[i] == '=') break;

        int b0 = b64_char_value(in[i++]);
        if (b0 < 0 || i >= in_len) return false;
        int b1 = b64_char_value(in[i++]);
        if (b1 < 0) return false;

        int b2 = -1;
        if (i < in_len && in[i] != '=') {
            b2 = b64_char_value(in[i++]);
            if (b2 < 0) return false;
        } else if (i < in_len && in[i] == '=') {
            i++;
        }

        int b3 = -1;
        if (i < in_len && in[i] != '=') {
            b3 = b64_char_value(in[i++]);
            if (b3 < 0) return false;
        } else if (i < in_len && in[i] == '=') {
            i++;
        }

        if (o >= out_cap) return false;
        out[o++] = (char)((b0 << 2) | (b1 >> 4));
        if (b2 >= 0) {
            if (o >= out_cap) return false;
            out[o++] = (char)(((b1 & 0xF) << 4) | (b2 >> 2));
        }
        if (b3 >= 0) {
            if (o >= out_cap) return false;
            out[o++] = (char)(((b2 & 0x3) << 6) | b3);
        }
    }
    if (o >= out_cap) return false;
    out[o] = '\0';
    if (out_len != NULL) *out_len = o;
    return true;
}

static bool router_check_auth_basic(const char *req_buf, size_t req_buf_len, const apex_auth_basic_config_t *ab) {
    if (ab == NULL || !ab->enabled) return true;
    if (ab->user_file[0] == '\0') return true;

    const char *auth_hdr = NULL;
    size_t auth_hdr_len = 0;
    if (!router_find_header(req_buf, req_buf_len, "Authorization", &auth_hdr, &auth_hdr_len)) {
        return false;
    }
    while (auth_hdr_len > 0 && (*auth_hdr == ' ' || *auth_hdr == '\t')) {
        auth_hdr++;
        auth_hdr_len--;
    }
    if (auth_hdr_len < 6 || strncasecmp(auth_hdr, "Basic ", 6) != 0) {
        return false;
    }
    const char *b64_str = auth_hdr + 6;
    size_t b64_len = auth_hdr_len - 6;
    while (b64_len > 0 && (*b64_str == ' ' || *b64_str == '\t')) {
        b64_str++;
        b64_len--;
    }
    while (b64_len > 0 && (b64_str[b64_len - 1] == ' ' || b64_str[b64_len - 1] == '\t' ||
                          b64_str[b64_len - 1] == '\r' || b64_str[b64_len - 1] == '\n')) {
        b64_len--;
    }

    char decoded[256];
    size_t decoded_len = 0;
    if (!base64_decode(b64_str, b64_len, decoded, sizeof(decoded), &decoded_len)) {
        return false;
    }

    char *colon = strchr(decoded, ':');
    if (colon == NULL) return false;
    *colon = '\0';
    const char *req_user = decoded;
    const char *req_pass = colon + 1;

    FILE *f = fopen(ab->user_file, "r");
    if (f == NULL) return false;

    char line[512];
    bool matched = false;
    while (fgets(line, sizeof(line), f) != NULL) {
        char *nl = strchr(line, '\n');
        if (nl != NULL) *nl = '\0';
        char *cr = strchr(line, '\r');
        if (cr != NULL) *cr = '\0';
        if (line[0] == '#' || line[0] == '\0') continue;

        char *fcolon = strchr(line, ':');
        if (fcolon == NULL) continue;
        *fcolon = '\0';
        const char *fuser = line;
        const char *fpass = fcolon + 1;

        if (strcmp(req_user, fuser) == 0) {
            if (strcmp(req_pass, fpass) == 0) {
                matched = true;
                break;
            }
        }
    }
    fclose(f);
    return matched;
}

static bool json_find_bool(const char *json, size_t json_len, const char *key, bool *out) {
    if (json == NULL || key == NULL || out == NULL) return false;
    char search_pattern[128];
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\"", key);
    const char *found = memmem(json, json_len, search_pattern, strlen(search_pattern));
    if (found == NULL) return false;
    const char *colon = memchr(found + strlen(search_pattern), ':', json_len - (size_t)(found + strlen(search_pattern) - json));
    if (colon == NULL) return false;
    const char *p = colon + 1;
    while (p < json + json_len && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    if (p + 4 <= json + json_len && strncmp(p, "true", 4) == 0) {
        *out = true;
        return true;
    }
    if (p + 5 <= json + json_len && strncmp(p, "false", 5) == 0) {
        *out = false;
        return true;
    }
    return false;
}

static void router_handle_api_request(conn_t *connection, const apex_runtime_t *runtime,
                                      const apex_server_config_t *server,
                                      const apex_location_config_t *location,
                                      const char *req_buf, size_t req_buf_len,
                                      const char *method, size_t method_len,
                                      const char *path, size_t path_len,
                                      const char *body, size_t body_len,
                                      apex_res_t *res,
                                      const char *extra_headers, size_t extra_headers_len,
                                      const char *client_ip) {
    (void)client_ip;
    (void)extra_headers;
    (void)extra_headers_len;

    if (connection == NULL || runtime == NULL || runtime->config == NULL) {
        return;
    }

    char meth[16];
    if (method_len >= sizeof(meth)) method_len = sizeof(meth) - 1;
    memcpy(meth, method, method_len);
    meth[method_len] = '\0';

    char req_path[APEX_CONFIG_PATH_MAX];
    if (path_len >= sizeof(req_path)) path_len = sizeof(req_path) - 1;
    memcpy(req_path, path, path_len);
    req_path[path_len] = '\0';
    char *q = strchr(req_path, '?');
    if (q != NULL) *q = '\0';

    char body_buf[16384];
    body_buf[0] = '\0';
    int status_code = 200;
    const char *reason = "OK";
    size_t resp_len = 0;

    /* 1. API Authentication & Token Protection */
    if (location != NULL && location->api.secret_set) {
        bool authorized = false;
        const char *expected = location->api.secret;
        size_t exp_len = strlen(expected);

        /* Check Authorization: Bearer <token> */
        const char *auth_hdr = NULL;
        size_t auth_hdr_len = 0;
        if (router_find_header(req_buf, req_buf_len, "Authorization", &auth_hdr, &auth_hdr_len)) {
            while (auth_hdr_len > 0 && (*auth_hdr == ' ' || *auth_hdr == '\t')) {
                auth_hdr++;
                auth_hdr_len--;
            }
            if (auth_hdr_len >= 7 && strncasecmp(auth_hdr, "Bearer ", 7) == 0) {
                const char *tok = auth_hdr + 7;
                size_t tok_len = auth_hdr_len - 7;
                while (tok_len > 0 && (*tok == ' ' || *tok == '\t')) {
                    tok++;
                    tok_len--;
                }
                while (tok_len > 0 && (tok[tok_len - 1] == ' ' || tok[tok_len - 1] == '\t')) {
                    tok_len--;
                }
                if (tok_len == exp_len && memcmp(tok, expected, exp_len) == 0) {
                    authorized = true;
                }
            }
        }

        /* Check X-API-Key: <token> */
        if (!authorized) {
            const char *key_hdr = NULL;
            size_t key_hdr_len = 0;
            if (router_find_header(req_buf, req_buf_len, "X-API-Key", &key_hdr, &key_hdr_len)) {
                while (key_hdr_len > 0 && (*key_hdr == ' ' || *key_hdr == '\t')) {
                    key_hdr++;
                    key_hdr_len--;
                }
                while (key_hdr_len > 0 && (key_hdr[key_hdr_len - 1] == ' ' || key_hdr[key_hdr_len - 1] == '\t')) {
                    key_hdr_len--;
                }
                if (key_hdr_len == exp_len && memcmp(key_hdr, expected, exp_len) == 0) {
                    authorized = true;
                }
            }
        }

        /* Check Query Param: ?api_key=<token> or ?secret=<token> */
        if (!authorized && path != NULL) {
            const char *qmark = memchr(path, '?', path_len);
            if (qmark != NULL) {
                const char *qp = qmark + 1;
                size_t qlen = path_len - (size_t)(qp - path);
                const char *p = qp;
                while (p < qp + qlen) {
                    bool match = false;
                    size_t klen = 0;
                    if ((size_t)(qp + qlen - p) >= 8 && memcmp(p, "api_key=", 8) == 0) {
                        match = true;
                        klen = 8;
                    } else if ((size_t)(qp + qlen - p) >= 7 && memcmp(p, "secret=", 7) == 0) {
                        match = true;
                        klen = 7;
                    }
                    if (match) {
                        const char *vstart = p + klen;
                        const char *vend = vstart;
                        while (vend < qp + qlen && *vend != '&' && *vend != '#') {
                            vend++;
                        }
                        size_t vlen = (size_t)(vend - vstart);
                        if (vlen == exp_len && memcmp(vstart, expected, exp_len) == 0) {
                            authorized = true;
                            break;
                        }
                    }
                    while (p < qp + qlen && *p != '&') p++;
                    if (p < qp + qlen && *p == '&') p++;
                }
            }
        }

        if (!authorized) {
            const apex_server_tokens_config_t *tokens = router_get_server_tokens(runtime, server);
            char server_hdr[128];
            router_format_server_header(tokens, server_hdr, sizeof(server_hdr));
            const char *unauth_body = "{\"error\":\"unauthorized: invalid or missing API key\"}\n";
            size_t unauth_len = strlen(unauth_body);
            char header[512];
            int written = snprintf(header, sizeof(header),
                                   "HTTP/1.1 401 Unauthorized\r\n"
                                   "%s"
                                   "WWW-Authenticate: Bearer realm=\"apex-api\"\r\n"
                                   "Content-Type: application/json\r\n"
                                   "Content-Length: %zu\r\n"
                                   "Connection: %s\r\n\r\n",
                                   server_hdr, unauth_len,
                                   connection->close_after_write ? "close" : "keep-alive");
            if (written > 0 && (size_t)written < sizeof(header)) {
                apex_conn_write(connection, header, (size_t)written);
                if (method_len != 4 || memcmp(method, "HEAD", 4) != 0) {
                    apex_conn_write(connection, unauth_body, unauth_len);
                }
            }
            if (res != NULL) {
                res->last_status = 401;
                res->last_body_bytes = unauth_len;
            }
            apex_record_status(401);
            return;
        }
    }

    const char *rel = NULL;
    if (location != NULL && location->path[0] != '\0' &&
        strncmp(req_path, location->path, strlen(location->path)) == 0) {
        rel = req_path + strlen(location->path);
        while (*rel == '/') rel++;
    }

    const char *sub = NULL;
    bool is_root_discovery = false;

    if (rel != NULL && *rel == '\0') {
        is_root_discovery = true;
    } else if (strcmp(req_path, "/api") == 0 || strcmp(req_path, "/api/") == 0) {
        is_root_discovery = true;
    } else if (rel != NULL && strncmp(rel, "http/upstreams", 14) == 0) {
        sub = rel + 14;
    } else if (strncmp(req_path, "/api/http/upstreams", 19) == 0) {
        sub = req_path + 19;
    }

    if (is_root_discovery) {
        append_json(body_buf, sizeof(body_buf), &resp_len,
                    "{\"version\":\"1.0\",\"http\":{\"upstreams\":\"/api/http/upstreams\"}}\n");
    } else if (sub != NULL) {
        if (*sub == '/') sub++;

        if (*sub == '\0') {
            if (strcmp(meth, "GET") != 0 && strcmp(meth, "HEAD") != 0) {
                status_code = 405;
                reason = "Method Not Allowed";
                append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"Method Not Allowed\"}\n");
            } else {
                append_json(body_buf, sizeof(body_buf), &resp_len, "{");
                for (size_t u = 0; u < runtime->config->upstream_count; u++) {
                    const char *uname = runtime->config->upstreams[u].name;
                    upstream_group_t *grp = (upstream_group_t *)&runtime->groups[u];
                    pthread_rwlock_rdlock(&grp->lock);
                    append_json(body_buf, sizeof(body_buf), &resp_len,
                                "%s\"%s\":{\"servers\":[", u > 0 ? "," : "", uname);
                    for (size_t s = 0; s < grp->server_count; s++) {
                        const upstream_server_t *srv = &grp->servers[s];
                        int64_t act = atomic_load_explicit(&srv->active_conns, memory_order_relaxed);
                        uint64_t reqs = atomic_load_explicit(&srv->total_requests, memory_order_relaxed);
                        uint64_t fails = atomic_load_explicit(&srv->failed_requests, memory_order_relaxed);
                        append_json(body_buf, sizeof(body_buf), &resp_len,
                            "%s{\"server\":\"%s:%u\",\"weight\":%u,\"down\":%s,\"backup\":%s,\"active\":%lld,\"requests\":%llu,\"fails\":%llu}",
                            s > 0 ? "," : "", srv->ip, (unsigned int)srv->port,
                            (unsigned int)srv->weight, srv->is_down ? "true" : "false",
                            srv->is_backup ? "true" : "false", (long long)act,
                            (unsigned long long)reqs, (unsigned long long)fails);
                    }
                    append_json(body_buf, sizeof(body_buf), &resp_len, "]}");
                    pthread_rwlock_unlock(&grp->lock);
                }
                append_json(body_buf, sizeof(body_buf), &resp_len, "}\n");
            }
        } else {
            char group_name[128];
            size_t g_idx = 0;
            const char *p = sub;
            while (*p != '\0' && *p != '/' && g_idx + 1 < sizeof(group_name)) {
                group_name[g_idx++] = *p++;
            }
            group_name[g_idx] = '\0';

            upstream_group_t *matched_group = NULL;
            for (size_t u = 0; u < runtime->config->upstream_count; u++) {
                if (strcmp(runtime->config->upstreams[u].name, group_name) == 0) {
                    matched_group = (upstream_group_t *)&runtime->groups[u];
                    break;
                }
            }

            if (matched_group == NULL) {
                status_code = 404;
                reason = "Not Found";
                append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"upstream group not found\"}\n");
            } else if (*p == '\0' || strcmp(p, "/") == 0) {
                if (strcmp(meth, "GET") != 0 && strcmp(meth, "HEAD") != 0) {
                    status_code = 405;
                    reason = "Method Not Allowed";
                    append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"Method Not Allowed\"}\n");
                } else {
                    pthread_rwlock_rdlock(&matched_group->lock);
                    append_json(body_buf, sizeof(body_buf), &resp_len, "{\"servers\":[");
                    for (size_t s = 0; s < matched_group->server_count; s++) {
                        const upstream_server_t *srv = &matched_group->servers[s];
                        int64_t act = atomic_load_explicit(&srv->active_conns, memory_order_relaxed);
                        uint64_t reqs = atomic_load_explicit(&srv->total_requests, memory_order_relaxed);
                        uint64_t fails = atomic_load_explicit(&srv->failed_requests, memory_order_relaxed);
                        append_json(body_buf, sizeof(body_buf), &resp_len,
                            "%s{\"server\":\"%s:%u\",\"weight\":%u,\"down\":%s,\"backup\":%s,\"active\":%lld,\"requests\":%llu,\"fails\":%llu}",
                            s > 0 ? "," : "", srv->ip, (unsigned int)srv->port,
                            (unsigned int)srv->weight, srv->is_down ? "true" : "false",
                            srv->is_backup ? "true" : "false", (long long)act,
                            (unsigned long long)reqs, (unsigned long long)fails);
                    }
                    append_json(body_buf, sizeof(body_buf), &resp_len, "]}\n");
                    pthread_rwlock_unlock(&matched_group->lock);
                }
            } else if (strncmp(p, "/servers", 8) == 0) {
                const char *sp = p + 8;
                if (*sp == '/') sp++;
                if (*sp == '\0') {
                    if (strcmp(meth, "POST") == 0) {
                        if (!location->api.write_enabled) {
                            status_code = 403;
                            reason = "Forbidden";
                            append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"API write disabled\"}\n");
                        } else {
                            char srv_str[128];
                            srv_str[0] = '\0';
                            int weight_val = 1;
                            bool down_val = false;
                            bool backup_val = false;

                            json_find_string(body, body_len, "server", srv_str, sizeof(srv_str));
                            json_find_int(body, body_len, "weight", &weight_val);
                            json_find_bool(body, body_len, "down", &down_val);
                            json_find_bool(body, body_len, "backup", &backup_val);

                            if (srv_str[0] == '\0') {
                                status_code = 400;
                                reason = "Bad Request";
                                append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"missing server field\"}\n");
                            } else {
                                char shost[128];
                                uint16_t sport = 80;
                                if (srv_str[0] == '[') {
                                    const char *close_b = strchr(srv_str, ']');
                                    if (close_b != NULL) {
                                        size_t hlen = (size_t)(close_b - (srv_str + 1));
                                        if (hlen >= sizeof(shost)) hlen = sizeof(shost) - 1;
                                        memcpy(shost, srv_str + 1, hlen);
                                        shost[hlen] = '\0';
                                        if (*(close_b + 1) == ':') {
                                            sport = (uint16_t)atoi(close_b + 2);
                                        }
                                    } else {
                                        snprintf(shost, sizeof(shost), "%s", srv_str);
                                    }
                                } else {
                                    const char *scolon = strchr(srv_str, ':');
                                    if (scolon != NULL) {
                                        size_t hlen = (size_t)(scolon - srv_str);
                                        if (hlen >= sizeof(shost)) hlen = sizeof(shost) - 1;
                                        memcpy(shost, srv_str, hlen);
                                        shost[hlen] = '\0';
                                        sport = (uint16_t)atoi(scolon + 1);
                                        if (sport == 0) sport = 80;
                                    } else {
                                        snprintf(shost, sizeof(shost), "%s", srv_str);
                                    }
                                }

                                int added = apex_upstream_add_server_ex(matched_group, shost, sport,
                                                                        weight_val > 0 ? (uint32_t)weight_val : 1u,
                                                                        backup_val, down_val);
                                if (added < 0) {
                                    status_code = 400;
                                    reason = "Bad Request";
                                    append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"failed to add server to upstream group\"}\n");
                                } else {
                                    status_code = 201;
                                    reason = "Created";
                                    append_json(body_buf, sizeof(body_buf), &resp_len,
                                        "{\"server\":\"%s\",\"weight\":%d,\"down\":%s,\"backup\":%s}\n",
                                        srv_str, weight_val > 0 ? weight_val : 1,
                                        down_val ? "true" : "false", backup_val ? "true" : "false");
                                }
                            }
                        }
                    } else if (strcmp(meth, "GET") == 0 || strcmp(meth, "HEAD") == 0) {
                        pthread_rwlock_rdlock(&matched_group->lock);
                        append_json(body_buf, sizeof(body_buf), &resp_len, "[");
                        for (size_t s = 0; s < matched_group->server_count; s++) {
                            const upstream_server_t *srv = &matched_group->servers[s];
                            append_json(body_buf, sizeof(body_buf), &resp_len,
                                "%s{\"server\":\"%s:%u\",\"weight\":%u,\"down\":%s,\"backup\":%s}",
                                s > 0 ? "," : "", srv->ip, (unsigned int)srv->port,
                                (unsigned int)srv->weight, srv->is_down ? "true" : "false",
                                srv->is_backup ? "true" : "false");
                        }
                        append_json(body_buf, sizeof(body_buf), &resp_len, "]\n");
                        pthread_rwlock_unlock(&matched_group->lock);
                    } else {
                        status_code = 405;
                        reason = "Method Not Allowed";
                        append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"Method Not Allowed\"}\n");
                    }
                } else {
                    const char *target_addr = sp;
                    upstream_server_t *target_srv = NULL;
                    size_t target_idx = 0;

                    pthread_rwlock_wrlock(&matched_group->lock);
                    for (size_t s = 0; s < matched_group->server_count; s++) {
                        char curr_addr[128];
                        if (strchr(matched_group->servers[s].ip, ':') != NULL) {
                            snprintf(curr_addr, sizeof(curr_addr), "[%s]:%u",
                                     matched_group->servers[s].ip, matched_group->servers[s].port);
                        } else {
                            snprintf(curr_addr, sizeof(curr_addr), "%s:%u",
                                     matched_group->servers[s].ip, matched_group->servers[s].port);
                        }
                        if (strcmp(curr_addr, target_addr) == 0) {
                            target_srv = &matched_group->servers[s];
                            target_idx = s;
                            break;
                        }
                    }

                    if (target_srv == NULL) {
                        pthread_rwlock_unlock(&matched_group->lock);
                        status_code = 404;
                        reason = "Not Found";
                        append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"server not found in upstream group\"}\n");
                    } else if (strcmp(meth, "PATCH") == 0) {
                        if (!location->api.write_enabled) {
                            pthread_rwlock_unlock(&matched_group->lock);
                            status_code = 403;
                            reason = "Forbidden";
                            append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"API write disabled\"}\n");
                        } else {
                            bool down_val = false;
                            if (json_find_bool(body, body_len, "down", &down_val)) {
                                target_srv->is_down = down_val;
                            }
                            int weight_val = 0;
                            if (json_find_int(body, body_len, "weight", &weight_val) && weight_val > 0) {
                                target_srv->weight = (uint32_t)weight_val;
                            }
                            status_code = 200;
                            reason = "OK";
                            append_json(body_buf, sizeof(body_buf), &resp_len,
                                "{\"server\":\"%s\",\"weight\":%u,\"down\":%s,\"backup\":%s}\n",
                                target_addr, (unsigned int)target_srv->weight,
                                target_srv->is_down ? "true" : "false",
                                target_srv->is_backup ? "true" : "false");
                            pthread_rwlock_unlock(&matched_group->lock);
                        }
                    } else if (strcmp(meth, "DELETE") == 0) {
                        if (!location->api.write_enabled) {
                            pthread_rwlock_unlock(&matched_group->lock);
                            status_code = 403;
                            reason = "Forbidden";
                            append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"API write disabled\"}\n");
                        } else {
                            if (target_idx + 1 < matched_group->server_count) {
                                memmove(&matched_group->servers[target_idx],
                                        &matched_group->servers[target_idx + 1],
                                        (matched_group->server_count - target_idx - 1) * sizeof(upstream_server_t));
                            }
                            matched_group->server_count--;
                            pthread_rwlock_unlock(&matched_group->lock);
                            status_code = 200;
                            reason = "OK";
                            append_json(body_buf, sizeof(body_buf), &resp_len,
                                "{\"status\":\"removed\",\"server\":\"%s\"}\n", target_addr);
                        }
                    } else {
                        pthread_rwlock_unlock(&matched_group->lock);
                        status_code = 405;
                        reason = "Method Not Allowed";
                        append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"Method Not Allowed\"}\n");
                    }
                }
            } else {
                status_code = 404;
                reason = "Not Found";
                append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"endpoint not found\"}\n");
            }
        }
    } else {
        status_code = 404;
        reason = "Not Found";
        append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"unknown api path\"}\n");
    }

    const apex_server_tokens_config_t *tokens = router_get_server_tokens(runtime, server);
    char server_hdr[128];
    router_format_server_header(tokens, server_hdr, sizeof(server_hdr));

    char header[512];
    int written = snprintf(header, sizeof(header),
                           "HTTP/1.1 %d %s\r\n"
                           "%s"
                           "Content-Type: application/json\r\n"
                           "Content-Length: %zu\r\n"
                           "Connection: %s\r\n\r\n",
                           status_code, reason, server_hdr, resp_len,
                           connection->close_after_write ? "close" : "keep-alive");
    if (written > 0 && (size_t)written < sizeof(header)) {
        apex_conn_write(connection, header, (size_t)written);
        if (strcmp(meth, "HEAD") != 0 && resp_len > 0) {
            apex_conn_write(connection, body_buf, resp_len);
        }
    }

    apex_record_status(status_code);
    if (res != NULL) {
        res->last_status = status_code;
        res->last_body_bytes = resp_len;
    }
}

void apex_dispatch(apex_app_t *app, const char *req_buf, size_t header_len, const char *body, size_t body_len,
                   apex_res_t *res) {
    const apex_runtime_t *runtime = app->generation != NULL ? app->generation->runtime : NULL;
    apex_dispatch_runtime(app, runtime, req_buf, header_len, body, body_len, res);
}

void apex_dispatch_runtime(apex_app_t *app, const apex_runtime_t *runtime, const char *req_buf, size_t header_len,
                           const char *body, size_t body_len, apex_res_t *res) {
    atomic_fetch_add_explicit(&g_apex_stats.requests, 1, memory_order_relaxed);
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

        struct timeval start_tv;
        gettimeofday(&start_tv, NULL);
        uint64_t start_time_us = (uint64_t)start_tv.tv_sec * 1000000ULL + (uint64_t)start_tv.tv_usec;

        char peer_ip[INET6_ADDRSTRLEN];
        if (res->conn == NULL || !conn_get_peer_ip(res->conn, peer_ip, sizeof(peer_ip))) {
            strcpy(peer_ip, "127.0.0.1");
        }
        char client_ip[INET6_ADDRSTRLEN];
        snprintf(client_ip, sizeof(client_ip), "%s", peer_ip);

        s_current_request_id[0] = '\0';

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
            .start_time_us = start_time_us,
            .extra_headers = {0},
            .extra_headers_len = 0,
            .request_id = {0},
            .module_data = {0},
        };

        /* Phase 1: PRE_ROUTING */
        apex_action_t action = apex_pipeline_run_phase(&ctx, APEX_PHASE_PRE_ROUTING);
        if (action == APEX_ACTION_DENY) {
            int deny_status = ctx.status_code >= 400 ? ctx.status_code : 403;
            router_send_error_ex(res->conn, NULL, req_buf, header_len,
                                 deny_status, "Forbidden", "Forbidden\n",
                                 ctx.extra_headers, ctx.extra_headers_len);
            router_trigger_logging(&ctx, deny_status, 10, client_ip);
            return;
        }
        if (action == APEX_ACTION_DONE) {
            return;
        }

        apex_config_route_t route;
        if (apex_runtime_match(runtime, host, host_length, path, match_path_length, &route)) {
            ctx.server = route.server;
            ctx.location = route.location;

            const apex_otel_config_t *otel_cfg = (route.location != NULL && route.location->otel.is_set)
                ? &route.location->otel
                : (route.server != NULL && route.server->otel.is_set ? &route.server->otel : (runtime && runtime->config ? &runtime->config->http.otel : NULL));
            router_otel_init(req_buf, header_len, otel_cfg);

            /* Resolve real client IP */
            const apex_real_ip_rule_t *real_ip_rules = NULL;
            size_t real_ip_count = 0;
            const char *real_ip_hdr = NULL;
            bool real_ip_rec = false;

            if (route.location != NULL && route.location->real_ip_rule_count > 0) {
                real_ip_rules = route.location->real_ip_rules;
                real_ip_count = route.location->real_ip_rule_count;
                real_ip_hdr = route.location->has_real_ip_header ? route.location->real_ip_header : "X-Forwarded-For";
                real_ip_rec = route.location->has_real_ip_recursive ? route.location->real_ip_recursive : false;
            } else if (route.server != NULL && route.server->real_ip_rule_count > 0) {
                real_ip_rules = route.server->real_ip_rules;
                real_ip_count = route.server->real_ip_rule_count;
                real_ip_hdr = route.server->has_real_ip_header ? route.server->real_ip_header : "X-Forwarded-For";
                real_ip_rec = route.server->has_real_ip_recursive ? route.server->real_ip_recursive : false;
            }
            apex_real_ip_resolve(real_ip_rules, real_ip_count, real_ip_hdr, real_ip_rec,
                                 peer_ip, req_buf, header_len, client_ip, sizeof(client_ip));

            /* Server-level return redirect */
            if (route.server != NULL && route.server->return_code > 0) {
                const char *scheme = (res->conn != NULL && res->conn->transport == APEX_TRANSPORT_TLS) ? "https" : "http";
                char expanded[APEX_CONFIG_PATH_MAX * 2];
                router_expand_string_ex(runtime, route.server->return_url, expanded, sizeof(expanded),
                                        host, host_length, path, path_len,
                                        client_ip, strlen(client_ip),
                                        scheme, strlen(scheme),
                                        NULL, 0, NULL, 0, NULL, 0,
                                        route.server->return_code, 0);
                char add_hdr_buf[1024];
                size_t add_hdr_len = router_build_add_headers(runtime, route.server, NULL, route.server->return_code,
                                                              host, host_length, path, path_len,
                                                              client_ip, strlen(client_ip), scheme, strlen(scheme),
                                                              0, add_hdr_buf, sizeof(add_hdr_buf));
                char red_extra[1024];
                snprintf(red_extra, sizeof(red_extra), "%.*s%.*s",
                         (int)ctx.extra_headers_len, ctx.extra_headers,
                         (int)add_hdr_len, add_hdr_buf);
                router_send_redirect(res->conn, route.server, route.server->return_code, expanded,
                                     red_extra, strlen(red_extra));
                router_trigger_logging(&ctx, route.server->return_code, 0, client_ip);
                return;
            }

            /* Server-level ACL rules */
            if (route.server != NULL && route.server->acl_rule_count > 0 && res->conn != NULL) {
                if (!router_check_acl(route.server->acl_rules, route.server->acl_rule_count, client_ip, res->conn->fd)) {
                    router_send_error(res->conn, route.server, req_buf, header_len, 403, "Forbidden", "Forbidden\n");
                    router_trigger_logging(&ctx, 403, 10, client_ip);
                    return;
                }
            }

            if (route.location != NULL) {
                /* Location-level return redirect */
                if (route.location->return_code > 0) {
                    const char *scheme = (res->conn != NULL && res->conn->transport == APEX_TRANSPORT_TLS) ? "https" : "http";
                    char expanded[APEX_CONFIG_PATH_MAX * 2];
                    router_expand_string_ex(runtime, route.location->return_url, expanded, sizeof(expanded),
                                            host, host_length, path, path_len,
                                            client_ip, strlen(client_ip),
                                            scheme, strlen(scheme),
                                            NULL, 0, NULL, 0, NULL, 0,
                                            route.location->return_code, 0);
                    char add_hdr_buf[1024];
                    size_t add_hdr_len = router_build_add_headers(runtime, route.server, route.location, route.location->return_code,
                                                                  host, host_length, path, path_len,
                                                                  client_ip, strlen(client_ip), scheme, strlen(scheme),
                                                                  0, add_hdr_buf, sizeof(add_hdr_buf));
                    char red_extra[1024];
                    snprintf(red_extra, sizeof(red_extra), "%.*s%.*s",
                             (int)ctx.extra_headers_len, ctx.extra_headers,
                             (int)add_hdr_len, add_hdr_buf);
                    router_send_redirect(res->conn, route.server, route.location->return_code, expanded,
                                         red_extra, strlen(red_extra));
                    router_trigger_logging(&ctx, route.location->return_code, 0, client_ip);
                    return;
                }

                /* Location-level ACL rules */
                if (route.location->acl_rule_count > 0 && res->conn != NULL) {
                    if (!router_check_acl(route.location->acl_rules, route.location->acl_rule_count, client_ip, res->conn->fd)) {
                        router_send_error(res->conn, route.server, req_buf, header_len, 403, "Forbidden", "Forbidden\n");
                        router_trigger_logging(&ctx, 403, 10, client_ip);
                        return;
                    }
                }

                /* Basic Authentication check */
                const apex_auth_basic_config_t *ab = (route.location != NULL && route.location->auth_basic.is_set)
                    ? &route.location->auth_basic
                    : (route.server != NULL && route.server->auth_basic.is_set)
                        ? &route.server->auth_basic
                        : (runtime != NULL && runtime->config != NULL && runtime->config->http.auth_basic.is_set)
                            ? &runtime->config->http.auth_basic
                            : NULL;

                if (ab != NULL && ab->enabled) {
                    if (!router_check_auth_basic(req_buf, header_len, ab)) {
                        char auth_hdr_buf[256];
                        snprintf(auth_hdr_buf, sizeof(auth_hdr_buf), "WWW-Authenticate: Basic realm=\"%s\"\r\n",
                                 ab->realm[0] ? ab->realm : "Restricted");
                        router_send_error_ex(res->conn, route.server, req_buf, header_len,
                                             401, "Unauthorized", "Unauthorized\n",
                                             auth_hdr_buf, strlen(auth_hdr_buf));
                        router_trigger_logging(&ctx, 401, 13, client_ip);
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
                    router_trigger_logging(&ctx, deny_status, 10, client_ip);
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
                    router_trigger_logging(&ctx, deny_status, 23, client_ip);
                    return;
                }
                if (action == APEX_ACTION_DONE) {
                    return;
                }

                /* Rate Limiting & Connection Limiting */

                const char *req_zone = (route.location != NULL && route.location->limit_req_zone[0] != '\0')
                    ? route.location->limit_req_zone
                    : (route.server != NULL ? route.server->limit_req_zone : "");
                if (req_zone[0] != '\0') {
                    uint32_t burst = (route.location != NULL && route.location->limit_req_zone[0] != '\0')
                        ? route.location->limit_req_burst : route.server->limit_req_burst;
                    bool nodelay = (route.location != NULL && route.location->limit_req_zone[0] != '\0')
                        ? route.location->limit_req_nodelay : route.server->limit_req_nodelay;
                    int req_status = (route.location != NULL && route.location->limit_req_status != 0)
                        ? route.location->limit_req_status
                        : (route.server != NULL && route.server->limit_req_status != 0 ? route.server->limit_req_status : 503);
                    uint32_t retry_after = 1;
                    if (!apex_rate_limit_check(runtime, req_zone, client_ip, burst, nodelay, &retry_after)) {
                        char retry_extra[512];
                        snprintf(retry_extra, sizeof(retry_extra), "%sRetry-After: %u\r\n", ctx.extra_headers, (unsigned)retry_after);
                        router_send_error_ex(res->conn, route.server, req_buf, header_len,
                                             req_status, req_status == 429 ? "Too Many Requests" : "Service Unavailable",
                                             req_status == 429 ? "Too Many Requests\n" : "Service Unavailable\n",
                                             retry_extra, strlen(retry_extra));
                        router_trigger_logging(&ctx, req_status, 20, client_ip);
                        return;
                    }
                }

                const char *conn_zone = (route.location != NULL && route.location->limit_conn_zone[0] != '\0')
                    ? route.location->limit_conn_zone
                    : (route.server != NULL ? route.server->limit_conn_zone : "");
                bool conn_acquired = false;
                if (conn_zone[0] != '\0') {
                    uint32_t max_conns = (route.location != NULL && route.location->limit_conn_zone[0] != '\0')
                        ? route.location->limit_conn_max : route.server->limit_conn_max;
                    int conn_status = (route.location != NULL && route.location->limit_conn_status != 0)
                        ? route.location->limit_conn_status
                        : (route.server != NULL && route.server->limit_conn_status != 0 ? route.server->limit_conn_status : 503);
                    if (!apex_conn_limit_acquire(runtime, conn_zone, client_ip, max_conns)) {
                        router_send_error_ex(res->conn, route.server, req_buf, header_len,
                                             conn_status, conn_status == 429 ? "Too Many Requests" : "Service Unavailable",
                                             conn_status == 429 ? "Too Many Requests\n" : "Service Unavailable\n",
                                             ctx.extra_headers, ctx.extra_headers_len);
                        router_trigger_logging(&ctx, conn_status, 20, client_ip);
                        return;
                    }
                    conn_acquired = true;
                }

                /* Phase 5: CONTENT_HANDLER */
                action = apex_pipeline_run_phase(&ctx, APEX_PHASE_CONTENT_HANDLER);
                if (action == APEX_ACTION_DONE) {
                    if (conn_acquired) {
                        apex_conn_limit_release(runtime, conn_zone, client_ip);
                    }
                    apex_pipeline_run_phase(&ctx, APEX_PHASE_RESPONSE_FILTER);
                    router_trigger_logging(&ctx, 200, 0, client_ip);
                    return;
                }

                /* Phase 6: RESPONSE_FILTER */
                apex_pipeline_run_phase(&ctx, APEX_PHASE_RESPONSE_FILTER);

                if (route.location->stub_status) {
                    uint64_t accepts = atomic_load_explicit(&g_apex_stats.accepts, memory_order_relaxed);
                    uint64_t handled = atomic_load_explicit(&g_apex_stats.handled, memory_order_relaxed);
                    uint64_t requests = atomic_load_explicit(&g_apex_stats.requests, memory_order_relaxed);
                    int64_t active = atomic_load_explicit(&g_apex_stats.active_connections, memory_order_relaxed);
                    int64_t reading = atomic_load_explicit(&g_apex_stats.reading_connections, memory_order_relaxed);
                    int64_t writing = atomic_load_explicit(&g_apex_stats.writing_connections, memory_order_relaxed);
                    int64_t waiting = atomic_load_explicit(&g_apex_stats.waiting_connections, memory_order_relaxed);
                    if (active < 0) active = 0;
                    if (reading < 0) reading = 0;
                    if (writing < 0) writing = 0;
                    if (waiting < 0) waiting = 0;

                    char body_buf[256];
                    int blen = snprintf(body_buf, sizeof(body_buf),
                                        "Active connections: %lld \n"
                                        "server accepts handled requests\n"
                                        " %llu %llu %llu \n"
                                        "Reading: %lld Writing: %lld Waiting: %lld \n",
                                        (long long)active,
                                        (unsigned long long)accepts,
                                        (unsigned long long)handled,
                                        (unsigned long long)requests,
                                        (long long)reading,
                                        (long long)writing,
                                        (long long)waiting);
                    const apex_server_tokens_config_t *tokens = router_get_server_tokens(runtime, route.server);
                    char server_hdr[128];
                    router_format_server_header(tokens, server_hdr, sizeof(server_hdr));

                    char extra_hdrs_buf[1024];
                    size_t extra_hdrs_len = 0;
                    if (ctx.extra_headers_len > 0) {
                        size_t to_copy = ctx.extra_headers_len < sizeof(extra_hdrs_buf) ? ctx.extra_headers_len : sizeof(extra_hdrs_buf) - 1;
                        memcpy(extra_hdrs_buf, ctx.extra_headers, to_copy);
                        extra_hdrs_len = to_copy;
                    }
                    extra_hdrs_len += router_build_add_headers(runtime, route.server, route.location, 200,
                                                              host, host_length, path, path_len,
                                                              client_ip, strlen(client_ip),
                                                              "http", 4, 0,
                                                              extra_hdrs_buf + extra_hdrs_len,
                                                              sizeof(extra_hdrs_buf) - extra_hdrs_len);

                    char resp_buf[1536];
                    int rlen = snprintf(resp_buf, sizeof(resp_buf),
                                        "HTTP/1.1 200 OK\r\n"
                                        "%s"
                                        "Content-Type: text/plain\r\n"
                                        "Content-Length: %d\r\n"
                                        "Connection: %s\r\n"
                                        "%.*s"
                                        "\r\n",
                                        server_hdr,
                                        blen,
                                        res->conn->close_after_write ? "close" : "keep-alive",
                                        (int)extra_hdrs_len, extra_hdrs_buf);
                    apex_conn_write(res->conn, resp_buf, (size_t)rlen);
                    if (method_len != 4 || memcmp(req_buf, "HEAD", 4) != 0) {
                        apex_conn_write(res->conn, body_buf, (size_t)blen);
                    }
                    apex_record_status(200);
                    if (conn_acquired) {
                        apex_conn_limit_release(runtime, conn_zone, client_ip);
                    }
                    router_trigger_logging(&ctx, 200, (size_t)blen, client_ip);
                    return;
                }

                if (route.location->metrics) {
                    uint64_t accepts = atomic_load_explicit(&g_apex_stats.accepts, memory_order_relaxed);
                    uint64_t handled = atomic_load_explicit(&g_apex_stats.handled, memory_order_relaxed);
                    uint64_t requests = atomic_load_explicit(&g_apex_stats.requests, memory_order_relaxed);
                    int64_t active = atomic_load_explicit(&g_apex_stats.active_connections, memory_order_relaxed);
                    int64_t reading = atomic_load_explicit(&g_apex_stats.reading_connections, memory_order_relaxed);
                    int64_t writing = atomic_load_explicit(&g_apex_stats.writing_connections, memory_order_relaxed);
                    int64_t waiting = atomic_load_explicit(&g_apex_stats.waiting_connections, memory_order_relaxed);
                    if (active < 0) active = 0;
                    if (reading < 0) reading = 0;
                    if (writing < 0) writing = 0;
                    if (waiting < 0) waiting = 0;

                    uint64_t r2xx = atomic_load_explicit(&g_apex_stats.responses_2xx, memory_order_relaxed);
                    uint64_t r3xx = atomic_load_explicit(&g_apex_stats.responses_3xx, memory_order_relaxed);
                    uint64_t r4xx = atomic_load_explicit(&g_apex_stats.responses_4xx, memory_order_relaxed);
                    uint64_t r5xx = atomic_load_explicit(&g_apex_stats.responses_5xx, memory_order_relaxed);
                    uint64_t chits = atomic_load_explicit(&g_apex_stats.cache_hits, memory_order_relaxed);
                    uint64_t cmiss = atomic_load_explicit(&g_apex_stats.cache_misses, memory_order_relaxed);
                    uint64_t cbyp = atomic_load_explicit(&g_apex_stats.cache_bypasses, memory_order_relaxed);

                    char body_buf[2048];
                    int blen = snprintf(body_buf, sizeof(body_buf),
                                        "# HELP apex_connections_active Active client connections\n"
                                        "# TYPE apex_connections_active gauge\n"
                                        "apex_connections_active %lld\n\n"
                                        "# HELP apex_connections_reading Connections reading request\n"
                                        "# TYPE apex_connections_reading gauge\n"
                                        "apex_connections_reading %lld\n\n"
                                        "# HELP apex_connections_writing Connections writing response\n"
                                        "# TYPE apex_connections_writing gauge\n"
                                        "apex_connections_writing %lld\n\n"
                                        "# HELP apex_connections_waiting Connections waiting for request\n"
                                        "# TYPE apex_connections_waiting gauge\n"
                                        "apex_connections_waiting %lld\n\n"
                                        "# HELP apex_connections_accepted_total Total accepted connections\n"
                                        "# TYPE apex_connections_accepted_total counter\n"
                                        "apex_connections_accepted_total %llu\n\n"
                                        "# HELP apex_connections_handled_total Total handled connections\n"
                                        "# TYPE apex_connections_handled_total counter\n"
                                        "apex_connections_handled_total %llu\n\n"
                                        "# HELP apex_http_requests_total Total HTTP requests handled\n"
                                        "# TYPE apex_http_requests_total counter\n"
                                        "apex_http_requests_total %llu\n\n"
                                        "# HELP apex_http_responses_total Total HTTP responses sent by status code class\n"
                                        "# TYPE apex_http_responses_total counter\n"
                                        "apex_http_responses_total{code=\"2xx\"} %llu\n"
                                        "apex_http_responses_total{code=\"3xx\"} %llu\n"
                                        "apex_http_responses_total{code=\"4xx\"} %llu\n"
                                        "apex_http_responses_total{code=\"5xx\"} %llu\n\n"
                                        "# HELP apex_cache_requests_total Cache requests by status\n"
                                        "# TYPE apex_cache_requests_total counter\n"
                                        "apex_cache_requests_total{status=\"hit\"} %llu\n"
                                        "apex_cache_requests_total{status=\"miss\"} %llu\n"
                                        "apex_cache_requests_total{status=\"bypass\"} %llu\n",
                                        (long long)active, (long long)reading, (long long)writing, (long long)waiting,
                                        (unsigned long long)accepts, (unsigned long long)handled,
                                        (unsigned long long)requests,
                                        (unsigned long long)r2xx, (unsigned long long)r3xx,
                                        (unsigned long long)r4xx, (unsigned long long)r5xx,
                                        (unsigned long long)chits, (unsigned long long)cmiss, (unsigned long long)cbyp);

                    const apex_server_tokens_config_t *tokens = router_get_server_tokens(runtime, route.server);
                    char server_hdr[128];
                    router_format_server_header(tokens, server_hdr, sizeof(server_hdr));

                    char extra_hdrs_buf[1024];
                    size_t extra_hdrs_len = 0;
                    if (ctx.extra_headers_len > 0) {
                        size_t to_copy = ctx.extra_headers_len < sizeof(extra_hdrs_buf) ? ctx.extra_headers_len : sizeof(extra_hdrs_buf) - 1;
                        memcpy(extra_hdrs_buf, ctx.extra_headers, to_copy);
                        extra_hdrs_len = to_copy;
                    }
                    extra_hdrs_len += router_build_add_headers(runtime, route.server, route.location, 200,
                                                              host, host_length, path, path_len,
                                                              client_ip, strlen(client_ip),
                                                              "http", 4, 0,
                                                              extra_hdrs_buf + extra_hdrs_len,
                                                              sizeof(extra_hdrs_buf) - extra_hdrs_len);

                    char resp_buf[1536];
                    int rlen = snprintf(resp_buf, sizeof(resp_buf),
                                        "HTTP/1.1 200 OK\r\n"
                                        "%s"
                                        "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                                        "Content-Length: %d\r\n"
                                        "Connection: %s\r\n"
                                        "%.*s"
                                        "\r\n",
                                        server_hdr,
                                        blen,
                                        res->conn->close_after_write ? "close" : "keep-alive",
                                        (int)extra_hdrs_len, extra_hdrs_buf);
                    apex_conn_write(res->conn, resp_buf, (size_t)rlen);
                    if (method_len != 4 || memcmp(req_buf, "HEAD", 4) != 0) {
                        apex_conn_write(res->conn, body_buf, (size_t)blen);
                    }
                    apex_record_status(200);
                    if (conn_acquired) {
                        apex_conn_limit_release(runtime, conn_zone, client_ip);
                    }
                    router_trigger_logging(&ctx, 200, (size_t)blen, client_ip);
                    return;
                }

                if (route.location->api.enabled) {
                    router_handle_api_request(res->conn, runtime, route.server, route.location,
                                              req_buf, header_len, req_buf, method_len, path, path_len, body, body_len,
                                              res, ctx.extra_headers, ctx.extra_headers_len, client_ip);
                    if (conn_acquired) {
                        apex_conn_limit_release(runtime, conn_zone, client_ip);
                    }
                    router_trigger_logging(&ctx, res ? res->last_status : 200, res ? res->last_body_bytes : 0, client_ip);
                    return;
                }

                if (route.location->target != APEX_PROXY_TARGET_NONE) {
                    router_forward_request(runtime, &route, req_buf, header_len, req_buf, method_len, path, path_len, body,
                                           body_len, res, ctx.extra_headers, ctx.extra_headers_len, client_ip);
                    if (conn_acquired) {
                        apex_conn_limit_release(runtime, conn_zone, client_ip);
                    }
                    router_trigger_logging(&ctx, 200, 0, client_ip);
                    return;
                }
                if (route.location->fastcgi_pass[0] != '\0') {
                    router_forward_fastcgi(runtime, &route, req_buf, header_len, req_buf, method_len, path, path_len, body,
                                           body_len, res, ctx.extra_headers, ctx.extra_headers_len, client_ip);
                    if (conn_acquired) {
                        apex_conn_limit_release(runtime, conn_zone, client_ip);
                    }
                    router_trigger_logging(&ctx, 200, 0, client_ip);
                    return;
                }
                if (route.location->root != NULL) {
                    bool head_request = method_len == 4 && memcmp(req_buf, "HEAD", 4) == 0;
                    char extra_hdrs_buf[1024];
                    size_t extra_hdrs_len = 0;
                    if (ctx.extra_headers_len > 0) {
                        size_t to_copy = ctx.extra_headers_len < sizeof(extra_hdrs_buf) ? ctx.extra_headers_len : sizeof(extra_hdrs_buf) - 1;
                        memcpy(extra_hdrs_buf, ctx.extra_headers, to_copy);
                        extra_hdrs_len = to_copy;
                    }
                    extra_hdrs_len += router_build_add_headers(runtime, route.server, route.location, 200,
                                                              host, host_length, path, path_len,
                                                              client_ip, strlen(client_ip),
                                                              "http", 4, 0,
                                                              extra_hdrs_buf + extra_hdrs_len,
                                                              sizeof(extra_hdrs_buf) - extra_hdrs_len);
                    apex_static_serve(route.server, route.location, req_buf, header_len, path, match_path_length,
                                      head_request, res, extra_hdrs_buf, extra_hdrs_len);
                    if (conn_acquired) {
                        apex_conn_limit_release(runtime, conn_zone, client_ip);
                    }
                    router_trigger_logging(&ctx, 200, 0, client_ip);
                    return;
                }
                if (conn_acquired) {
                    apex_conn_limit_release(runtime, conn_zone, client_ip);
                }
            }
        }

        if (runtime->config != NULL && runtime->config->server_count > 0) {
            router_send_error(res->conn, &runtime->config->servers[0], req_buf, header_len, 404, "Not Found",
                              "Not Found\n");
            router_trigger_logging(&ctx, 404, 10, client_ip);
            return;
        }
    }

    apex_res_send(res, 404, NULL, 0);
}
