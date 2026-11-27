#include "apex/http_api.h"
#include "apex/http_util.h"
#include "apex/proxy.h"
#include "internal.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

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
    if (p >= json + json_len || *p != '\"') return false;
    p++;
    const char *val_start = p;
    while (p < json + json_len && *p != '\"') p++;
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

void apex_http_api_handle(conn_t *connection, const apex_runtime_t *runtime,
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
        if (apex_http_find_header(req_buf, req_buf_len, "Authorization", &auth_hdr, &auth_hdr_len)) {
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
            if (apex_http_find_header(req_buf, req_buf_len, "X-API-Key", &key_hdr, &key_hdr_len)) {
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
            const apex_server_tokens_config_t *tokens = apex_http_get_server_tokens(server, &runtime->config->http);
            char server_hdr[128];
            apex_http_format_server_header(tokens, server_hdr, sizeof(server_hdr));
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
    const char *allow_methods = NULL;

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
                allow_methods = "GET, HEAD";
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
                    allow_methods = "GET, HEAD";
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
                        allow_methods = "GET, HEAD, POST";
                        append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"Method Not Allowed\"}\n");
                    }
                } else {
                    const char *target_addr = sp;
                    upstream_server_t *target_srv = NULL;
                    size_t target_idx = 0;

                    atomic_store_explicit(&matched_group->write_in_progress, 1, memory_order_release);
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
                        atomic_store_explicit(&matched_group->write_in_progress, 0, memory_order_release);
                        status_code = 404;
                        reason = "Not Found";
                        append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"server not found in upstream group\"}\n");
                    } else if (strcmp(meth, "PATCH") == 0) {
                        if (!location->api.write_enabled) {
                            pthread_rwlock_unlock(&matched_group->lock);
                            atomic_store_explicit(&matched_group->write_in_progress, 0, memory_order_release);
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
                            atomic_store_explicit(&matched_group->write_in_progress, 0, memory_order_release);
                        }
                    } else if (strcmp(meth, "DELETE") == 0) {
                        if (!location->api.write_enabled) {
                            pthread_rwlock_unlock(&matched_group->lock);
                            atomic_store_explicit(&matched_group->write_in_progress, 0, memory_order_release);
                            status_code = 403;
                            reason = "Forbidden";
                            append_json(body_buf, sizeof(body_buf), &resp_len, "{\"error\":\"API write disabled\"}\n");
                        } else {
                            target_srv->is_down = true;
                            if (target_idx + 1 < matched_group->server_count) {
                                memmove(&matched_group->servers[target_idx],
                                        &matched_group->servers[target_idx + 1],
                                        (matched_group->server_count - target_idx - 1) * sizeof(upstream_server_t));
                            }
                            memset(&matched_group->servers[matched_group->server_count - 1], 0, sizeof(upstream_server_t));
                            matched_group->server_count--;
                            pthread_rwlock_unlock(&matched_group->lock);
                            atomic_store_explicit(&matched_group->write_in_progress, 0, memory_order_release);
                            status_code = 200;
                            reason = "OK";
                            append_json(body_buf, sizeof(body_buf), &resp_len,
                                "{\"status\":\"removed\",\"server\":\"%s\"}\n", target_addr);
                        }
                    } else {
                        pthread_rwlock_unlock(&matched_group->lock);
                        status_code = 405;
                        reason = "Method Not Allowed";
                        allow_methods = "PATCH, DELETE";
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

    const apex_server_tokens_config_t *tokens = apex_http_get_server_tokens(server, &runtime->config->http);
    char server_hdr[128];
    apex_http_format_server_header(tokens, server_hdr, sizeof(server_hdr));

    char allow_hdr[64] = {0};
    if (status_code == 405 && allow_methods != NULL) {
        snprintf(allow_hdr, sizeof(allow_hdr), "Allow: %s\r\n", allow_methods);
    }

    char header[512];
    int written = snprintf(header, sizeof(header),
                           "HTTP/1.1 %d %s\r\n"
                           "%s"
                           "%s"
                           "Content-Type: application/json\r\n"
                           "Content-Length: %zu\r\n"
                           "Connection: %s\r\n\r\n",
                           status_code, reason, server_hdr, allow_hdr, resp_len,
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
