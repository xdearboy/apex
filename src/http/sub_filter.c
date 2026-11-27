#include "apex/sub_filter.h"
#include "apex/http_util.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

void apex_cookie_rules_get(const apex_server_config_t *server,
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

bool apex_cookie_rewrite_line(const char *line, size_t line_length,
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
    if (!apex_http_header_name_equal(line, name_len, "Set-Cookie")) {
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

const apex_sub_filter_config_t *apex_sub_filter_get(const apex_server_config_t *server,
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

bool apex_sub_filter_apply(const apex_sub_filter_config_t *sub,
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
        if (apex_http_find_header(response_headers, response_headers_len, "Content-Type", &ct_val, &ct_len)) {
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

        if (repl_len > match_len) {
            size_t diff = repl_len - match_len;
            if (match_count > (SIZE_MAX - cur_len) / diff) {
                free(allocated_intermediate);
                return false;
            }
        }

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
