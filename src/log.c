#include "apex/log.h"
#include "internal.h"

#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define APEX_LOG_LINE_MAX 8192
#define APEX_LOG_BUFFER_SIZE 65536

typedef struct apex_log_file {
    char path[APEX_CONFIG_PATH_MAX];
    int fd;
    pthread_mutex_t lock;
    char buffer[APEX_LOG_BUFFER_SIZE];
    size_t buffer_len;
    struct apex_log_file *next;
} apex_log_file_t;

typedef struct apex_log_manager {
    apex_log_format_t formats[APEX_CONFIG_MAX_LOG_FORMATS + 2];
    size_t format_count;
    apex_log_file_t *files;
    pthread_mutex_t files_lock;
} apex_log_manager_t;

static bool extract_header(const char *raw, size_t raw_len, const char *header, char *out, size_t out_len) {
    if (raw == NULL || raw_len == 0 || header == NULL || out == NULL || out_len == 0) {
        return false;
    }
    size_t hlen = strlen(header);
    const char *cur = raw;
    const char *end = raw + raw_len;

    const char *line_end = memmem(cur, (size_t)(end - cur), "\r\n", 2);
    if (!line_end) return false;
    cur = line_end + 2;

    while (cur < end) {
        if (cur + 2 <= end && cur[0] == '\r' && cur[1] == '\n') break;
        const char *next_line = memmem(cur, (size_t)(end - cur), "\r\n", 2);
        size_t line_len = next_line ? (size_t)(next_line - cur) : (size_t)(end - cur);

        const char *colon = memchr(cur, ':', line_len);
        if (colon != NULL) {
            size_t name_len = (size_t)(colon - cur);
            if (name_len == hlen && strncasecmp(cur, header, hlen) == 0) {
                const char *val = colon + 1;
                while (val < cur + line_len && (*val == ' ' || *val == '\t')) val++;
                const char *vend = cur + line_len;
                while (vend > val && (vend[-1] == ' ' || vend[-1] == '\t')) vend--;
                size_t len = (size_t)(vend - val);
                if (len >= out_len) len = out_len - 1;
                memcpy(out, val, len);
                out[len] = '\0';
                return true;
            }
        }
        if (!next_line) break;
        cur = next_line + 2;
    }
    return false;
}

static void add_item(apex_log_format_t *fmt, apex_log_item_type_t type, const char *literal, const char *custom) {
    if (fmt->item_count == fmt->item_capacity) {
        size_t new_cap = fmt->item_capacity ? fmt->item_capacity * 2 : 16;
        apex_log_item_t *new_items = realloc(fmt->items, new_cap * sizeof(apex_log_item_t));
        if (!new_items) return;
        fmt->items = new_items;
        fmt->item_capacity = new_cap;
    }
    apex_log_item_t *item = &fmt->items[fmt->item_count++];
    memset(item, 0, sizeof(*item));
    item->type = type;
    if (literal) {
        strncpy(item->literal, literal, sizeof(item->literal) - 1);
    }
    if (custom) {
        strncpy(item->custom_header, custom, sizeof(item->custom_header) - 1);
    }
}

int apex_log_format_compile(const char *name, const char *fmt_str, apex_log_format_t *out_fmt) {
    if (name == NULL || fmt_str == NULL || out_fmt == NULL) {
        return -1;
    }
    memset(out_fmt, 0, sizeof(*out_fmt));
    strncpy(out_fmt->name, name, sizeof(out_fmt->name) - 1);

    const char *p = fmt_str;
    char lit_buf[128];
    size_t lit_len = 0;

    while (*p != '\0') {
        if (*p == '$') {
            /* Flush literal buffer first */
            if (lit_len > 0) {
                lit_buf[lit_len] = '\0';
                add_item(out_fmt, APEX_LOG_ITEM_LITERAL, lit_buf, NULL);
                lit_len = 0;
            }

            p++; /* skip '$' */
            const char *var_start = p;
            while (*p && (isalnum((unsigned char)*p) || *p == '_')) {
                p++;
            }
            size_t var_len = (size_t)(p - var_start);
            char var_name[64];
            if (var_len >= sizeof(var_name)) var_len = sizeof(var_name) - 1;
            memcpy(var_name, var_start, var_len);
            var_name[var_len] = '\0';

            if (strcmp(var_name, "remote_addr") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_REMOTE_ADDR, NULL, NULL);
            } else if (strcmp(var_name, "remote_user") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_REMOTE_USER, NULL, NULL);
            } else if (strcmp(var_name, "time_local") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_TIME_LOCAL, NULL, NULL);
            } else if (strcmp(var_name, "time_iso8601") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_TIME_ISO8601, NULL, NULL);
            } else if (strcmp(var_name, "request") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_REQUEST, NULL, NULL);
            } else if (strcmp(var_name, "request_method") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_REQUEST_METHOD, NULL, NULL);
            } else if (strcmp(var_name, "request_uri") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_REQUEST_URI, NULL, NULL);
            } else if (strcmp(var_name, "server_protocol") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_SERVER_PROTOCOL, NULL, NULL);
            } else if (strcmp(var_name, "status") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_STATUS, NULL, NULL);
            } else if (strcmp(var_name, "body_bytes_sent") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_BODY_BYTES_SENT, NULL, NULL);
            } else if (strcmp(var_name, "bytes_sent") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_BYTES_SENT, NULL, NULL);
            } else if (strcmp(var_name, "http_referer") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_HTTP_REFERER, NULL, NULL);
            } else if (strcmp(var_name, "http_user_agent") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_HTTP_USER_AGENT, NULL, NULL);
            } else if (strcmp(var_name, "upstream_addr") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_UPSTREAM_ADDR, NULL, NULL);
            } else if (strcmp(var_name, "upstream_status") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_UPSTREAM_STATUS, NULL, NULL);
            } else if (strcmp(var_name, "upstream_response_time") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_UPSTREAM_RESPONSE_TIME, NULL, NULL);
            } else if (strcmp(var_name, "request_time") == 0) {
                add_item(out_fmt, APEX_LOG_VAR_REQUEST_TIME, NULL, NULL);
            } else if (strncmp(var_name, "http_", 5) == 0) {
                /* Custom header e.g. http_x_custom -> X-Custom */
                char header_trans[64];
                const char *hraw = var_name + 5;
                size_t hraw_len = strlen(hraw);
                if (hraw_len >= sizeof(header_trans)) hraw_len = sizeof(header_trans) - 1;
                for (size_t i = 0; i < hraw_len; i++) {
                    header_trans[i] = (hraw[i] == '_') ? '-' : hraw[i];
                }
                header_trans[hraw_len] = '\0';
                add_item(out_fmt, APEX_LOG_VAR_HTTP_CUSTOM, NULL, header_trans);
            } else {
                /* Unknown variable: print as literal "$var" */
                char unknown[80];
                snprintf(unknown, sizeof(unknown), "$%s", var_name);
                add_item(out_fmt, APEX_LOG_ITEM_LITERAL, unknown, NULL);
            }
        } else {
            lit_buf[lit_len++] = *p++;
            if (lit_len >= sizeof(lit_buf) - 1) {
                lit_buf[lit_len] = '\0';
                add_item(out_fmt, APEX_LOG_ITEM_LITERAL, lit_buf, NULL);
                lit_len = 0;
            }
        }
    }

    if (lit_len > 0) {
        lit_buf[lit_len] = '\0';
        add_item(out_fmt, APEX_LOG_ITEM_LITERAL, lit_buf, NULL);
    }

    return 0;
}

void apex_log_format_free(apex_log_format_t *fmt) {
    if (fmt == NULL) return;
    free(fmt->items);
    fmt->items = NULL;
    fmt->item_count = 0;
    fmt->item_capacity = 0;
}

int apex_log_manager_init(apex_runtime_t *runtime) {
    if (runtime == NULL) return -1;

    apex_log_manager_t *mgr = calloc(1, sizeof(*mgr));
    if (mgr == NULL) return -1;

    pthread_mutex_init(&mgr->files_lock, NULL);

    /* Compile built-in formats */
    apex_log_format_compile("combined",
        "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"",
        &mgr->formats[mgr->format_count++]);

    apex_log_format_compile("common",
        "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent",
        &mgr->formats[mgr->format_count++]);

    /* Compile user-configured formats from config->http.log_formats */
    const apex_config_t *cfg = runtime->config;
    if (cfg != NULL) {
        for (size_t i = 0; i < cfg->http.log_format_count && mgr->format_count < (APEX_CONFIG_MAX_LOG_FORMATS + 2); i++) {
            apex_log_format_compile(cfg->http.log_formats[i].name,
                                    cfg->http.log_formats[i].format,
                                    &mgr->formats[mgr->format_count++]);
        }
    }

    runtime->log_manager = mgr;
    return 0;
}

static apex_log_file_t *get_or_open_log_file(apex_log_manager_t *mgr, const char *path) {
    if (mgr == NULL || path == NULL || path[0] == '\0') {
        return NULL;
    }

    pthread_mutex_lock(&mgr->files_lock);
    for (apex_log_file_t *f = mgr->files; f != NULL; f = f->next) {
        if (strcmp(f->path, path) == 0) {
            pthread_mutex_unlock(&mgr->files_lock);
            return f;
        }
    }

    /* Open new log file */
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        pthread_mutex_unlock(&mgr->files_lock);
        return NULL;
    }

    apex_log_file_t *new_file = calloc(1, sizeof(*new_file));
    if (new_file == NULL) {
        close(fd);
        pthread_mutex_unlock(&mgr->files_lock);
        return NULL;
    }

    strncpy(new_file->path, path, sizeof(new_file->path) - 1);
    new_file->fd = fd;
    pthread_mutex_init(&new_file->lock, NULL);
    new_file->next = mgr->files;
    mgr->files = new_file;

    pthread_mutex_unlock(&mgr->files_lock);
    return new_file;
}

static const apex_log_format_t *find_log_format(apex_log_manager_t *mgr, const char *name) {
    if (mgr == NULL) return NULL;
    const char *target = (name != NULL && name[0] != '\0') ? name : "combined";
    for (size_t i = 0; i < mgr->format_count; i++) {
        if (strcmp(mgr->formats[i].name, target) == 0) {
            return &mgr->formats[i];
        }
    }
    /* Fallback to combined if format not found */
    return &mgr->formats[0];
}

static void format_time_local(uint64_t time_us, char *out, size_t out_len) {
    time_t sec = time_us ? (time_t)(time_us / 1000000ULL) : time(NULL);
    struct tm tm_buf;
    localtime_r(&sec, &tm_buf);
    strftime(out, out_len, "%d/%b/%Y:%H:%M:%S %z", &tm_buf);
}

static void format_time_iso8601(uint64_t time_us, char *out, size_t out_len) {
    time_t sec = time_us ? (time_t)(time_us / 1000000ULL) : time(NULL);
    struct tm tm_buf;
    localtime_r(&sec, &tm_buf);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S%z", &tm_buf);
    size_t len = strlen(buf);
    if (len >= 5 && (buf[len - 5] == '+' || buf[len - 5] == '-')) {
        snprintf(out, out_len, "%.*s:%.2s", (int)(len - 2), buf, buf + len - 2);
    } else {
        snprintf(out, out_len, "%s", buf);
    }
}

void apex_access_log_write(apex_runtime_t *runtime, const apex_location_config_t *location,
                           const apex_server_config_t *server, const apex_log_ctx_t *ctx) {
    if (runtime == NULL || runtime->log_manager == NULL || ctx == NULL) {
        return;
    }
    apex_log_manager_t *mgr = (apex_log_manager_t *)runtime->log_manager;

    /* Determine effective access_log configuration */
    const apex_access_log_config_t *log_cfg = NULL;
    if (location != NULL && location->has_access_log) {
        log_cfg = &location->access_log;
    } else if (server != NULL && server->has_access_log) {
        log_cfg = &server->access_log;
    } else if (runtime->config != NULL && runtime->config->http.has_access_log) {
        log_cfg = &runtime->config->http.access_log;
    }

    if (log_cfg == NULL || log_cfg->off || log_cfg->path[0] == '\0') {
        return;
    }

    apex_log_file_t *file = get_or_open_log_file(mgr, log_cfg->path);
    if (file == NULL) {
        return;
    }

    const apex_log_format_t *fmt = find_log_format(mgr, log_cfg->format_name);
    if (fmt == NULL) {
        return;
    }

    /* Build the log line */
    char line[APEX_LOG_LINE_MAX];
    size_t line_len = 0;

    for (size_t i = 0; i < fmt->item_count && line_len < sizeof(line) - 2; i++) {
        const apex_log_item_t *item = &fmt->items[i];
        char temp[512];
        const char *val_str = NULL;

        switch (item->type) {
            case APEX_LOG_VAR_REMOTE_ADDR:
                val_str = (ctx->client_ip && ctx->client_ip[0]) ? ctx->client_ip : "-";
                break;
            case APEX_LOG_VAR_REMOTE_USER:
                val_str = "-";
                break;
            case APEX_LOG_VAR_TIME_LOCAL:
                format_time_local(ctx->start_time_us, temp, sizeof(temp));
                val_str = temp;
                break;
            case APEX_LOG_VAR_TIME_ISO8601:
                format_time_iso8601(ctx->start_time_us, temp, sizeof(temp));
                val_str = temp;
                break;
            case APEX_LOG_VAR_REQUEST: {
                char req_method[16] = "-";
                char req_uri[256] = "-";
                if (ctx->method && ctx->method_len) {
                    size_t ml = ctx->method_len < sizeof(req_method) - 1 ? ctx->method_len : sizeof(req_method) - 1;
                    memcpy(req_method, ctx->method, ml);
                    req_method[ml] = '\0';
                }
                if (ctx->uri && ctx->uri_len) {
                    size_t ul = ctx->uri_len < sizeof(req_uri) - 1 ? ctx->uri_len : sizeof(req_uri) - 1;
                    memcpy(req_uri, ctx->uri, ul);
                    req_uri[ul] = '\0';
                }
                snprintf(temp, sizeof(temp), "%s %s %s", req_method, req_uri,
                         ctx->protocol ? ctx->protocol : "HTTP/1.1");
                val_str = temp;
                break;
            }
            case APEX_LOG_VAR_REQUEST_METHOD: {
                if (ctx->method && ctx->method_len) {
                    size_t ml = ctx->method_len < sizeof(temp) - 1 ? ctx->method_len : sizeof(temp) - 1;
                    memcpy(temp, ctx->method, ml);
                    temp[ml] = '\0';
                    val_str = temp;
                } else {
                    val_str = "-";
                }
                break;
            }
            case APEX_LOG_VAR_REQUEST_URI: {
                if (ctx->uri && ctx->uri_len) {
                    size_t ul = ctx->uri_len < sizeof(temp) - 1 ? ctx->uri_len : sizeof(temp) - 1;
                    memcpy(temp, ctx->uri, ul);
                    temp[ul] = '\0';
                    val_str = temp;
                } else {
                    val_str = "-";
                }
                break;
            }
            case APEX_LOG_VAR_SERVER_PROTOCOL:
                val_str = ctx->protocol ? ctx->protocol : "HTTP/1.1";
                break;
            case APEX_LOG_VAR_STATUS:
                snprintf(temp, sizeof(temp), "%d", ctx->status);
                val_str = temp;
                break;
            case APEX_LOG_VAR_BODY_BYTES_SENT:
                snprintf(temp, sizeof(temp), "%zu", ctx->body_bytes_sent);
                val_str = temp;
                break;
            case APEX_LOG_VAR_BYTES_SENT:
                snprintf(temp, sizeof(temp), "%zu", ctx->bytes_sent);
                val_str = temp;
                break;
            case APEX_LOG_VAR_HTTP_REFERER:
                if (extract_header(ctx->raw_request, ctx->raw_request_len, "Referer", temp, sizeof(temp))) {
                    val_str = temp;
                } else {
                    val_str = "-";
                }
                break;
            case APEX_LOG_VAR_HTTP_USER_AGENT:
                if (extract_header(ctx->raw_request, ctx->raw_request_len, "User-Agent", temp, sizeof(temp))) {
                    val_str = temp;
                } else {
                    val_str = "-";
                }
                break;
            case APEX_LOG_VAR_UPSTREAM_ADDR:
                val_str = (ctx->upstream_addr && ctx->upstream_addr[0]) ? ctx->upstream_addr : "-";
                break;
            case APEX_LOG_VAR_UPSTREAM_STATUS:
                if (ctx->upstream_status > 0) {
                    snprintf(temp, sizeof(temp), "%d", ctx->upstream_status);
                    val_str = temp;
                } else {
                    val_str = "-";
                }
                break;
            case APEX_LOG_VAR_UPSTREAM_RESPONSE_TIME:
                if (ctx->upstream_time_us > 0) {
                    snprintf(temp, sizeof(temp), "%.3f", (double)ctx->upstream_time_us / 1000000.0);
                    val_str = temp;
                } else {
                    val_str = "-";
                }
                break;
            case APEX_LOG_VAR_REQUEST_TIME: {
                uint64_t dur = (ctx->end_time_us > ctx->start_time_us) ? (ctx->end_time_us - ctx->start_time_us) : 0;
                snprintf(temp, sizeof(temp), "%.3f", (double)dur / 1000000.0);
                val_str = temp;
                break;
            }
            case APEX_LOG_VAR_HTTP_CUSTOM:
                if (extract_header(ctx->raw_request, ctx->raw_request_len, item->custom_header, temp, sizeof(temp))) {
                    val_str = temp;
                } else {
                    val_str = "-";
                }
                break;
            case APEX_LOG_ITEM_LITERAL:
                val_str = item->literal;
                break;
        }

        if (val_str != NULL) {
            size_t vlen = strlen(val_str);
            if (line_len + vlen < sizeof(line) - 2) {
                memcpy(line + line_len, val_str, vlen);
                line_len += vlen;
            }
        }
    }

    line[line_len++] = '\n';
    line[line_len] = '\0';

    /* Buffered thread-safe write to file */
    pthread_mutex_lock(&file->lock);
    if (file->buffer_len + line_len > sizeof(file->buffer)) {
        if (file->buffer_len > 0) {
            ssize_t written = write(file->fd, file->buffer, file->buffer_len);
            (void)written;
            file->buffer_len = 0;
        }
    }

    if (file->buffer_len + line_len <= sizeof(file->buffer)) {
        memcpy(file->buffer + file->buffer_len, line, line_len);
        file->buffer_len += line_len;
    }

    if (log_cfg->buffer_size == 0 && file->buffer_len > 0) {
        /* Immediate flush if unbuffered */
        ssize_t written = write(file->fd, file->buffer, file->buffer_len);
        (void)written;
        file->buffer_len = 0;
    }
    pthread_mutex_unlock(&file->lock);
}

void apex_access_log_flush_all(apex_runtime_t *runtime) {
    if (runtime == NULL || runtime->log_manager == NULL) return;
    apex_log_manager_t *mgr = (apex_log_manager_t *)runtime->log_manager;

    pthread_mutex_lock(&mgr->files_lock);
    for (apex_log_file_t *f = mgr->files; f != NULL; f = f->next) {
        pthread_mutex_lock(&f->lock);
        if (f->buffer_len > 0 && f->fd >= 0) {
            ssize_t written = write(f->fd, f->buffer, f->buffer_len);
            (void)written;
            f->buffer_len = 0;
        }
        pthread_mutex_unlock(&f->lock);
    }
    pthread_mutex_unlock(&mgr->files_lock);
}

void apex_log_manager_destroy(apex_runtime_t *runtime) {
    if (runtime == NULL || runtime->log_manager == NULL) return;
    apex_log_manager_t *mgr = (apex_log_manager_t *)runtime->log_manager;

    apex_access_log_flush_all(runtime);

    pthread_mutex_lock(&mgr->files_lock);
    apex_log_file_t *cur = mgr->files;
    while (cur != NULL) {
        apex_log_file_t *next = cur->next;
        if (cur->fd >= 0) {
            close(cur->fd);
            cur->fd = -1;
        }
        pthread_mutex_destroy(&cur->lock);
        free(cur);
        cur = next;
    }
    mgr->files = NULL;
    pthread_mutex_unlock(&mgr->files_lock);

    for (size_t i = 0; i < mgr->format_count; i++) {
        apex_log_format_free(&mgr->formats[i]);
    }

    pthread_mutex_destroy(&mgr->files_lock);
    free(mgr);
    runtime->log_manager = NULL;
}
