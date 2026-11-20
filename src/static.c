#include "apex/static.h"
#include "apex/config.h"
#include "internal.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    const char *extension;
    const char *mime_type;
} mime_map_entry_t;

static const mime_map_entry_t MIME_TABLE[] = {
    {".avif", "image/avif"},
    {".bin", "application/octet-stream"},
    {".br", "application/x-brotli"},
    {".css", "text/css; charset=utf-8"},
    {".csv", "text/csv; charset=utf-8"},
    {".eot", "application/vnd.ms-fontobject"},
    {".gif", "image/gif"},
    {".gz", "application/gzip"},
    {".htm", "text/html; charset=utf-8"},
    {".html", "text/html; charset=utf-8"},
    {".ico", "image/x-icon"},
    {".jpeg", "image/jpeg"},
    {".jpg", "image/jpeg"},
    {".js", "application/javascript; charset=utf-8"},
    {".json", "application/json"},
    {".map", "application/json"},
    {".md", "text/markdown; charset=utf-8"},
    {".mjs", "application/javascript; charset=utf-8"},
    {".mp3", "audio/mpeg"},
    {".mp4", "video/mp4"},
    {".ogg", "audio/ogg"},
    {".otf", "font/otf"},
    {".pdf", "application/pdf"},
    {".png", "image/png"},
    {".svg", "image/svg+xml"},
    {".svgz", "image/svg+xml"},
    {".tar", "application/x-tar"},
    {".ttf", "font/ttf"},
    {".txt", "text/plain; charset=utf-8"},
    {".wasm", "application/wasm"},
    {".webm", "video/webm"},
    {".webp", "image/webp"},
    {".woff", "font/woff"},
    {".woff2", "font/woff2"},
    {".xml", "application/xml"},
    {".zip", "application/zip"},
    {".zst", "application/zstd"},
};

#define MIME_TABLE_SIZE (sizeof(MIME_TABLE) / sizeof(MIME_TABLE[0]))

const char *apex_mime_type(const char *path) {
    if (path == NULL) {
        return "application/octet-stream";
    }

    const char *dot = strrchr(path, '.');
    if (dot == NULL || dot == path) {
        return "application/octet-stream";
    }

    for (size_t index = 0; index < MIME_TABLE_SIZE; index++) {
        if (strcasecmp(dot, MIME_TABLE[index].extension) == 0) {
            return MIME_TABLE[index].mime_type;
        }
    }
    return "application/octet-stream";
}

#define APEX_STATIC_CACHE_SLOTS 512
#define APEX_STATIC_CACHE_MAX_BYTES (64 * 1024) /* 64 KB */
#define APEX_STATIC_CACHE_TTL 10 /* seconds */

typedef struct {
    char target_path[APEX_CONFIG_PATH_MAX * 2];
    time_t expires_at;
    time_t mtime;
    size_t size;
    char etag[64];
    char last_modified[64];
    const char *content_type;
    const char *content_encoding;
    char *in_memory_data;
    size_t in_memory_len;
} apex_static_cache_entry_t;

typedef struct {
    apex_static_cache_entry_t entries[APEX_STATIC_CACHE_SLOTS];
} apex_static_cache_t;

static __thread apex_static_cache_t s_thread_cache;

static inline uint32_t static_cache_hash(const char *str, size_t len) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint8_t)str[i];
        hash *= 16777619u;
    }
    return hash % APEX_STATIC_CACHE_SLOTS;
}

void apex_static_cache_flush(void) {
    for (size_t i = 0; i < APEX_STATIC_CACHE_SLOTS; i++) {
        if (s_thread_cache.entries[i].in_memory_data != NULL) {
            free(s_thread_cache.entries[i].in_memory_data);
            s_thread_cache.entries[i].in_memory_data = NULL;
        }
        s_thread_cache.entries[i].target_path[0] = '\0';
        s_thread_cache.entries[i].expires_at = 0;
    }
}

void apex_static_format_etag(time_t mtime, off_t size, char *out, size_t out_size) {
    if (out == NULL || out_size == 0) {
        return;
    }
    snprintf(out, out_size, "\"%lx-%lx\"", (unsigned long)mtime, (unsigned long)size);
}

void apex_static_format_http_date(time_t time_val, char *out, size_t out_size) {
    if (out == NULL || out_size == 0) {
        return;
    }
    struct tm tm_buf;
    if (gmtime_r(&time_val, &tm_buf) == NULL) {
        out[0] = '\0';
        return;
    }
    strftime(out, out_size, "%a, %d %b %Y %H:%M:%S GMT", &tm_buf);
}

bool apex_static_parse_http_date(const char *str, size_t len, time_t *out_time) {
    if (str == NULL || len == 0 || out_time == NULL) {
        return false;
    }

    char temp[64];
    if (len >= sizeof(temp)) {
        return false;
    }
    memcpy(temp, str, len);
    temp[len] = '\0';

    struct tm tm_buf = {0};
    char *parsed = strptime(temp, "%a, %d %b %Y %H:%M:%S GMT", &tm_buf);
    if (parsed == NULL) {
        parsed = strptime(temp, "%A, %d-%b-%y %H:%M:%S GMT", &tm_buf);
    }
    if (parsed == NULL) {
        parsed = strptime(temp, "%a %b %e %H:%M:%S %Y", &tm_buf);
    }
    if (parsed == NULL) {
        return false;
    }

    time_t result = timegm(&tm_buf);
    if (result == (time_t)-1) {
        return false;
    }
    *out_time = result;
    return true;
}

static const char *static_find_crlf(const char *data, size_t length) {
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

static bool static_find_header(const char *buffer, size_t length, const char *name,
                               const char **value, size_t *value_length) {
    const char *first_end = static_find_crlf(buffer, length);
    if (first_end == NULL) {
        return false;
    }

    size_t name_len = strlen(name);
    size_t position = (size_t)(first_end - buffer) + 2u;
    while (position < length) {
        const char *line = buffer + position;
        const char *line_end = static_find_crlf(line, length - position);
        if (line_end == NULL) {
            return false;
        }
        size_t line_length = (size_t)(line_end - line);
        if (line_length == 0) {
            return false;
        }

        const char *colon = memchr(line, ':', line_length);
        if (colon != NULL) {
            size_t field_len = (size_t)(colon - line);
            while (field_len > 0 && (line[field_len - 1u] == ' ' || line[field_len - 1u] == '\t')) {
                field_len--;
            }
            if (field_len == name_len && strncasecmp(line, name, name_len) == 0) {
                const char *val_start = colon + 1;
                const char *val_end = line + line_length;
                while (val_start < val_end && (*val_start == ' ' || *val_start == '\t')) {
                    val_start++;
                }
                while (val_end > val_start && (val_end[-1] == ' ' || val_end[-1] == '\t')) {
                    val_end--;
                }
                *value = val_start;
                *value_length = (size_t)(val_end - val_start);
                return true;
            }
        }
        position += line_length + 2u;
    }
    return false;
}

static bool static_decode_path(const char *src, size_t src_len, char *dst, size_t dst_capacity) {
    size_t src_idx = 0;
    size_t dst_idx = 0;

    while (src_idx < src_len) {
        if (dst_idx + 1 >= dst_capacity) {
            return false;
        }
        if (src[src_idx] == '%' && src_idx + 2 < src_len) {
            int high = src[src_idx + 1];
            int low = src[src_idx + 2];
            int high_val = isxdigit(high) ? (high >= 'a' ? high - 'a' + 10 : (high >= 'A' ? high - 'A' + 10 : high - '0')) : -1;
            int low_val = isxdigit(low) ? (low >= 'a' ? low - 'a' + 10 : (low >= 'A' ? low - 'A' + 10 : low - '0')) : -1;

            if (high_val >= 0 && low_val >= 0) {
                char ch = (char)((high_val << 4) | low_val);
                if (ch == '\0') {
                    return false; /* Disallow null byte in path */
                }
                dst[dst_idx++] = ch;
                src_idx += 3;
                continue;
            }
        }
        if (src[src_idx] == '\0') {
            return false;
        }
        dst[dst_idx++] = src[src_idx++];
    }
    dst[dst_idx] = '\0';
    return true;
}

static bool static_is_traversal(const char *path, size_t len) {
    for (size_t index = 0; index + 1 < len; index++) {
        if (path[index] == '.' && path[index + 1] == '.') {
            if (index + 2 == len || path[index + 2] == '/' || index == 0 || path[index - 1] == '/') {
                return true;
            }
        }
    }
    return false;
}

static size_t static_format_server_header(const apex_server_config_t *server, char *buf, size_t buf_cap) {
    if (server == NULL || !server->server_tokens.set || server->server_tokens.mode == APEX_SERVER_TOKENS_ON) {
        return (size_t)snprintf(buf, buf_cap, "Server: apex\r\n");
    }
    if (server->server_tokens.mode == APEX_SERVER_TOKENS_CUSTOM) {
        return (size_t)snprintf(buf, buf_cap, "Server: %s\r\n", server->server_tokens.custom_value);
    }
    /* APEX_SERVER_TOKENS_OFF */
    if (buf_cap > 0) {
        buf[0] = '\0';
    }
    return 0;
}

void apex_static_serve(const apex_server_config_t *server,
                       const apex_location_config_t *location,
                       const char *request, size_t request_len,
                       const char *path, size_t path_len,
                       bool head_request,
                       apex_res_t *res,
                       const char *extra_headers, size_t extra_headers_len) {
    char server_hdr[160];
    static_format_server_header(server, server_hdr, sizeof(server_hdr));
    conn_t *connection = res != NULL ? res->conn : NULL;
    if (connection == NULL || location == NULL || location->root == NULL || path == NULL) {
        router_send_error(connection, server, request, request_len, 404, "Not Found", "Not Found\n");
        return;
    }

    char decoded_path[APEX_CONFIG_PATH_MAX];
    if (!static_decode_path(path, path_len, decoded_path, sizeof(decoded_path))) {
        router_send_error(connection, server, request, request_len, 400, "Bad Request", "Invalid URI Encoding\n");
        return;
    }
    size_t decoded_len = strlen(decoded_path);

    if (static_is_traversal(decoded_path, decoded_len)) {
        router_send_error(connection, server, request, request_len, 403, "Forbidden", "Forbidden\n");
        return;
    }

    size_t root_len = strlen(location->root);
    size_t location_path_len = strlen(location->path);
    const char *relative_path = decoded_path;
    size_t relative_path_len = decoded_len;

    if (decoded_len >= location_path_len && strncmp(decoded_path, location->path, location_path_len) == 0) {
        relative_path = decoded_path + location_path_len;
        relative_path_len = decoded_len - location_path_len;
    }

    char file_path[APEX_CONFIG_PATH_MAX * 2];
    bool root_has_slash = root_len > 0 && location->root[root_len - 1] == '/';
    bool rel_has_slash = relative_path_len > 0 && relative_path[0] == '/';

    int written = 0;
    if (root_has_slash && rel_has_slash) {
        written = snprintf(file_path, sizeof(file_path), "%s%.*s", location->root,
                           (int)(relative_path_len - 1), relative_path + 1);
    } else if (!root_has_slash && !rel_has_slash && relative_path_len > 0) {
        written = snprintf(file_path, sizeof(file_path), "%s/%.*s", location->root,
                           (int)relative_path_len, relative_path);
    } else {
        written = snprintf(file_path, sizeof(file_path), "%s%.*s", location->root,
                           (int)relative_path_len, relative_path);
    }

    if (written < 0 || (size_t)written >= sizeof(file_path)) {
        router_send_error(connection, server, request, request_len, 414, "URI Too Long", "URI Too Long\n");
        return;
    }

    struct stat file_stat;
    bool found_candidate = false;

    if (stat(file_path, &file_stat) == 0) {
        found_candidate = true;
    }

    /* If try_files is configured and primary target not found, probe candidates */
    if (!found_candidate && location->try_files_count > 0) {
        for (size_t index = 0; index < location->try_files_count; index++) {
            const char *pattern = location->try_files[index];
            char candidate_path[APEX_CONFIG_PATH_MAX * 2];

            if (strcmp(pattern, "$uri") == 0) {
                snprintf(candidate_path, sizeof(candidate_path), "%s", file_path);
            } else if (strcmp(pattern, "$uri/") == 0) {
                snprintf(candidate_path, sizeof(candidate_path), "%s/", file_path);
            } else if (pattern[0] == '/') {
                snprintf(candidate_path, sizeof(candidate_path), "%s%s", location->root, pattern);
            } else {
                snprintf(candidate_path, sizeof(candidate_path), "%s/%s", location->root, pattern);
            }

            if (stat(candidate_path, &file_stat) == 0) {
                snprintf(file_path, sizeof(file_path), "%s", candidate_path);
                found_candidate = true;
                break;
            }
        }
    }

    if (!found_candidate) {
        router_send_error(connection, server, request, request_len, 404, "Not Found", "File Not Found\n");
        return;
    }

    /* Handle directory index resolution */
    if (S_ISDIR(file_stat.st_mode)) {
        bool resolved_index = false;
        size_t current_len = strlen(file_path);

        if (location->index_count > 0) {
            for (size_t i = 0; i < location->index_count; i++) {
                char candidate_index[APEX_CONFIG_PATH_MAX * 2];
                if (file_path[current_len - 1] == '/') {
                    snprintf(candidate_index, sizeof(candidate_index), "%s%s", file_path, location->indices[i]);
                } else {
                    snprintf(candidate_index, sizeof(candidate_index), "%s/%s", file_path, location->indices[i]);
                }

                if (stat(candidate_index, &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
                    snprintf(file_path, sizeof(file_path), "%s", candidate_index);
                    resolved_index = true;
                    break;
                }
            }
        } else {
            char candidate_index[APEX_CONFIG_PATH_MAX * 2];
            if (file_path[current_len - 1] == '/') {
                snprintf(candidate_index, sizeof(candidate_index), "%sindex.html", file_path);
            } else {
                snprintf(candidate_index, sizeof(candidate_index), "%s/index.html", file_path);
            }
            if (stat(candidate_index, &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
                snprintf(file_path, sizeof(file_path), "%s", candidate_index);
                resolved_index = true;
            }
        }

        if (!resolved_index) {
            router_send_error(connection, server, request, request_len, 404, "Not Found", "Directory index not found\n");
            return;
        }
    }

    if (!S_ISREG(file_stat.st_mode)) {
        router_send_error(connection, server, request, request_len, 403, "Forbidden", "Not a regular file\n");
        return;
    }

    /* Content-Type detection based on logical file path (not compressed twin extension) */
    const char *content_type = apex_mime_type(file_path);

    /* Pre-compressed twin selection (.br, .zst, .gz) */
    const char *content_encoding = NULL;
    char target_path[APEX_CONFIG_PATH_MAX * 2];
    snprintf(target_path, sizeof(target_path), "%s", file_path);
    struct stat target_stat = file_stat;

    const char *accept_encoding = NULL;
    size_t accept_encoding_len = 0;
    if (request != NULL && request_len > 0) {
        static_find_header(request, request_len, "Accept-Encoding", &accept_encoding, &accept_encoding_len);
    }

    if (location->precompressed && accept_encoding != NULL && accept_encoding_len > 0) {
        char twin_path[APEX_CONFIG_PATH_MAX * 2];
        struct stat twin_stat;

        if (memmem(accept_encoding, accept_encoding_len, "br", 2) != NULL) {
            snprintf(twin_path, sizeof(twin_path), "%s.br", file_path);
            if (stat(twin_path, &twin_stat) == 0 && S_ISREG(twin_stat.st_mode) &&
                twin_stat.st_mtime >= file_stat.st_mtime) {
                snprintf(target_path, sizeof(target_path), "%s", twin_path);
                target_stat = twin_stat;
                content_encoding = "br";
            }
        }
        if (content_encoding == NULL && memmem(accept_encoding, accept_encoding_len, "zstd", 4) != NULL) {
            snprintf(twin_path, sizeof(twin_path), "%s.zst", file_path);
            if (stat(twin_path, &twin_stat) == 0 && S_ISREG(twin_stat.st_mode) &&
                twin_stat.st_mtime >= file_stat.st_mtime) {
                snprintf(target_path, sizeof(target_path), "%s", twin_path);
                target_stat = twin_stat;
                content_encoding = "zstd";
            }
        }
        if (content_encoding == NULL && memmem(accept_encoding, accept_encoding_len, "gzip", 4) != NULL) {
            snprintf(twin_path, sizeof(twin_path), "%s.gz", file_path);
            if (stat(twin_path, &twin_stat) == 0 && S_ISREG(twin_stat.st_mode) &&
                twin_stat.st_mtime >= file_stat.st_mtime) {
                snprintf(target_path, sizeof(target_path), "%s", twin_path);
                target_stat = twin_stat;
                content_encoding = "gzip";
            }
        }
    }

    /* Cache Validation: ETag and Last-Modified (using thread-local in-memory cache) */
    time_t now = time(NULL);
    size_t tpath_len = strlen(target_path);
    uint32_t slot = static_cache_hash(target_path, tpath_len);
    apex_static_cache_entry_t *cached = &s_thread_cache.entries[slot];

    char etag_str[64] = {0};
    char last_mod_str[64] = {0};
    size_t total_size = 0;
    char *cached_memory = NULL;

    if (cached->target_path[0] != '\0' && strcmp(cached->target_path, target_path) == 0 &&
        now < cached->expires_at) {
        total_size = cached->size;
        memcpy(etag_str, cached->etag, sizeof(etag_str));
        memcpy(last_mod_str, cached->last_modified, sizeof(last_mod_str));
        content_type = cached->content_type;
        content_encoding = cached->content_encoding;
        cached_memory = cached->in_memory_data;
    } else {
        apex_static_format_etag(file_stat.st_mtime, file_stat.st_size, etag_str, sizeof(etag_str));
        apex_static_format_http_date(file_stat.st_mtime, last_mod_str, sizeof(last_mod_str));
        total_size = (size_t)target_stat.st_size;

        if (cached->in_memory_data != NULL) {
            free(cached->in_memory_data);
            cached->in_memory_data = NULL;
        }
        snprintf(cached->target_path, sizeof(cached->target_path), "%s", target_path);
        cached->expires_at = now + APEX_STATIC_CACHE_TTL;
        cached->mtime = file_stat.st_mtime;
        cached->size = total_size;
        memcpy(cached->etag, etag_str, sizeof(cached->etag));
        memcpy(cached->last_modified, last_mod_str, sizeof(cached->last_modified));
        cached->content_type = content_type;
        cached->content_encoding = content_encoding;
        cached->in_memory_len = 0;

        if (total_size > 0 && total_size <= APEX_STATIC_CACHE_MAX_BYTES) {
            int pre_fd = open(target_path, O_RDONLY | O_CLOEXEC);
            if (pre_fd >= 0) {
                char *buf = malloc(total_size);
                if (buf != NULL) {
                    ssize_t rd = read(pre_fd, buf, total_size);
                    if (rd == (ssize_t)total_size) {
                        cached->in_memory_data = buf;
                        cached->in_memory_len = total_size;
                        cached_memory = buf;
                    } else {
                        free(buf);
                    }
                }
                close(pre_fd);
            }
        }
    }

    if (location->etag && request != NULL && request_len > 0) {
        const char *if_none_match = NULL;
        size_t if_none_match_len = 0;
        if (static_find_header(request, request_len, "If-None-Match", &if_none_match, &if_none_match_len)) {
            if (if_none_match_len > 0) {
                if ((if_none_match_len == 1 && if_none_match[0] == '*') ||
                    (if_none_match_len == strlen(etag_str) &&
                     strncmp(if_none_match, etag_str, if_none_match_len) == 0)) {
                    /* 304 Not Modified */
                    char header_buf[1024];
                    int hlen = snprintf(header_buf, sizeof(header_buf),
                                        "HTTP/1.1 304 Not Modified\r\n"
                                        "%s"
                                        "ETag: %s\r\n"
                                        "Last-Modified: %s\r\n"
                                        "Connection: %s\r\n"
                                        "%.*s"
                                        "\r\n",
                                        server_hdr,
                                        etag_str, last_mod_str,
                                        connection->close_after_write ? "close" : "keep-alive",
                                        (int)extra_headers_len, extra_headers ? extra_headers : "");
                    if (hlen > 0 && (size_t)hlen < sizeof(header_buf)) {
                        apex_conn_write(connection, header_buf, (size_t)hlen);
                        apex_record_status(304);
                        if (res != NULL) {
                            res->last_status = 304;
                            res->last_body_bytes = 0;
                        }
                    }
                    return;
                }
            }
        }

        const char *if_mod_since = NULL;
        size_t if_mod_since_len = 0;
        if (static_find_header(request, request_len, "If-Modified-Since", &if_mod_since, &if_mod_since_len)) {
            time_t client_time;
            if (apex_static_parse_http_date(if_mod_since, if_mod_since_len, &client_time)) {
                if (file_stat.st_mtime <= client_time) {
                    /* 304 Not Modified */
                    char header_buf[1024];
                    int hlen = snprintf(header_buf, sizeof(header_buf),
                                        "HTTP/1.1 304 Not Modified\r\n"
                                        "%s"
                                        "ETag: %s\r\n"
                                        "Last-Modified: %s\r\n"
                                        "Connection: %s\r\n"
                                        "%.*s"
                                        "\r\n",
                                        server_hdr,
                                        etag_str, last_mod_str,
                                        connection->close_after_write ? "close" : "keep-alive",
                                        (int)extra_headers_len, extra_headers ? extra_headers : "");
                    if (hlen > 0 && (size_t)hlen < sizeof(header_buf)) {
                        apex_conn_write(connection, header_buf, (size_t)hlen);
                        apex_record_status(304);
                        if (res != NULL) {
                            res->last_status = 304;
                            res->last_body_bytes = 0;
                        }
                    }
                    return;
                }
            }
        }
    }

    off_t range_start = 0;
    size_t send_length = total_size;
    bool is_range = false;

    const char *range_hdr = NULL;
    size_t range_hdr_len = 0;
    if (request != NULL && request_len > 0 && content_encoding == NULL &&
        static_find_header(request, request_len, "Range", &range_hdr, &range_hdr_len)) {
        if (range_hdr_len > 6 && strncmp(range_hdr, "bytes=", 6) == 0) {
            const char *range_spec = range_hdr + 6;
            size_t spec_len = range_hdr_len - 6;
            const char *dash = memchr(range_spec, '-', spec_len);
            if (dash != NULL) {
                long long start = -1;
                long long end = -1;
                if (dash > range_spec) {
                    start = strtoll(range_spec, NULL, 10);
                }
                if ((size_t)(dash + 1 - range_spec) < spec_len) {
                    end = strtoll(dash + 1, NULL, 10);
                }

                if (start >= 0 && end >= start && (size_t)start < total_size) {
                    if ((size_t)end >= total_size) {
                        end = (long long)(total_size - 1);
                    }
                    range_start = (off_t)start;
                    send_length = (size_t)(end - start + 1);
                    is_range = true;
                } else if (start >= 0 && end < 0 && (size_t)start < total_size) {
                    range_start = (off_t)start;
                    send_length = total_size - (size_t)start;
                    is_range = true;
                } else if (start < 0 && end > 0) {
                    if ((size_t)end > total_size) {
                        end = (long long)total_size;
                    }
                    range_start = (off_t)(total_size - (size_t)end);
                    send_length = (size_t)end;
                    is_range = true;
                } else {
                    /* 416 Range Not Satisfiable */
                    char h416[512];
                    int n416 = snprintf(h416, sizeof(h416),
                                       "HTTP/1.1 416 Range Not Satisfiable\r\n"
                                       "%s"
                                       "Content-Range: bytes */%zu\r\n"
                                       "Content-Length: 0\r\n"
                                       "Connection: %s\r\n"
                                       "\r\n",
                                       server_hdr,
                                       total_size,
                                       connection->close_after_write ? "close" : "keep-alive");
                    if (n416 > 0 && (size_t)n416 < sizeof(h416)) {
                        apex_conn_write(connection, h416, (size_t)n416);
                        apex_record_status(416);
                        if (res != NULL) {
                            res->last_status = 416;
                            res->last_body_bytes = 0;
                        }
                    }
                    return;
                }
            }
        }
    }

    char header_buffer[2048];
    int header_len = 0;

    if (is_range) {
        header_len = snprintf(header_buffer, sizeof(header_buffer),
                              "HTTP/1.1 206 Partial Content\r\n"
                              "%s"
                              "Content-Type: %s\r\n"
                              "Content-Length: %zu\r\n"
                              "Content-Range: bytes %zu-%zu/%zu\r\n"
                              "Accept-Ranges: bytes\r\n"
                              "ETag: %s\r\n"
                              "Last-Modified: %s\r\n"
                              "Connection: %s\r\n"
                              "%.*s"
                              "\r\n",
                              server_hdr,
                              content_type, send_length,
                              (size_t)range_start, (size_t)(range_start + (off_t)send_length - 1), total_size,
                              etag_str, last_mod_str,
                              connection->close_after_write ? "close" : "keep-alive",
                              (int)extra_headers_len, extra_headers ? extra_headers : "");
    } else {
        header_len = snprintf(header_buffer, sizeof(header_buffer),
                              "HTTP/1.1 200 OK\r\n"
                              "%s"
                              "Content-Type: %s\r\n"
                              "Content-Length: %zu\r\n"
                              "Accept-Ranges: bytes\r\n"
                              "ETag: %s\r\n"
                              "Last-Modified: %s\r\n"
                              "%s%s%s"
                              "%s"
                              "Connection: %s\r\n"
                              "%.*s"
                              "\r\n",
                              server_hdr,
                              content_type, send_length,
                              etag_str, last_mod_str,
                              content_encoding ? "Content-Encoding: " : "",
                              content_encoding ? content_encoding : "",
                              content_encoding ? "\r\n" : "",
                              content_encoding ? "Vary: Accept-Encoding\r\n" : "",
                              connection->close_after_write ? "close" : "keep-alive",
                              (int)extra_headers_len, extra_headers ? extra_headers : "");
    }

    if (header_len > 0 && (size_t)header_len < sizeof(header_buffer)) {
        apex_conn_write(connection, header_buffer, (size_t)header_len);
        apex_record_status(is_range ? 206 : 200);
        if (res != NULL) {
            res->last_status = is_range ? 206 : 200;
            res->last_body_bytes = head_request ? 0 : send_length;
        }
        if (!head_request && send_length > 0) {
            if (cached_memory != NULL) {
                apex_conn_write(connection, cached_memory + range_start, send_length);
                return;
            }
            int file_fd = open(target_path, O_RDONLY | O_CLOEXEC);
            if (file_fd >= 0) {
                apex_conn_sendfile(connection, file_fd, range_start, send_length);
                return;
            }
            router_send_error(connection, server, request, request_len, 403, "Forbidden", "Permission Denied\n");
            return;
        }
    }
}
