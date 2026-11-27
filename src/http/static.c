#include "apex/static.h"
#include "apex/config.h"
#include "apex/file_cache.h"
#include "apex/http_util.h"
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
    char logical_path[APEX_CONFIG_PATH_MAX * 2];
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
    char header_keepalive[512];
    size_t header_keepalive_len;
    char header_close[512];
    size_t header_close_len;
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
        s_thread_cache.entries[i].logical_path[0] = '\0';
        s_thread_cache.entries[i].target_path[0] = '\0';
        s_thread_cache.entries[i].expires_at = 0;
        s_thread_cache.entries[i].header_keepalive_len = 0;
        s_thread_cache.entries[i].header_close_len = 0;
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


static bool static_etag_matches(const char *hdr_val, size_t hdr_len, const char *etag_str, bool weak_allowed) {
    if (hdr_val == NULL || hdr_len == 0 || etag_str == NULL) {
        return false;
    }
    const char *p = hdr_val;
    const char *end = hdr_val + hdr_len;
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    if (p < end && *p == '*' && (p + 1 == end || p[1] == ' ' || p[1] == '\t' || p[1] == ',')) {
        return true;
    }

    const char *target_opaque = etag_str;
    size_t target_opaque_len = strlen(etag_str);
    if (target_opaque_len >= 2 && target_opaque[0] == '"' && target_opaque[target_opaque_len - 1] == '"') {
        target_opaque++;
        target_opaque_len -= 2;
    }

    p = hdr_val;
    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) p++;
        if (p >= end) break;

        const char *tag_start = p;
        const char *tag_end = memchr(p, ',', (size_t)(end - p));
        if (tag_end == NULL) tag_end = end;
        p = tag_end;

        while (tag_end > tag_start && (tag_end[-1] == ' ' || tag_end[-1] == '\t')) {
            tag_end--;
        }
        size_t tag_len = (size_t)(tag_end - tag_start);
        if (tag_len == 0) continue;

        if (tag_len == 1 && tag_start[0] == '*') {
            return true;
        }

        bool is_weak = false;
        if (tag_len >= 2 && (tag_start[0] == 'W' || tag_start[0] == 'w') && tag_start[1] == '/') {
            is_weak = true;
            tag_start += 2;
            tag_len -= 2;
        }

        if (is_weak && !weak_allowed) {
            continue;
        }

        if (tag_len >= 2 && tag_start[0] == '"' && tag_start[tag_len - 1] == '"') {
            tag_start++;
            tag_len -= 2;
        }

        if (tag_len == target_opaque_len && memcmp(tag_start, target_opaque, tag_len) == 0) {
            return true;
        }
    }
    return false;
}

static inline bool static_decode_path(const char *src, size_t src_len, char *dst, size_t dst_capacity) {
    return apex_uri_decode(src, src_len, dst, dst_capacity);
}

static inline bool static_is_traversal(const char *path, size_t len) {
    return apex_uri_is_traversal(path, len);
}

typedef enum {
    STATIC_PRECOND_PROCEED = 0,
    STATIC_PRECOND_FAILED = 1,
    STATIC_PRECOND_NOT_MODIFIED = 2
} static_precond_result_t;

typedef enum {
    STATIC_RANGE_NONE = 0,
    STATIC_RANGE_OK = 1,
    STATIC_RANGE_NOT_SATISFIABLE = 2
} static_range_result_t;

/* Helper 1: Resolve URI path against location root and prevent directory traversal */
static int static_resolve_path(const apex_location_config_t *location,
                               const char *path, size_t path_len,
                               char *file_path, size_t file_path_cap) {
    char decoded_path[APEX_CONFIG_PATH_MAX];
    if (!static_decode_path(path, path_len, decoded_path, sizeof(decoded_path))) {
        return 400; /* Bad Request */
    }
    size_t decoded_len = strlen(decoded_path);

    if (static_is_traversal(decoded_path, decoded_len)) {
        return 403; /* Forbidden */
    }

    size_t root_len = strlen(location->root);
    size_t location_path_len = strlen(location->path);
    const char *relative_path = decoded_path;
    size_t relative_path_len = decoded_len;

    if (decoded_len >= location_path_len && strncmp(decoded_path, location->path, location_path_len) == 0) {
        if (location_path_len == 0 ||
            location->path[location_path_len - 1] == '/' ||
            decoded_path[location_path_len] == '/' ||
            decoded_path[location_path_len] == '\0') {
            relative_path = decoded_path + location_path_len;
            relative_path_len = decoded_len - location_path_len;
        } else {
            return 404; /* Prefix mismatch on path segment boundary */
        }
    }

    bool root_has_slash = root_len > 0 && location->root[root_len - 1] == '/';
    bool rel_has_slash = relative_path_len > 0 && relative_path[0] == '/';

    int written = 0;
    if (root_has_slash && rel_has_slash) {
        written = snprintf(file_path, file_path_cap, "%s%.*s", location->root,
                           (int)(relative_path_len - 1), relative_path + 1);
    } else if (!root_has_slash && !rel_has_slash && relative_path_len > 0) {
        written = snprintf(file_path, file_path_cap, "%s/%.*s", location->root,
                           (int)relative_path_len, relative_path);
    } else {
        written = snprintf(file_path, file_path_cap, "%s%.*s", location->root,
                           (int)relative_path_len, relative_path);
    }

    if (written < 0 || (size_t)written >= file_path_cap) {
        return 414; /* URI Too Long */
    }

    return 0;
}

/* Helper 2: Negotiate encoding from Accept-Encoding header */
static const char *static_detect_requested_encoding(const apex_location_config_t *location,
                                                    const char *request, size_t request_len,
                                                    const char **out_accept_hdr,
                                                    size_t *out_accept_len) {
    *out_accept_hdr = NULL;
    *out_accept_len = 0;
    if (!location->precompressed || request == NULL || request_len == 0) {
        return "id";
    }

    apex_http_find_header(request, request_len, "Accept-Encoding", out_accept_hdr, out_accept_len);
    if (*out_accept_hdr == NULL || *out_accept_len == 0) {
        return "id";
    }

    if (memmem(*out_accept_hdr, *out_accept_len, "br", 2) != NULL) {
        return "br";
    }
    if (memmem(*out_accept_hdr, *out_accept_len, "zstd", 4) != NULL) {
        return "zstd";
    }
    if (memmem(*out_accept_hdr, *out_accept_len, "gzip", 4) != NULL) {
        return "gzip";
    }

    return "id";
}

/* Helper 3: Probe file candidates, try_files patterns, and directory index files */
static bool static_resolve_candidate_file(const apex_location_config_t *location,
                                          char *file_path, size_t file_path_cap,
                                          struct stat *file_stat) {
    bool found_candidate = (stat(file_path, file_stat) == 0);

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

            if (stat(candidate_path, file_stat) == 0) {
                snprintf(file_path, file_path_cap, "%s", candidate_path);
                found_candidate = true;
                break;
            }
        }
    }

    if (!found_candidate) {
        return false;
    }

    if (S_ISDIR(file_stat->st_mode)) {
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

                if (stat(candidate_index, file_stat) == 0 && S_ISREG(file_stat->st_mode)) {
                    snprintf(file_path, file_path_cap, "%s", candidate_index);
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
            if (stat(candidate_index, file_stat) == 0 && S_ISREG(file_stat->st_mode)) {
                snprintf(file_path, file_path_cap, "%s", candidate_index);
                resolved_index = true;
            }
        }

        if (!resolved_index) {
            return false;
        }
    }

    return S_ISREG(file_stat->st_mode);
}

/* Helper 4: Select precompressed twin file (.br, .zst, .gz) */
static void static_select_twin_precompressed(const apex_location_config_t *location,
                                             const char *accept_encoding, size_t accept_encoding_len,
                                             const char *file_path, const struct stat *file_stat,
                                             char *target_path, size_t target_path_cap,
                                             struct stat *target_stat,
                                             const char **out_encoding) {
    snprintf(target_path, target_path_cap, "%s", file_path);
    *target_stat = *file_stat;
    *out_encoding = NULL;

    if (!location->precompressed || accept_encoding == NULL || accept_encoding_len == 0) {
        return;
    }

    char twin_path[APEX_CONFIG_PATH_MAX * 2];
    struct stat twin_stat;

    if (memmem(accept_encoding, accept_encoding_len, "br", 2) != NULL) {
        snprintf(twin_path, sizeof(twin_path), "%s.br", file_path);
        if (stat(twin_path, &twin_stat) == 0 && S_ISREG(twin_stat.st_mode) &&
            twin_stat.st_mtime >= file_stat->st_mtime) {
            snprintf(target_path, target_path_cap, "%s", twin_path);
            *target_stat = twin_stat;
            *out_encoding = "br";
            return;
        }
    }

    if (memmem(accept_encoding, accept_encoding_len, "zstd", 4) != NULL) {
        snprintf(twin_path, sizeof(twin_path), "%s.zst", file_path);
        if (stat(twin_path, &twin_stat) == 0 && S_ISREG(twin_stat.st_mode) &&
            twin_stat.st_mtime >= file_stat->st_mtime) {
            snprintf(target_path, target_path_cap, "%s", twin_path);
            *target_stat = twin_stat;
            *out_encoding = "zstd";
            return;
        }
    }

    if (memmem(accept_encoding, accept_encoding_len, "gzip", 4) != NULL) {
        snprintf(twin_path, sizeof(twin_path), "%s.gz", file_path);
        if (stat(twin_path, &twin_stat) == 0 && S_ISREG(twin_stat.st_mode) &&
            twin_stat.st_mtime >= file_stat->st_mtime) {
            snprintf(target_path, target_path_cap, "%s", twin_path);
            *target_stat = twin_stat;
            *out_encoding = "gzip";
        }
    }
}

/* Helper 5: Canonical path validation against location root */
static bool static_validate_canonical_path(const char *root, const char *target_path,
                                           char *canonical_target, size_t canonical_target_cap,
                                           int *out_error) {
    char canonical_root[PATH_MAX];
    if (realpath(root, canonical_root) == NULL) {
        *out_error = 404;
        return false;
    }
    size_t canonical_root_len = strlen(canonical_root);

    char resolved[PATH_MAX];
    if (realpath(target_path, resolved) == NULL) {
        *out_error = 404;
        return false;
    }
    size_t resolved_len = strlen(resolved);

    if (resolved_len < canonical_root_len ||
        strncmp(resolved, canonical_root, canonical_root_len) != 0 ||
        (resolved[canonical_root_len] != '/' && resolved[canonical_root_len] != '\0')) {
        *out_error = 403;
        return false;
    }

    snprintf(canonical_target, canonical_target_cap, "%s", resolved);
    return true;
}

/* Helper 6: Populate and pre-format thread cache */
static void static_populate_thread_cache(apex_static_cache_entry_t *cached,
                                         const char *cache_key,
                                         const char *target_path,
                                         time_t now,
                                         time_t mtime,
                                         size_t total_size,
                                         const char *etag_str,
                                         const char *last_mod_str,
                                         const char *content_type,
                                         const char *content_encoding,
                                         const char *server_hdr,
                                         char **out_cached_memory) {
    if (cached->in_memory_data != NULL) {
        free(cached->in_memory_data);
        cached->in_memory_data = NULL;
    }
    snprintf(cached->logical_path, sizeof(cached->logical_path), "%s", cache_key);
    snprintf(cached->target_path, sizeof(cached->target_path), "%s", target_path);
    cached->expires_at = now + APEX_STATIC_CACHE_TTL;
    cached->mtime = mtime;
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
                    *out_cached_memory = buf;
                } else {
                    free(buf);
                }
            }
            close(pre_fd);
        }
    }

    int kh_len = snprintf(cached->header_keepalive, sizeof(cached->header_keepalive),
                          "HTTP/1.1 200 OK\r\n"
                          "%s"
                          "Content-Type: %s\r\n"
                          "Content-Length: %zu\r\n"
                          "Accept-Ranges: bytes\r\n"
                          "ETag: %s\r\n"
                          "Last-Modified: %s\r\n"
                          "%s%s%s"
                          "%s"
                          "Connection: keep-alive\r\n"
                          "\r\n",
                          server_hdr, content_type, total_size,
                          etag_str, last_mod_str,
                          content_encoding ? "Content-Encoding: " : "",
                          content_encoding ? content_encoding : "",
                          content_encoding ? "\r\n" : "",
                          content_encoding ? "Vary: Accept-Encoding\r\n" : "");
    cached->header_keepalive_len = kh_len > 0 && (size_t)kh_len < sizeof(cached->header_keepalive) ? (size_t)kh_len : 0;

    int cl_len = snprintf(cached->header_close, sizeof(cached->header_close),
                          "HTTP/1.1 200 OK\r\n"
                          "%s"
                          "Content-Type: %s\r\n"
                          "Content-Length: %zu\r\n"
                          "Accept-Ranges: bytes\r\n"
                          "ETag: %s\r\n"
                          "Last-Modified: %s\r\n"
                          "%s%s%s"
                          "%s"
                          "Connection: close\r\n"
                          "\r\n",
                          server_hdr, content_type, total_size,
                          etag_str, last_mod_str,
                          content_encoding ? "Content-Encoding: " : "",
                          content_encoding ? content_encoding : "",
                          content_encoding ? "\r\n" : "",
                          content_encoding ? "Vary: Accept-Encoding\r\n" : "");
    cached->header_close_len = cl_len > 0 && (size_t)cl_len < sizeof(cached->header_close) ? (size_t)cl_len : 0;
}

/* Helper 7: Evaluate HTTP conditional preconditions (If-Match, If-None-Match, etc.) */
static static_precond_result_t static_check_preconditions(conn_t *connection,
                                                          const apex_server_config_t *server,
                                                          const apex_location_config_t *location,
                                                          const char *request, size_t request_len,
                                                          const char *etag_str, const char *last_mod_str,
                                                          time_t mtime, const char *server_hdr,
                                                          const char *extra_headers, size_t extra_headers_len,
                                                          apex_res_t *res) {
    if (request == NULL || request_len == 0) {
        return STATIC_PRECOND_PROCEED;
    }

    /* Step 1: If-Match (RFC 9110 §13.1.1) */
    const char *if_match = NULL;
    size_t if_match_len = 0;
    if (apex_http_find_header(request, request_len, "If-Match", &if_match, &if_match_len)) {
        if (!static_etag_matches(if_match, if_match_len, etag_str, false)) {
            router_send_error_ex(connection, server, request, request_len, 412,
                                 "Precondition Failed", "Precondition Failed\n",
                                 extra_headers, extra_headers_len);
            if (res != NULL) {
                res->last_status = 412;
                res->last_body_bytes = 0;
            }
            return STATIC_PRECOND_FAILED;
        }
    } else {
        /* Step 2: If-Unmodified-Since (RFC 9110 §13.1.4) */
        const char *if_unmod_since = NULL;
        size_t if_unmod_since_len = 0;
        if (apex_http_find_header(request, request_len, "If-Unmodified-Since", &if_unmod_since, &if_unmod_since_len)) {
            time_t unmod_time;
            if (apex_static_parse_http_date(if_unmod_since, if_unmod_since_len, &unmod_time)) {
                if (mtime > unmod_time) {
                    router_send_error_ex(connection, server, request, request_len, 412,
                                         "Precondition Failed", "Precondition Failed\n",
                                         extra_headers, extra_headers_len);
                    if (res != NULL) {
                        res->last_status = 412;
                        res->last_body_bytes = 0;
                    }
                    return STATIC_PRECOND_FAILED;
                }
            }
        }
    }

    /* Step 3: If-None-Match (RFC 9110 §13.1.2) */
    const char *if_none_match = NULL;
    size_t if_none_match_len = 0;
    bool if_none_match_present = location->etag &&
                                 apex_http_find_header(request, request_len, "If-None-Match", &if_none_match, &if_none_match_len);
    if (if_none_match_present) {
        if (static_etag_matches(if_none_match, if_none_match_len, etag_str, true)) {
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
            return STATIC_PRECOND_NOT_MODIFIED;
        }
    } else {
        /* Step 4: If-Modified-Since (RFC 9110 §13.1.3) */
        const char *if_mod_since = NULL;
        size_t if_mod_since_len = 0;
        if (apex_http_find_header(request, request_len, "If-Modified-Since", &if_mod_since, &if_mod_since_len)) {
            time_t client_time;
            if (apex_static_parse_http_date(if_mod_since, if_mod_since_len, &client_time)) {
                if (mtime <= client_time) {
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
                    return STATIC_PRECOND_NOT_MODIFIED;
                }
            }
        }
    }

    return STATIC_PRECOND_PROCEED;
}

/* Helper 8: Parse HTTP Range header */
static static_range_result_t static_parse_range_request(const char *request, size_t request_len,
                                                        const char *etag_str, time_t mtime,
                                                        size_t total_size, const char *content_encoding,
                                                        off_t *out_start, size_t *out_len) {
    *out_start = 0;
    *out_len = total_size;

    if (request == NULL || request_len == 0 || content_encoding != NULL) {
        return STATIC_RANGE_NONE;
    }

    const char *if_range = NULL;
    size_t if_range_len = 0;
    if (apex_http_find_header(request, request_len, "If-Range", &if_range, &if_range_len) &&
        if_range != NULL && if_range_len > 0) {
        if (if_range[0] == '"') {
            size_t etag_len = strlen(etag_str);
            if (if_range_len != etag_len || strncmp(if_range, etag_str, etag_len) != 0) {
                return STATIC_RANGE_NONE;
            }
        } else if (if_range[0] == 'W' && if_range_len > 1 && if_range[1] == '/') {
            return STATIC_RANGE_NONE;
        } else {
            time_t if_range_time = 0;
            if (!apex_static_parse_http_date(if_range, if_range_len, &if_range_time) ||
                mtime != if_range_time) {
                return STATIC_RANGE_NONE;
            }
        }
    }

    const char *range_hdr = NULL;
    size_t range_hdr_len = 0;
    if (!apex_http_find_header(request, request_len, "Range", &range_hdr, &range_hdr_len)) {
        return STATIC_RANGE_NONE;
    }

    if (range_hdr_len <= 6 || strncmp(range_hdr, "bytes=", 6) != 0) {
        return STATIC_RANGE_NONE;
    }

    const char *range_spec = range_hdr + 6;
    size_t spec_len = range_hdr_len - 6;
    const char *dash = memchr(range_spec, '-', spec_len);
    if (dash == NULL) {
        return STATIC_RANGE_NONE;
    }

    long long start = -1;
    long long end = -1;
    bool valid_syntax = true;

    if (dash > range_spec) {
        char *endptr = NULL;
        start = strtoll(range_spec, &endptr, 10);
        if (endptr != dash || start < 0) {
            valid_syntax = false;
        }
    }

    if (valid_syntax && (size_t)(dash + 1 - range_spec) < spec_len) {
        char *endptr = NULL;
        end = strtoll(dash + 1, &endptr, 10);
        if (endptr != range_spec + spec_len || end < 0) {
            valid_syntax = false;
        }
    }

    if (!valid_syntax || (start < 0 && end < 0)) {
        return STATIC_RANGE_NONE;
    }

    if (start >= 0 && end >= start && (size_t)start < total_size) {
        if ((size_t)end >= total_size) {
            end = (long long)(total_size - 1);
        }
        *out_start = (off_t)start;
        *out_len = (size_t)(end - start + 1);
        return STATIC_RANGE_OK;
    } else if (start >= 0 && end < 0 && (size_t)start < total_size) {
        *out_start = (off_t)start;
        *out_len = total_size - (size_t)start;
        return STATIC_RANGE_OK;
    } else if (start < 0 && end > 0 && total_size > 0) {
        if ((size_t)end > total_size) {
            end = (long long)total_size;
        }
        *out_start = (off_t)(total_size - (size_t)end);
        *out_len = (size_t)(end);
        return STATIC_RANGE_OK;
    }

    return STATIC_RANGE_NOT_SATISFIABLE;
}

/* Helper 9: Send 416 Range Not Satisfiable */
static void static_send_range_not_satisfiable(conn_t *connection, const char *server_hdr,
                                              size_t total_size, apex_res_t *res) {
    char h416[512];
    int n416 = snprintf(h416, sizeof(h416),
                       "HTTP/1.1 416 Range Not Satisfiable\r\n"
                       "%s"
                       "Content-Range: bytes */%zu\r\n"
                       "Content-Length: 0\r\n"
                       "Connection: %s\r\n"
                       "\r\n",
                       server_hdr, total_size,
                       connection->close_after_write ? "close" : "keep-alive");
    if (n416 > 0 && (size_t)n416 < sizeof(h416)) {
        apex_conn_write(connection, h416, (size_t)n416);
        apex_record_status(416);
        if (res != NULL) {
            res->last_status = 416;
            res->last_body_bytes = 0;
        }
    }
}

/* Helper 10: Transmit response body and headers */
static void static_transmit(conn_t *connection, const apex_server_config_t *server,
                            const char *request, size_t request_len,
                            const char *target_path, bool is_range,
                            off_t range_start, size_t send_length, size_t total_size,
                            const char *server_hdr, const char *content_type,
                            const char *content_encoding, const char *etag_str,
                            const char *last_mod_str, const char *extra_headers,
                            size_t extra_headers_len, bool head_request,
                            const char *cached_memory, apex_cached_file_t **inout_ofc,
                            apex_res_t *res) {
    apex_cached_file_t *ofc_entry = *inout_ofc;
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
                              server_hdr, content_type, send_length,
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
                              server_hdr, content_type, send_length,
                              etag_str, last_mod_str,
                              content_encoding ? "Content-Encoding: " : "",
                              content_encoding ? content_encoding : "",
                              content_encoding ? "\r\n" : "",
                              content_encoding ? "Vary: Accept-Encoding\r\n" : "",
                              connection->close_after_write ? "close" : "keep-alive",
                              (int)extra_headers_len, extra_headers ? extra_headers : "");
    }

    int file_fd = -1;
    if (!head_request && send_length > 0 && cached_memory == NULL) {
        if (ofc_entry != NULL && ofc_entry->fd >= 0) {
            file_fd = ofc_entry->fd;
        } else {
            file_fd = open(target_path, O_RDONLY | O_CLOEXEC);
            if (file_fd < 0) {
                router_send_error(connection, server, request, request_len, 403, "Forbidden", "Permission Denied\n");
                return;
            }
        }
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
            if (ofc_entry != NULL && ofc_entry->fd >= 0) {
                apex_conn_sendfile_cached(connection, ofc_entry->fd, range_start, send_length, ofc_entry);
                *inout_ofc = NULL; /* Transferred ownership to sendfile_cached */
                return;
            }
            if (file_fd >= 0) {
                apex_conn_sendfile(connection, file_fd, range_start, send_length);
                return;
            }
        }
    } else {
        if (file_fd >= 0 && (ofc_entry == NULL || file_fd != ofc_entry->fd)) {
            close(file_fd);
        }
    }
}

void apex_static_serve(const apex_runtime_t *runtime,
                       const apex_server_config_t *server,
                       const apex_location_config_t *location,
                       const char *request, size_t request_len,
                       const char *path, size_t path_len,
                       bool head_request,
                       apex_res_t *res,
                       const char *extra_headers, size_t extra_headers_len) {
    char server_hdr[160];
    apex_http_format_server_header(server ? &server->server_tokens : NULL, server_hdr, sizeof(server_hdr));
    conn_t *connection = res != NULL ? res->conn : NULL;
    if (connection == NULL || location == NULL || location->root == NULL || path == NULL) {
        router_send_error(connection, server, request, request_len, 404, "Not Found", "Not Found\n");
        return;
    }

    char file_path[APEX_CONFIG_PATH_MAX * 2];
    int path_res = static_resolve_path(location, path, path_len, file_path, sizeof(file_path));
    if (path_res != 0) {
        const char *reason = (path_res == 400) ? "Bad Request" :
                             (path_res == 403) ? "Forbidden" :
                             (path_res == 414) ? "URI Too Long" : "Not Found";
        const char *body = (path_res == 400) ? "Invalid URI Encoding\n" :
                           (path_res == 403) ? "Forbidden\n" :
                           (path_res == 414) ? "URI Too Long\n" : "Not Found\n";
        router_send_error(connection, server, request, request_len, path_res, reason, body);
        return;
    }

    const char *accept_encoding = NULL;
    size_t accept_encoding_len = 0;
    const char *requested_encoding = static_detect_requested_encoding(location, request, request_len,
                                                                    &accept_encoding, &accept_encoding_len);

    char cache_key[APEX_CONFIG_PATH_MAX * 2 + 16];
    int key_len = snprintf(cache_key, sizeof(cache_key), "%s:%s", file_path, requested_encoding);
    if (key_len < 0 || (size_t)key_len >= sizeof(cache_key)) {
        key_len = snprintf(cache_key, sizeof(cache_key), "%s", file_path);
    }

    time_t now = time(NULL);
    uint32_t fast_slot = static_cache_hash(cache_key, (size_t)key_len);
    apex_static_cache_entry_t *cached = &s_thread_cache.entries[fast_slot];
    bool cache_hit = false;

    struct stat file_stat;
    struct stat target_stat;
    const char *content_type = NULL;
    const char *content_encoding = NULL;
    char target_path[APEX_CONFIG_PATH_MAX * 2];
    char etag_str[64] = {0};
    char last_mod_str[64] = {0};
    size_t total_size = 0;
    char *cached_memory = NULL;

    if (cached->logical_path[0] != '\0' && strcmp(cached->logical_path, cache_key) == 0 && now < cached->expires_at) {
        cache_hit = true;
        total_size = cached->size;
        memcpy(etag_str, cached->etag, sizeof(etag_str));
        memcpy(last_mod_str, cached->last_modified, sizeof(last_mod_str));
        content_type = cached->content_type;
        content_encoding = cached->content_encoding;
        cached_memory = cached->in_memory_data;
        file_stat.st_mtime = cached->mtime;
        file_stat.st_size = (off_t)cached->size;
        target_stat = file_stat;
        snprintf(target_path, sizeof(target_path), "%s", cached->target_path);
    }

    apex_cached_file_t *ofc_entry = NULL;
#define STATIC_OFC_RELEASE() do { if (ofc_entry != NULL && runtime != NULL && runtime->file_cache != NULL) { apex_file_cache_release((apex_file_cache_t *)runtime->file_cache, ofc_entry); ofc_entry = NULL; } } while(0)

    if (location->open_file_cache.enabled && runtime != NULL && runtime->file_cache != NULL) {
        char lookup_path[sizeof(file_path)];
        snprintf(lookup_path, sizeof(lookup_path), "%s", file_path);
        size_t lp_len = strlen(lookup_path);
        if (lp_len > 0 && lookup_path[lp_len - 1] == '/') {
            if (location->index_count > 0) {
                snprintf(lookup_path + lp_len, sizeof(lookup_path) - lp_len, "%s", location->indices[0]);
            } else {
                snprintf(lookup_path + lp_len, sizeof(lookup_path) - lp_len, "index.html");
            }
            lp_len = strlen(lookup_path);
        }

        bool found_ofc = false;
        if (location->precompressed && accept_encoding != NULL && accept_encoding_len > 0) {
            char twin_path[sizeof(lookup_path) + 8];
            const char *twin_enc = NULL;
            if (memmem(accept_encoding, accept_encoding_len, "br", 2) != NULL) {
                snprintf(twin_path, sizeof(twin_path), "%s.br", lookup_path);
                twin_enc = "br";
            } else if (memmem(accept_encoding, accept_encoding_len, "zstd", 4) != NULL) {
                snprintf(twin_path, sizeof(twin_path), "%s.zst", lookup_path);
                twin_enc = "zstd";
            } else if (memmem(accept_encoding, accept_encoding_len, "gzip", 4) != NULL) {
                snprintf(twin_path, sizeof(twin_path), "%s.gz", lookup_path);
                twin_enc = "gzip";
            }
            if (twin_enc != NULL) {
                if (apex_file_cache_acquire((apex_file_cache_t *)runtime->file_cache, twin_path, strlen(twin_path), &ofc_entry)) {
                    if (ofc_entry->err_code == 0) {
                        content_encoding = twin_enc;
                        found_ofc = true;
                    } else {
                        STATIC_OFC_RELEASE();
                    }
                }
            }
        }

        if (!found_ofc) {
            if (apex_file_cache_acquire((apex_file_cache_t *)runtime->file_cache, lookup_path, lp_len, &ofc_entry)) {
                found_ofc = true;
            }
        }

        if (found_ofc && ofc_entry != NULL) {
            if (ofc_entry->err_code != 0) {
                int err = ofc_entry->err_code;
                STATIC_OFC_RELEASE();
                if (err == ENOENT) {
                    router_send_error_ex(connection, server, request, request_len, 404, "Not Found", "File Not Found\n", extra_headers, extra_headers_len);
                } else {
                    router_send_error_ex(connection, server, request, request_len, 403, "Forbidden", "Forbidden\n", extra_headers, extra_headers_len);
                }
                return;
            }

            cache_hit = true;
            file_stat = ofc_entry->stat_info;
            target_stat = ofc_entry->stat_info;
            total_size = (size_t)ofc_entry->stat_info.st_size;
            content_type = ofc_entry->content_type;
            memcpy(etag_str, ofc_entry->etag, sizeof(etag_str));
            memcpy(last_mod_str, ofc_entry->last_modified, sizeof(last_mod_str));
            cached_memory = ofc_entry->mmap_addr;
            snprintf(target_path, sizeof(target_path), "%s", ofc_entry->path);
        }
    }

    if (!cache_hit) {
        if (!static_resolve_candidate_file(location, file_path, sizeof(file_path), &file_stat)) {
            if (location->open_file_cache.enabled && runtime != NULL && runtime->file_cache != NULL && location->open_file_cache.errors) {
                apex_cached_file_t *neg_entry = NULL;
                if (apex_file_cache_acquire((apex_file_cache_t *)runtime->file_cache, file_path, strlen(file_path), &neg_entry)) {
                    apex_file_cache_release((apex_file_cache_t *)runtime->file_cache, neg_entry);
                }
            }
            router_send_error(connection, server, request, request_len, 404, "Not Found", "File Not Found\n");
            return;
        }

        content_type = apex_mime_type(file_path);
        static_select_twin_precompressed(location, accept_encoding, accept_encoding_len,
                                         file_path, &file_stat, target_path, sizeof(target_path),
                                         &target_stat, &content_encoding);

        int canon_err = 0;
        char canonical_target[PATH_MAX];
        if (!static_validate_canonical_path(location->root, target_path, canonical_target, sizeof(canonical_target), &canon_err)) {
            const char *reason = (canon_err == 403) ? "Forbidden" : "Not Found";
            const char *body = (canon_err == 403) ? "Forbidden\n" : "File Not Found\n";
            router_send_error(connection, server, request, request_len, canon_err, reason, body);
            return;
        }
        snprintf(target_path, sizeof(target_path), "%s", canonical_target);

        apex_static_format_etag(file_stat.st_mtime, file_stat.st_size, etag_str, sizeof(etag_str));
        apex_static_format_http_date(file_stat.st_mtime, last_mod_str, sizeof(last_mod_str));
        total_size = (size_t)target_stat.st_size;

        if (location->open_file_cache.enabled && runtime != NULL && runtime->file_cache != NULL && ofc_entry == NULL) {
            if (apex_file_cache_acquire((apex_file_cache_t *)runtime->file_cache, target_path, strlen(target_path), &ofc_entry)) {
                if (ofc_entry->err_code == 0 && ofc_entry->mmap_addr != NULL) {
                    cached_memory = ofc_entry->mmap_addr;
                }
            }
        }

        static_populate_thread_cache(cached, cache_key, target_path, now, file_stat.st_mtime,
                                     total_size, etag_str, last_mod_str, content_type,
                                     content_encoding, server_hdr, &cached_memory);
    }

    static_precond_result_t precond = static_check_preconditions(connection, server, location,
                                                                request, request_len, etag_str,
                                                                last_mod_str, file_stat.st_mtime,
                                                                server_hdr, extra_headers, extra_headers_len, res);
    if (precond != STATIC_PRECOND_PROCEED) {
        STATIC_OFC_RELEASE();
        return;
    }

    off_t range_start = 0;
    size_t send_length = total_size;
    static_range_result_t range_res = static_parse_range_request(request, request_len, etag_str,
                                                                 file_stat.st_mtime, total_size,
                                                                 content_encoding, &range_start, &send_length);
    if (range_res == STATIC_RANGE_NOT_SATISFIABLE) {
        STATIC_OFC_RELEASE();
        static_send_range_not_satisfiable(connection, server_hdr, total_size, res);
        return;
    }
    bool is_range = (range_res == STATIC_RANGE_OK);

    /* Fast path for standard 200 OK responses with pre-formatted cached headers */
    if (!is_range && extra_headers_len == 0 && cached != NULL && cached->header_keepalive_len > 0) {
        const char *hdr = connection->close_after_write ? cached->header_close : cached->header_keepalive;
        size_t hlen = connection->close_after_write ? cached->header_close_len : cached->header_keepalive_len;

        apex_record_status(200);
        if (res != NULL) {
            res->last_status = 200;
            res->last_body_bytes = head_request ? 0 : send_length;
        }

        if (head_request || send_length == 0) {
            apex_conn_write(connection, hdr, hlen);
            STATIC_OFC_RELEASE();
            return;
        }

        if (cached_memory != NULL) {
            if (hlen + send_length <= sizeof(connection->write_buffer) - connection->write_length &&
                connection->aux_length == connection->aux_offset) {
                memcpy(connection->write_buffer + connection->write_length, hdr, hlen);
                memcpy(connection->write_buffer + connection->write_length + hlen, cached_memory, send_length);
                connection->write_length += (uint32_t)(hlen + send_length);
                STATIC_OFC_RELEASE();
                return;
            }
            apex_conn_write(connection, hdr, hlen);
            apex_conn_write(connection, cached_memory, send_length);
            STATIC_OFC_RELEASE();
            return;
        }
    }

    static_transmit(connection, server, request, request_len, target_path, is_range,
                    range_start, send_length, total_size, server_hdr, content_type,
                    content_encoding, etag_str, last_mod_str, extra_headers, extra_headers_len,
                    head_request, cached_memory, &ofc_entry, res);

    STATIC_OFC_RELEASE();
#undef STATIC_OFC_RELEASE
}
