#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "apex/proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static SSL_CTX *g_client_ssl_ctx = NULL;
static pthread_once_t g_client_ssl_once = PTHREAD_ONCE_INIT;

static void init_client_ssl_ctx(void) {
    const SSL_METHOD *method = TLS_client_method();
    g_client_ssl_ctx = SSL_CTX_new(method);
    if (g_client_ssl_ctx != NULL) {
        SSL_CTX_set_verify(g_client_ssl_ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_mode(g_client_ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    }
}

typedef struct {
    char *data;
    size_t len;
    size_t capacity;
} buffer_t;

typedef struct {
    int fd;
    struct sockaddr_storage address;
    socklen_t address_len;
    uint64_t last_used_ms;
} pooled_conn_t;

typedef struct {
    pooled_conn_t entries[APEX_PROXY_POOL_CAPACITY];
    size_t count;
    size_t total_created;
    size_t total_reused;
    size_t total_closed;
} thread_pool_t;

typedef struct {
    int fd;
    SSL *ssl;
    char *data;
    size_t len;
    size_t capacity;
    size_t position;
    size_t limit;
    uint64_t deadline_ms;
    bool eof;
} reader_t;

/*
 * The connection cache is intentionally thread-local. A worker never hands a
 * backend socket to another worker, so no lock or atomic is needed on acquire
 * or release.
 */
static _Thread_local thread_pool_t thread_pool;
static _Thread_local uint64_t random_state;

static uint64_t monotonic_ms(void) {
    struct timespec timestamp;
    if (clock_gettime(CLOCK_MONOTONIC, &timestamp) != 0) {
        return 0;
    }
    return (uint64_t)timestamp.tv_sec * 1000u + (uint64_t)timestamp.tv_nsec / 1000000u;
}

static uint64_t monotonic_us(void) {
    struct timespec timestamp;
    if (clock_gettime(CLOCK_MONOTONIC, &timestamp) != 0) {
        return 0;
    }
    return (uint64_t)timestamp.tv_sec * 1000000u + (uint64_t)timestamp.tv_nsec / 1000u;
}

static const char *find_bytes(const char *haystack, size_t haystack_len, const char *needle, size_t needle_len) {
    if (haystack == NULL || needle_len == 0 || haystack_len < needle_len) {
        return NULL;
    }

    const char *last = haystack + haystack_len - needle_len;
    const char *cursor = haystack;
    while (cursor <= last) {
        cursor = memchr(cursor, needle[0], (size_t)(last - cursor) + 1);
        if (cursor == NULL) {
            return NULL;
        }
        if (memcmp(cursor, needle, needle_len) == 0) {
            return cursor;
        }
        cursor++;
    }
    return NULL;
}

static bool buffer_reserve(buffer_t *buffer, size_t extra) {
    if (extra > SIZE_MAX - buffer->len) {
        return false;
    }

    size_t needed = buffer->len + extra;
    if (needed <= buffer->capacity) {
        return true;
    }

    size_t capacity = buffer->capacity ? buffer->capacity : 256u;
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
    return true;
}

static bool buffer_append(buffer_t *buffer, const void *data, size_t len) {
    if (len == 0) {
        return true;
    }
    if (!buffer_reserve(buffer, len)) {
        return false;
    }
    memcpy(buffer->data + buffer->len, data, len);
    buffer->len += len;
    return true;
}

static bool buffer_append_string(buffer_t *buffer, const char *text) {
    return buffer_append(buffer, text, strlen(text));
}

static void buffer_free(buffer_t *buffer) {
    free(buffer->data);
    buffer->data = NULL;
    buffer->len = 0;
    buffer->capacity = 0;
}

static bool address_equal(const struct sockaddr_storage *left, socklen_t left_len,
                          const struct sockaddr_storage *right, socklen_t right_len) {
    if (left_len != right_len || left->ss_family != right->ss_family) {
        return false;
    }

    if (left->ss_family == AF_INET) {
        const struct sockaddr_in *first = (const struct sockaddr_in *)left;
        const struct sockaddr_in *second = (const struct sockaddr_in *)right;
        return first->sin_port == second->sin_port && first->sin_addr.s_addr == second->sin_addr.s_addr;
    }

    if (left->ss_family == AF_INET6) {
        const struct sockaddr_in6 *first = (const struct sockaddr_in6 *)left;
        const struct sockaddr_in6 *second = (const struct sockaddr_in6 *)right;
        return first->sin6_port == second->sin6_port && first->sin6_scope_id == second->sin6_scope_id &&
               memcmp(&first->sin6_addr, &second->sin6_addr, sizeof(first->sin6_addr)) == 0;
    }

    return memcmp(left, right, left_len) == 0;
}

static bool connection_is_reusable(int fd) {
    unsigned char probe = 0;
    ssize_t peeked = recv(fd, &probe, 1, MSG_PEEK | MSG_DONTWAIT);
    if (peeked == 0) {
        return false;
    }
    if (peeked > 0) {
        return false;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return true;
    }
    return false;
}

static void pool_close(int fd) {
    close(fd);
    thread_pool.total_closed++;
}

static int pool_acquire(const upstream_server_t *server, const upstream_group_t *group) {
    uint64_t now = monotonic_ms();
    uint64_t idle_limit = group->idle_timeout_ms ? group->idle_timeout_ms : APEX_PROXY_DEFAULT_IDLE_TIMEOUT_MS;

    size_t index = 0;
    while (index < thread_pool.count) {
        pooled_conn_t *entry = &thread_pool.entries[index];
        if (!address_equal(&entry->address, entry->address_len, &server->address, server->address_len)) {
            index++;
            continue;
        }

        bool expired = now > entry->last_used_ms && now - entry->last_used_ms > idle_limit;
        int fd = entry->fd;

        thread_pool.entries[index] = thread_pool.entries[thread_pool.count - 1u];
        thread_pool.count--;

        if (expired || !connection_is_reusable(fd)) {
            pool_close(fd);
            continue;
        }

        thread_pool.total_reused++;
        return fd;
    }

    return -1;
}

static void pool_release(const upstream_server_t *server, const upstream_group_t *group, int fd) {
    uint32_t limit = group->keepalive_capacity;
    if (limit > APEX_PROXY_POOL_CAPACITY) {
        limit = APEX_PROXY_POOL_CAPACITY;
    }
    if (limit == 0 || thread_pool.count >= limit) {
        pool_close(fd);
        return;
    }

    pooled_conn_t *entry = &thread_pool.entries[thread_pool.count++];
    entry->fd = fd;
    entry->address = server->address;
    entry->address_len = server->address_len;
    entry->last_used_ms = monotonic_ms();
}

static uint64_t thread_random(void) {
    if (random_state == 0) {
        random_state = monotonic_us() ^ ((uint64_t)getpid() << 32) ^ (uintptr_t)&random_state;
        if (random_state == 0) {
            random_state = UINT64_C(0x9e3779b97f4a7c15);
        }
    }

    uint64_t value = random_state;
    value ^= value >> 12;
    value ^= value << 25;
    value ^= value >> 27;
    random_state = value;
    return value * UINT64_C(0x2545f4914f6cdd1d);
}

static size_t random_below(size_t bound) {
    if (bound == 0) {
        return 0;
    }
    return (size_t)(thread_random() % (uint64_t)bound);
}

static uint64_t server_load_score(const upstream_server_t *server) {
    int64_t active = atomic_load_explicit(&server->active_conns, memory_order_relaxed);
    if (active < 0) {
        active = 0;
    }
    uint64_t weight = server->weight ? server->weight : 1u;
    return (((uint64_t)active + 1u) * 1024u) / weight;
}

static bool is_http_method(const char *method) {
    if (method == NULL || method[0] == '\0') {
        return false;
    }

    for (const unsigned char *cursor = (const unsigned char *)method; cursor[0] != 0; cursor++) {
        unsigned char byte = cursor[0];
        if (byte <= 0x20 || byte >= 0x7f) {
            return false;
        }
        switch (byte) {
        case '(':
        case ')':
        case '<':
        case '>':
        case '@':
        case ',':
        case ';':
        case ':':
        case '\\':
        case '"':
        case '/':
        case '[':
        case ']':
        case '?':
        case '=':
        case '{':
        case '}':
            return false;
        default:
            break;
        }
    }
    return true;
}

static bool is_idempotent_method(const char *method) {
    if (method == NULL) return false;
    return (strcasecmp(method, "GET") == 0 ||
            strcasecmp(method, "HEAD") == 0 ||
            strcasecmp(method, "OPTIONS") == 0 ||
            strcasecmp(method, "TRACE") == 0 ||
            strcasecmp(method, "PUT") == 0 ||
            strcasecmp(method, "DELETE") == 0);
}

static bool is_request_target(const char *target) {
    if (target == NULL || target[0] == '\0') {
        return false;
    }

    for (const unsigned char *cursor = (const unsigned char *)target; cursor[0] != 0; cursor++) {
        if (cursor[0] <= 0x20 || cursor[0] >= 0x7f) {
            return false;
        }
    }
    return true;
}

static bool header_block_contains(const char *headers, size_t headers_len, const char *name) {
    if (headers == NULL || headers_len == 0) {
        return false;
    }

    size_t name_len = strlen(name);
    size_t position = 0;
    while (position < headers_len) {
        const char *line = headers + position;
        const char *newline = memchr(line, '\n', headers_len - position);
        size_t line_len = newline ? (size_t)(newline - line) : headers_len - position;
        if (line_len > 0 && line[line_len - 1u] == '\r') {
            line_len--;
        }

        if (line_len > name_len && strncasecmp(line, name, name_len) == 0 && line[name_len] == ':') {
            return true;
        }

        if (newline == NULL) {
            break;
        }
        position += (size_t)(newline - line) + 1u;
    }
    return false;
}

static bool header_lookup(const char *headers, size_t headers_len, const char *name, const char **value,
                          size_t *value_len) {
    if (headers == NULL || headers_len < 2) {
        return false;
    }

    size_t name_len = strlen(name);
    const char *first_line_end = find_bytes(headers, headers_len, "\r\n", 2);
    if (first_line_end == NULL) {
        return false;
    }

    size_t position = (size_t)(first_line_end - headers) + 2u;
    while (position < headers_len) {
        const char *line = headers + position;
        const char *line_end = find_bytes(line, headers_len - position, "\r\n", 2);
        if (line_end == NULL) {
            return false;
        }

        size_t line_len = (size_t)(line_end - line);
        if (line_len == 0) {
            return false;
        }

        const char *colon = memchr(line, ':', line_len);
        if (colon != NULL) {
            size_t field_len = (size_t)(colon - line);
            while (field_len > 0 && (line[field_len - 1u] == ' ' || line[field_len - 1u] == '\t')) {
                field_len--;
            }

            if (field_len == name_len && strncasecmp(line, name, name_len) == 0) {
                const char *start = colon + 1;
                const char *end = line + line_len;
                while (start < end && (start[0] == ' ' || start[0] == '\t')) {
                    start++;
                }
                while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
                    end--;
                }
                *value = start;
                *value_len = (size_t)(end - start);
                return true;
            }
        }

        position += line_len + 2u;
    }
    return false;
}

static bool header_has_token(const char *headers, size_t headers_len, const char *name, const char *token) {
    if (headers == NULL || headers_len < 2) {
        return false;
    }

    size_t name_len = strlen(name);
    size_t token_len = strlen(token);
    const char *first_line_end = find_bytes(headers, headers_len, "\r\n", 2);
    if (first_line_end == NULL) {
        return false;
    }

    size_t position = (size_t)(first_line_end - headers) + 2u;
    while (position < headers_len) {
        const char *line = headers + position;
        const char *line_end = find_bytes(line, headers_len - position, "\r\n", 2);
        if (line_end == NULL) {
            return false;
        }

        size_t line_len = (size_t)(line_end - line);
        if (line_len == 0) {
            return false;
        }

        const char *colon = memchr(line, ':', line_len);
        if (colon != NULL) {
            size_t field_len = (size_t)(colon - line);
            while (field_len > 0 && (line[field_len - 1u] == ' ' || line[field_len - 1u] == '\t')) {
                field_len--;
            }

            if (field_len == name_len && strncasecmp(line, name, name_len) == 0) {
                const char *cursor = colon + 1;
                const char *end = line + line_len;
                while (cursor < end) {
                    const char *comma = memchr(cursor, ',', (size_t)(end - cursor));
                    const char *piece_end = comma ? comma : end;
                    const char *piece = cursor;
                    const char *piece_stop = piece_end;
                    while (piece < piece_stop && (piece[0] == ' ' || piece[0] == '\t')) {
                        piece++;
                    }
                    while (piece_stop > piece && (piece_stop[-1] == ' ' || piece_stop[-1] == '\t')) {
                        piece_stop--;
                    }
                    if ((size_t)(piece_stop - piece) == token_len &&
                        strncasecmp(piece, token, token_len) == 0) {
                        return true;
                    }
                    if (comma == NULL) {
                        break;
                    }
                    cursor = comma + 1;
                }
            }
        }

        position += line_len + 2u;
    }
    return false;
}

static bool parse_status_code(const char *headers, size_t headers_len, int *status) {
    if (headers_len < 12 || memcmp(headers, "HTTP/", 5) != 0) {
        return false;
    }

    const char *space = memchr(headers, ' ', headers_len);
    if (space == NULL) {
        return false;
    }

    const char *code = space + 1;
    size_t remaining = (size_t)((headers + headers_len) - code);
    if (remaining < 3u) {
        return false;
    }
    if (code[0] < '0' || code[0] > '9' || code[1] < '0' || code[1] > '9' || code[2] < '0' || code[2] > '9') {
        return false;
    }
    if (remaining > 3u && code[3] != ' ' && code[3] != '\r') {
        return false;
    }

    *status = (code[0] - '0') * 100 + (code[1] - '0') * 10 + (code[2] - '0');
    return true;
}

static bool parse_u64(const char *text, size_t text_len, uint64_t *value) {
    size_t cursor = 0;
    while (cursor < text_len && (text[cursor] == ' ' || text[cursor] == '\t')) {
        cursor++;
    }

    size_t digits_start = cursor;
    uint64_t parsed = 0;
    while (cursor < text_len && text[cursor] >= '0' && text[cursor] <= '9') {
        unsigned int digit = (unsigned int)(text[cursor] - '0');
        if (parsed > (UINT64_MAX - digit) / 10u) {
            return false;
        }
        parsed = parsed * 10u + digit;
        cursor++;
    }

    if (cursor == digits_start) {
        return false;
    }
    while (cursor < text_len && (text[cursor] == ' ' || text[cursor] == '\t')) {
        cursor++;
    }
    if (cursor != text_len) {
        return false;
    }

    *value = parsed;
    return true;
}

static bool parse_hex_u64(const char *text, size_t text_len, uint64_t *value) {
    size_t cursor = 0;
    uint64_t parsed = 0;
    bool any_digit = false;

    while (cursor < text_len) {
        char byte = text[cursor];
        unsigned int digit;
        if (byte >= '0' && byte <= '9') {
            digit = (unsigned int)(byte - '0');
        } else if (byte >= 'a' && byte <= 'f') {
            digit = (unsigned int)(byte - 'a') + 10u;
        } else if (byte >= 'A' && byte <= 'F') {
            digit = (unsigned int)(byte - 'A') + 10u;
        } else {
            break;
        }

        if (parsed > (UINT64_MAX - digit) / 16u) {
            return false;
        }
        parsed = parsed * 16u + digit;
        any_digit = true;
        cursor++;
    }

    if (!any_digit) {
        return false;
    }
    if (cursor < text_len && text[cursor] != ';' && text[cursor] != ' ' && text[cursor] != '\t') {
        return false;
    }

    *value = parsed;
    return true;
}

static void apply_io_timeouts(int fd, const upstream_group_t *group) {
    uint64_t milliseconds = group->io_timeout_ms ? group->io_timeout_ms : APEX_PROXY_DEFAULT_IO_TIMEOUT_MS;
    if (milliseconds > 3600000u) {
        milliseconds = 3600000u;
    }

    struct timeval timeout;
    timeout.tv_sec = (time_t)(milliseconds / 1000u);
    timeout.tv_usec = (suseconds_t)((milliseconds % 1000u) * 1000u);

    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static void configure_socket(int fd) {
    int enabled = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
    (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled));
#ifdef SO_NOSIGPIPE
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
#endif
}

static int connect_server(const upstream_server_t *server, uint64_t timeout_ms) {
    int fd = socket(server->address.ss_family, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }

    int result = connect(fd, (const struct sockaddr *)&server->address, server->address_len);
    if (result < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    if (result < 0) {
        struct pollfd descriptor = {.fd = fd, .events = POLLOUT, .revents = 0};
        int timeout = timeout_ms > (uint64_t)INT_MAX ? INT_MAX : (int)timeout_ms;
        int ready;
        do {
            ready = poll(&descriptor, 1, timeout);
        } while (ready < 0 && errno == EINTR);

        if (ready == 0) {
            close(fd);
            errno = ETIMEDOUT;
            return -1;
        }
        if (ready < 0) {
            close(fd);
            return -1;
        }

        int socket_error = 0;
        socklen_t error_len = sizeof(socket_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_len) < 0 || socket_error != 0) {
            if (socket_error != 0) {
                errno = socket_error;
            }
            close(fd);
            return -1;
        }
    }

    if (fcntl(fd, F_SETFL, flags) < 0) {
        close(fd);
        return -1;
    }

    configure_socket(fd);
    return fd;
}

static int send_all(int fd, SSL *ssl, const void *data, size_t len) {
    if (ssl != NULL) {
        const char *cursor = data;
        while (len > 0) {
            int to_send = len > (size_t)INT_MAX ? INT_MAX : (int)len;
            int written = SSL_write(ssl, cursor, to_send);
            if (written > 0) {
                cursor += (size_t)written;
                len -= (size_t)written;
                continue;
            }
            int err = SSL_get_error(ssl, written);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            return APEX_PROXY_ERR_IO;
        }
        return APEX_PROXY_OK;
    }
    const char *cursor = data;
    while (len > 0) {
        ssize_t sent;
#ifdef MSG_NOSIGNAL
        sent = send(fd, cursor, len, MSG_NOSIGNAL);
#else
        sent = send(fd, cursor, len, 0);
#endif
        if (sent > 0) {
            cursor += sent;
            len -= (size_t)sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return APEX_PROXY_ERR_TIMEOUT;
        }
        return APEX_PROXY_ERR_IO;
    }
    return APEX_PROXY_OK;
}

static int build_request(buffer_t *wire, const apex_proxy_request_t *request, const upstream_server_t *server) {
    if (!buffer_append_string(wire, request->method) || !buffer_append_string(wire, " ") ||
        !buffer_append_string(wire, request->target) || !buffer_append_string(wire, " HTTP/1.1\r\n")) {
        return APEX_PROXY_ERR_ALLOC;
    }

    if (request->headers != NULL && request->headers_len > 0) {
        size_t length = request->headers_len;
        while (length > 0 && (request->headers[length - 1u] == '\n' || request->headers[length - 1u] == '\r')) {
            length--;
        }
        if (length > 0) {
            if (!buffer_append(wire, request->headers, length) || !buffer_append_string(wire, "\r\n")) {
                return APEX_PROXY_ERR_ALLOC;
            }
        }
    }

    if (!header_block_contains(request->headers, request->headers_len, "Host")) {
        char host_header[96];
        int written;
        if (request->host != NULL && request->host[0] != '\0') {
            written = snprintf(host_header, sizeof(host_header), "Host: %s\r\n", request->host);
        } else if (server->address.ss_family == AF_INET6) {
            written = snprintf(host_header, sizeof(host_header), "Host: [%s]:%u\r\n", server->ip,
                               (unsigned int)server->port);
        } else {
            written = snprintf(host_header, sizeof(host_header), "Host: %s:%u\r\n", server->ip,
                               (unsigned int)server->port);
        }
        if (written < 0 || (size_t)written >= sizeof(host_header) ||
            !buffer_append(wire, host_header, (size_t)written)) {
            return APEX_PROXY_ERR_INVALID;
        }
    }

    if (!header_block_contains(request->headers, request->headers_len, "Connection")) {
        const char *connection = request->keep_alive ? "Connection: keep-alive\r\n" : "Connection: close\r\n";
        if (!buffer_append_string(wire, connection)) {
            return APEX_PROXY_ERR_ALLOC;
        }
    }

    if (request->body_len > 0 && !header_block_contains(request->headers, request->headers_len, "Content-Length")) {
        char length_header[32];
        int written = snprintf(length_header, sizeof(length_header), "Content-Length: %zu\r\n", request->body_len);
        if (written < 0 || (size_t)written >= sizeof(length_header) ||
            !buffer_append(wire, length_header, (size_t)written)) {
            return APEX_PROXY_ERR_INVALID;
        }
    }

    if (!buffer_append_string(wire, "\r\n")) {
        return APEX_PROXY_ERR_ALLOC;
    }
    if (request->body_len > 0 && !buffer_append(wire, request->body, request->body_len)) {
        return APEX_PROXY_ERR_ALLOC;
    }

    return APEX_PROXY_OK;
}

static bool reader_reserve(reader_t *reader, size_t extra) {
    if (reader->len > reader->limit || extra > reader->limit - reader->len) {
        return false;
    }

    size_t needed = reader->len + extra;
    if (needed <= reader->capacity) {
        return true;
    }

    size_t capacity = reader->capacity ? reader->capacity : 8192u;
    while (capacity < needed) {
        if (capacity > reader->limit / 2u) {
            capacity = reader->limit;
            break;
        }
        capacity *= 2u;
    }
    if (capacity < needed) {
        capacity = needed;
    }

    char *grown = realloc(reader->data, capacity);
    if (grown == NULL) {
        return false;
    }

    reader->data = grown;
    reader->capacity = capacity;
    return true;
}

static int reader_pull(reader_t *reader) {
    if (reader->eof) {
        return 0;
    }
    if (reader->deadline_ms != 0 && monotonic_ms() >= reader->deadline_ms) {
        return APEX_PROXY_ERR_TIMEOUT;
    }
    if (!reader_reserve(reader, 8192u)) {
        return APEX_PROXY_ERR_TOO_LARGE;
    }

    for (;;) {
        ssize_t received;
        if (reader->ssl != NULL) {
            int to_read = (int)(reader->capacity - reader->len);
            int ret = SSL_read(reader->ssl, reader->data + reader->len, to_read);
            if (ret > 0) {
                received = (ssize_t)ret;
            } else {
                int err = SSL_get_error(reader->ssl, ret);
                if (err == SSL_ERROR_ZERO_RETURN) {
                    received = 0;
                } else if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    return APEX_PROXY_ERR_TIMEOUT;
                } else {
                    return APEX_PROXY_ERR_IO;
                }
            }
        } else {
            received = recv(reader->fd, reader->data + reader->len, reader->capacity - reader->len, 0);
        }

        if (received > 0) {
            reader->len += (size_t)received;
            return 1;
        }
        if (received == 0) {
            reader->eof = true;
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return APEX_PROXY_ERR_TIMEOUT;
        }
        return APEX_PROXY_ERR_IO;
    }
}

static void reader_compact(reader_t *reader) {
    if (reader->position == 0) {
        return;
    }
    if (reader->position >= reader->len) {
        reader->len = 0;
        reader->position = 0;
        return;
    }

    size_t remaining = reader->len - reader->position;
    memmove(reader->data, reader->data + reader->position, remaining);
    reader->len = remaining;
    reader->position = 0;
}

static void reader_free(reader_t *reader) {
    free(reader->data);
    reader->data = NULL;
    reader->len = 0;
    reader->capacity = 0;
    reader->position = 0;
}

static int reader_read_headers(reader_t *reader, size_t max_header, char **headers, size_t *headers_len) {
    size_t search_from = reader->position;
    for (;;) {
        const char *delimiter = NULL;
        if (reader->len - search_from >= 4u) {
            delimiter = find_bytes(reader->data + search_from, reader->len - search_from, "\r\n\r\n", 4u);
        }
        if (delimiter != NULL) {
            size_t end = (size_t)(delimiter - reader->data) + 4u;
            size_t length = end - reader->position;
            if (length > max_header) {
                return APEX_PROXY_ERR_TOO_LARGE;
            }

            char *copy = malloc(length ? length : 1u);
            if (copy == NULL) {
                return APEX_PROXY_ERR_ALLOC;
            }
            memcpy(copy, reader->data + reader->position, length);
            reader->position = end;
            *headers = copy;
            *headers_len = length;
            return APEX_PROXY_OK;
        }

        if (reader->len - reader->position > max_header) {
            return APEX_PROXY_ERR_TOO_LARGE;
        }

        search_from = reader->len >= 3u ? reader->len - 3u : 0;
        if (search_from < reader->position) {
            search_from = reader->position;
        }

        int pulled = reader_pull(reader);
        if (pulled == 0) {
            return APEX_PROXY_ERR_PROTOCOL;
        }
        if (pulled < 0) {
            return pulled;
        }
    }
}

static int read_exact_body(reader_t *reader, size_t max_body, uint64_t content_length, apex_proxy_response_t *response) {
    if (content_length > max_body) {
        return APEX_PROXY_ERR_TOO_LARGE;
    }
    size_t length = (size_t)content_length;

    while (reader->len - reader->position < length) {
        int pulled = reader_pull(reader);
        if (pulled == 0) {
            return APEX_PROXY_ERR_PROTOCOL;
        }
        if (pulled < 0) {
            return pulled;
        }
    }

    if (length > 0) {
        void *body = malloc(length);
        if (body == NULL) {
            return APEX_PROXY_ERR_ALLOC;
        }
        memcpy(body, reader->data + reader->position, length);
        response->body = body;
        response->body_len = length;
    }

    reader->position += length;
    return APEX_PROXY_OK;
}

static int read_chunked_body(reader_t *reader, size_t max_body, apex_proxy_response_t *response) {
    buffer_t body = {0};
    size_t trailer_bytes = 0;

    for (;;) {
        reader_compact(reader);

        const char *line_end = find_bytes(reader->data, reader->len, "\r\n", 2u);
        while (line_end == NULL) {
            if (reader->len > 8192u) {
                buffer_free(&body);
                return APEX_PROXY_ERR_TOO_LARGE;
            }
            int pulled = reader_pull(reader);
            if (pulled == 0) {
                buffer_free(&body);
                return APEX_PROXY_ERR_PROTOCOL;
            }
            if (pulled < 0) {
                buffer_free(&body);
                return pulled;
            }
            line_end = find_bytes(reader->data, reader->len, "\r\n", 2u);
        }

        size_t line_length = (size_t)(line_end - reader->data);
        uint64_t chunk_size = 0;
        if (!parse_hex_u64(reader->data, line_length, &chunk_size)) {
            buffer_free(&body);
            return APEX_PROXY_ERR_PROTOCOL;
        }
        reader->position = line_length + 2u;

        if (chunk_size == 0) {
            for (;;) {
                reader_compact(reader);
                const char *trailer_end = find_bytes(reader->data, reader->len, "\r\n", 2u);
                while (trailer_end == NULL) {
                    if (reader->len > 8192u) {
                        buffer_free(&body);
                        return APEX_PROXY_ERR_TOO_LARGE;
                    }
                    int pulled = reader_pull(reader);
                    if (pulled == 0) {
                        buffer_free(&body);
                        return APEX_PROXY_ERR_PROTOCOL;
                    }
                    if (pulled < 0) {
                        buffer_free(&body);
                        return pulled;
                    }
                    trailer_end = find_bytes(reader->data, reader->len, "\r\n", 2u);
                }

                size_t trailer_length = (size_t)(trailer_end - reader->data);
                reader->position = trailer_length + 2u;
                if (trailer_length == 0) {
                    break;
                }
                trailer_bytes += trailer_length;
                if (trailer_bytes > APEX_PROXY_MAX_TRAILER_BYTES) {
                    buffer_free(&body);
                    return APEX_PROXY_ERR_TOO_LARGE;
                }
            }
            break;
        }

        if (chunk_size > max_body || body.len > max_body - (size_t)chunk_size) {
            buffer_free(&body);
            return APEX_PROXY_ERR_TOO_LARGE;
        }
        if (chunk_size > (uint64_t)SIZE_MAX - 2u) {
            buffer_free(&body);
            return APEX_PROXY_ERR_TOO_LARGE;
        }
        size_t chunk_total = (size_t)chunk_size + 2u;

        reader_compact(reader);

        while (reader->len < chunk_total) {
            int pulled = reader_pull(reader);
            if (pulled == 0) {
                buffer_free(&body);
                return APEX_PROXY_ERR_PROTOCOL;
            }
            if (pulled < 0) {
                buffer_free(&body);
                return pulled;
            }
        }

        if (!buffer_append(&body, reader->data, (size_t)chunk_size)) {
            buffer_free(&body);
            return APEX_PROXY_ERR_ALLOC;
        }
        if (reader->data[chunk_size] != '\r' || reader->data[chunk_size + 1u] != '\n') {
            buffer_free(&body);
            return APEX_PROXY_ERR_PROTOCOL;
        }
        reader->position = chunk_total;
    }

    reader_compact(reader);
    response->body = body.data;
    response->body_len = body.len;
    response->chunked = true;
    return APEX_PROXY_OK;
}

static int read_close_delimited_body(reader_t *reader, size_t max_body, apex_proxy_response_t *response) {
    buffer_t body = {0};

    for (;;) {
        size_t available = reader->len - reader->position;
        if (available > 0) {
            if (body.len > max_body || available > max_body - body.len) {
                buffer_free(&body);
                return APEX_PROXY_ERR_TOO_LARGE;
            }
            if (!buffer_append(&body, reader->data + reader->position, available)) {
                buffer_free(&body);
                return APEX_PROXY_ERR_ALLOC;
            }
            reader->position = reader->len;
        }

        reader_compact(reader);
        if (reader->eof) {
            break;
        }

        int pulled = reader_pull(reader);
        if (pulled == 0) {
            break;
        }
        if (pulled < 0) {
            buffer_free(&body);
            return pulled;
        }
    }

    response->body = body.data;
    response->body_len = body.len;
    return APEX_PROXY_OK;
}

static int read_response(reader_t *reader, const upstream_group_t *group, const apex_proxy_request_t *request,
                         apex_proxy_response_t *response) {
    uint32_t max_header =
        group->max_header_bytes ? group->max_header_bytes : APEX_PROXY_DEFAULT_MAX_HEADER_BYTES;
    uint32_t max_body = group->max_body_bytes ? group->max_body_bytes : APEX_PROXY_DEFAULT_MAX_BODY_BYTES;

    char *headers = NULL;
    size_t headers_len = 0;
    int status = 0;
    bool have_response = false;

    for (int round = 0; round < 8; round++) {
        int result = reader_read_headers(reader, max_header, &headers, &headers_len);
        if (result != APEX_PROXY_OK) {
            return result;
        }

        if (!parse_status_code(headers, headers_len, &status)) {
            free(headers);
            return APEX_PROXY_ERR_PROTOCOL;
        }

        if (status == 101) {
            have_response = true;
            break;
        }
        if (status >= 100 && status < 200) {
            free(headers);
            headers = NULL;
            headers_len = 0;
            continue;
        }

        have_response = true;
        break;
    }

    if (!have_response || headers == NULL) {
        free(headers);
        return APEX_PROXY_ERR_PROTOCOL;
    }

    response->status = status;
    response->headers = headers;
    response->headers_len = headers_len;

    reader_compact(reader);

    bool head_request = strcasecmp(request->method, "HEAD") == 0;
    bool no_body = head_request || status == 204 || status == 304 || status == 101;
    bool chunked = header_has_token(headers, headers_len, "Transfer-Encoding", "chunked");

    const char *content_length_text = NULL;
    size_t content_length_text_len = 0;
    bool has_content_length =
        header_lookup(headers, headers_len, "Content-Length", &content_length_text, &content_length_text_len);
    uint64_t content_length = 0;
    if (has_content_length && !parse_u64(content_length_text, content_length_text_len, &content_length)) {
        return APEX_PROXY_ERR_PROTOCOL;
    }
    if (!no_body && chunked && has_content_length) {
        return APEX_PROXY_ERR_PROTOCOL;
    }

    bool connection_close = header_has_token(headers, headers_len, "Connection", "close");
    bool connection_keep_alive = header_has_token(headers, headers_len, "Connection", "keep-alive");
    bool http11 = headers_len >= 8u && memcmp(headers, "HTTP/1.1", 8) == 0;

    int result = APEX_PROXY_OK;
    if (no_body) {
        response->body = NULL;
        response->body_len = 0;
    } else if (chunked) {
        result = read_chunked_body(reader, max_body, response);
    } else if (has_content_length) {
        result = read_exact_body(reader, max_body, content_length, response);
    } else {
        result = read_close_delimited_body(reader, max_body, response);
        connection_close = true;
    }

    if (result != APEX_PROXY_OK) {
        return result;
    }

    response->keep_alive = !connection_close && status != 101 && (http11 || connection_keep_alive);
    return APEX_PROXY_OK;
}

void apex_upstream_group_init(upstream_group_t *group) {
    if (group == NULL) {
        return;
    }

    memset(group, 0, sizeof(*group));
    group->policy = APEX_BALANCE_ROUND_ROBIN;
    group->keepalive_capacity = APEX_PROXY_DEFAULT_KEEPALIVE;
    group->max_header_bytes = APEX_PROXY_DEFAULT_MAX_HEADER_BYTES;
    group->max_body_bytes = APEX_PROXY_DEFAULT_MAX_BODY_BYTES;
    group->connect_timeout_ms = APEX_PROXY_DEFAULT_CONNECT_TIMEOUT_MS;
    group->io_timeout_ms = APEX_PROXY_DEFAULT_IO_TIMEOUT_MS;
    group->idle_timeout_ms = APEX_PROXY_DEFAULT_IDLE_TIMEOUT_MS;
    group->max_fails = 2u;
    group->fail_timeout_ms = 10000u;
    group->max_retries = 2u;
    group->health_check_interval_ms = 5000u;
    group->health_check_timeout_ms = 2000u;
    group->health_check_fall = 2u;
    group->health_check_rise = 2u;
    snprintf(group->health_check_uri, sizeof(group->health_check_uri), "/");
    atomic_init(&group->round_robin_cursor, 0u);
}

int apex_upstream_add_server(upstream_group_t *group, const char *host, uint16_t port, uint32_t weight) {
    if (group == NULL || host == NULL || host[0] == '\0' || group->server_count >= APEX_UPSTREAM_MAX_SERVERS) {
        return -1;
    }

    char service[8];
    int written = snprintf(service, sizeof(service), "%u", (unsigned int)port);
    if (written < 0 || (size_t)written >= sizeof(service)) {
        return -1;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;

    struct addrinfo *resolved = NULL;
    if (getaddrinfo(host, service, &hints, &resolved) != 0 || resolved == NULL) {
        return -1;
    }

    struct addrinfo *selected = NULL;
    for (struct addrinfo *candidate = resolved; candidate != NULL; candidate = candidate->ai_next) {
        if (candidate->ai_family == AF_INET || candidate->ai_family == AF_INET6) {
            selected = candidate;
            break;
        }
    }

    if (selected == NULL || selected->ai_addrlen > sizeof(struct sockaddr_storage)) {
        freeaddrinfo(resolved);
        return -1;
    }

    upstream_server_t *server = &group->servers[group->server_count];
    memset(server, 0, sizeof(*server));
    memcpy(&server->address, selected->ai_addr, selected->ai_addrlen);
    server->address_len = (socklen_t)selected->ai_addrlen;
    server->port = port;
    server->weight = weight == 0 ? 1u : weight;
    if (server->weight > 1000000u) {
        server->weight = 1000000u;
    }

    if (getnameinfo(selected->ai_addr, selected->ai_addrlen, server->ip, sizeof(server->ip), NULL, 0,
                    NI_NUMERICHOST) != 0) {
        snprintf(server->ip, sizeof(server->ip), "%s", host);
    }

    atomic_init(&server->active_conns, 0);
    atomic_init(&server->total_requests, 0);
    atomic_init(&server->failed_requests, 0);
    atomic_init(&server->bytes_sent, 0);
    atomic_init(&server->bytes_received, 0);
    atomic_init(&server->healthy, true);
    atomic_init(&server->consecutive_failures, 0);
    atomic_init(&server->consecutive_successes, 0);
    atomic_init(&server->last_failure_time_ms, 0);

    size_t index = group->server_count;
    group->server_count++;
    freeaddrinfo(resolved);
    return (int)index;
}

int apex_upstream_add_server_ex(upstream_group_t *group, const char *host, uint16_t port, uint32_t weight,
                                bool is_backup, bool is_down) {
    int idx = apex_upstream_add_server(group, host, port, weight);
    if (idx >= 0 && (size_t)idx < group->server_count) {
        group->servers[idx].is_backup = is_backup;
        group->servers[idx].is_down = is_down;
    }
    return idx;
}

void apex_upstream_set_policy(upstream_group_t *group, apex_balance_policy_t policy) {
    if (group == NULL) {
        return;
    }
    if (policy == APEX_BALANCE_ROUND_ROBIN || policy == APEX_BALANCE_P2C ||
        policy == APEX_BALANCE_LEAST_CONN || policy == APEX_BALANCE_IP_HASH) {
        group->policy = policy;
    }
}

void apex_upstream_record_success(upstream_group_t *group, size_t server_index) {
    if (group == NULL || server_index >= group->server_count) {
        return;
    }
    upstream_server_t *server = &group->servers[server_index];
    atomic_store_explicit(&server->consecutive_failures, 0, memory_order_relaxed);
    atomic_fetch_add_explicit(&server->consecutive_successes, 1, memory_order_relaxed);
    atomic_store_explicit(&server->healthy, true, memory_order_relaxed);
}

void apex_upstream_record_failure(upstream_group_t *group, size_t server_index) {
    if (group == NULL || server_index >= group->server_count) {
        return;
    }
    upstream_server_t *server = &group->servers[server_index];
    atomic_store_explicit(&server->consecutive_successes, 0, memory_order_relaxed);
    uint32_t fails = atomic_fetch_add_explicit(&server->consecutive_failures, 1, memory_order_relaxed) + 1u;
    uint32_t max_fails = group->max_fails ? group->max_fails : 2u;
    if (fails >= max_fails) {
        atomic_store_explicit(&server->healthy, false, memory_order_relaxed);
    }
    atomic_store_explicit(&server->last_failure_time_ms, monotonic_ms(), memory_order_relaxed);
}

static bool server_is_available(const upstream_group_t *group, size_t index, uint64_t now_ms) {
    if (index >= group->server_count) {
        return false;
    }
    const upstream_server_t *server = &group->servers[index];
    if (atomic_load_explicit(&server->healthy, memory_order_relaxed)) {
        return true;
    }
    /* Half-Open probationary trial check */
    uint64_t last_fail = atomic_load_explicit(&server->last_failure_time_ms, memory_order_relaxed);
    uint64_t timeout = group->fail_timeout_ms ? group->fail_timeout_ms : 10000u;
    if (now_ms >= last_fail && (now_ms - last_fail) >= timeout) {
        return true;
    }
    return false;
}

ssize_t apex_upstream_select_request(upstream_group_t *group, uint64_t excluded_mask, const char *client_ip) {
    if (group == NULL || group->server_count == 0) {
        return -1;
    }

    size_t primary_candidates[APEX_UPSTREAM_MAX_SERVERS];
    size_t primary_count = 0;
    size_t backup_candidates[APEX_UPSTREAM_MAX_SERVERS];
    size_t backup_count = 0;
    uint64_t now_ms = monotonic_ms();

    for (size_t i = 0; i < group->server_count; i++) {
        if (group->servers[i].is_down) {
            continue; /* Skip administratively disabled servers */
        }
        if ((excluded_mask & (1ULL << i)) != 0) {
            continue;
        }
        if (server_is_available(group, i, now_ms)) {
            if (group->servers[i].is_backup) {
                backup_candidates[backup_count++] = i;
            } else {
                primary_candidates[primary_count++] = i;
            }
        }
    }

    size_t *candidates = primary_candidates;
    size_t candidate_count = primary_count;

    /* If all primary servers are down/unavailable, fail over to backup servers */
    if (candidate_count == 0 && backup_count > 0) {
        candidates = backup_candidates;
        candidate_count = backup_count;
    }

    /* Fail-open: if no available servers, fall back to non-down non-excluded */
    if (candidate_count == 0) {
        for (size_t i = 0; i < group->server_count; i++) {
            if (group->servers[i].is_down) {
                continue;
            }
            if ((excluded_mask & (1ULL << i)) == 0) {
                candidates[candidate_count++] = i;
            }
        }
    }

    if (candidate_count == 0) {
        return -1;
    }
    if (candidate_count == 1) {
        return (ssize_t)candidates[0];
    }

    if (group->policy == APEX_BALANCE_LEAST_CONN) {
        size_t start_idx = atomic_fetch_add_explicit(&group->round_robin_cursor, 1u, memory_order_relaxed) % candidate_count;
        size_t best = candidates[start_idx];
        int64_t min_conns = atomic_load_explicit(&group->servers[best].active_conns, memory_order_relaxed);
        for (size_t step = 1; step < candidate_count; step++) {
            size_t idx = (start_idx + step) % candidate_count;
            size_t i = candidates[idx];
            int64_t c = atomic_load_explicit(&group->servers[i].active_conns, memory_order_relaxed);
            if (c < min_conns) {
                min_conns = c;
                best = i;
            }
        }
        return (ssize_t)best;
    }

    if (group->policy == APEX_BALANCE_IP_HASH) {
        uint32_t hash = 2166136261u;
        if (client_ip != NULL && client_ip[0] != '\0') {
            for (const char *p = client_ip; *p; p++) {
                hash ^= (uint8_t)*p;
                hash *= 16777619u;
            }
        } else {
            hash = atomic_fetch_add_explicit(&group->round_robin_cursor, 1u, memory_order_relaxed);
        }
        return (ssize_t)candidates[hash % candidate_count];
    }

    if (group->policy == APEX_BALANCE_P2C) {
        size_t first_idx = random_below(candidate_count);
        size_t second_idx = random_below(candidate_count - 1u);
        if (second_idx >= first_idx) {
            second_idx++;
        }
        size_t first = candidates[first_idx];
        size_t second = candidates[second_idx];

        uint64_t first_score = server_load_score(&group->servers[first]);
        uint64_t second_score = server_load_score(&group->servers[second]);
        if (first_score < second_score) {
            return (ssize_t)first;
        }
        if (second_score < first_score) {
            return (ssize_t)second;
        }
        return (ssize_t)(thread_random() & 1u ? first : second);
    }

    /* Round Robin over candidates */
    uint64_t total_weight = 0;
    for (size_t idx = 0; idx < candidate_count; idx++) {
        size_t i = candidates[idx];
        total_weight += group->servers[i].weight ? group->servers[i].weight : 1u;
    }

    uint32_t cursor = atomic_fetch_add_explicit(&group->round_robin_cursor, 1u, memory_order_relaxed);
    if (total_weight == 0) {
        return (ssize_t)candidates[cursor % candidate_count];
    }

    uint64_t slot = (uint64_t)cursor % total_weight;
    uint64_t accumulated = 0;
    for (size_t idx = 0; idx < candidate_count; idx++) {
        size_t i = candidates[idx];
        accumulated += group->servers[i].weight ? group->servers[i].weight : 1u;
        if (slot < accumulated) {
            return (ssize_t)i;
        }
    }

    return (ssize_t)candidates[candidate_count - 1u];
}

ssize_t apex_upstream_select_excluding(upstream_group_t *group, uint64_t excluded_mask) {
    return apex_upstream_select_request(group, excluded_mask, NULL);
}

ssize_t apex_upstream_select(upstream_group_t *group) {
    return apex_upstream_select_request(group, 0, NULL);
}

void apex_proxy_response_init(apex_proxy_response_t *response) {
    if (response == NULL) {
        return;
    }
    memset(response, 0, sizeof(*response));
    response->upstream_fd = -1;
}

void apex_proxy_response_free(apex_proxy_response_t *response) {
    if (response == NULL) {
        return;
    }
    free(response->headers);
    free(response->body);
    free(response->leftover_data);
    if (response->upstream_fd >= 0) {
        close(response->upstream_fd);
        response->upstream_fd = -1;
    }
    memset(response, 0, sizeof(*response));
    response->upstream_fd = -1;
}

int apex_proxy_forward(upstream_group_t *group, const apex_proxy_request_t *request,
                       apex_proxy_response_t *response) {
    apex_proxy_response_init(response);

    if (group == NULL || request == NULL || response == NULL) {
        return APEX_PROXY_ERR_INVALID;
    }
    if (group->server_count == 0) {
        return APEX_PROXY_ERR_NO_UPSTREAM;
    }
    if (!is_http_method(request->method) || !is_request_target(request->target)) {
        return APEX_PROXY_ERR_INVALID;
    }
    if (request->headers_len > 0 && request->headers == NULL) {
        return APEX_PROXY_ERR_INVALID;
    }
    if (request->body_len > 0 && request->body == NULL) {
        return APEX_PROXY_ERR_INVALID;
    }
    if (request->host != NULL && (strchr(request->host, '\r') != NULL || strchr(request->host, '\n') != NULL)) {
        return APEX_PROXY_ERR_INVALID;
    }
    if (request->body_len > APEX_PROXY_MAX_REQUEST_BYTES ||
        request->headers_len > APEX_PROXY_MAX_REQUEST_BYTES - request->body_len) {
        return APEX_PROXY_ERR_TOO_LARGE;
    }

    uint32_t conditions = request->next_upstream_conditions;
    if (conditions == 0) {
        conditions = APEX_NEXT_UPSTREAM_DEFAULT;
    }
    bool next_disabled = (conditions & APEX_NEXT_UPSTREAM_OFF) != 0;

    uint32_t max_retries = group->max_retries;
    if (next_disabled) {
        max_retries = 0;
    } else if (request->next_upstream_tries > 0) {
        max_retries = request->next_upstream_tries > 1 ? request->next_upstream_tries - 1 : 0;
    } else if (group->server_count <= 1) {
        max_retries = 0;
    } else {
        max_retries = (uint32_t)(group->server_count - 1u);
    }

    uint64_t tried_mask = 0;
    int last_error = APEX_PROXY_ERR_NO_UPSTREAM;
    uint64_t started_us = monotonic_us();

    for (uint32_t attempt = 0; attempt <= max_retries; attempt++) {
        if (attempt > 0 && request->next_upstream_timeout_ms > 0) {
            uint64_t elapsed_ms = (monotonic_us() - started_us) / 1000ULL;
            if (elapsed_ms >= request->next_upstream_timeout_ms) {
                break;
            }
        }

        ssize_t selected = apex_upstream_select_request(group, tried_mask, request != NULL ? request->client_ip : NULL);
        if (selected < 0) {
            break;
        }
        tried_mask |= (1ULL << (size_t)selected);
        upstream_server_t *server = &group->servers[selected];

        atomic_fetch_add_explicit(&server->active_conns, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&server->total_requests, 1, memory_order_relaxed);

        buffer_t wire = {0};
        reader_t reader = {0};
        int fd = -1;
        int result = build_request(&wire, request, server);
        if (result != APEX_PROXY_OK) {
            atomic_fetch_sub_explicit(&server->active_conns, 1, memory_order_relaxed);
            return result;
        }

        bool is_ssl = server->use_ssl || group->use_ssl || request->use_ssl;
        SSL *ssl = NULL;
        bool from_pool = false;

        if (is_ssl) {
            fd = connect_server(server, group->connect_timeout_ms ? group->connect_timeout_ms
                                                                 : APEX_PROXY_DEFAULT_CONNECT_TIMEOUT_MS);
            if (fd < 0) {
                apex_upstream_record_failure(group, (size_t)selected);
                atomic_fetch_add_explicit(&server->failed_requests, 1, memory_order_relaxed);
                atomic_fetch_sub_explicit(&server->active_conns, 1, memory_order_relaxed);
                buffer_free(&wire);
                last_error = APEX_PROXY_ERR_CONNECT;
                if (!next_disabled && (conditions & APEX_NEXT_UPSTREAM_ERROR) && attempt < max_retries) {
                    continue;
                }
                return last_error;
            }
            pthread_once(&g_client_ssl_once, init_client_ssl_ctx);
            if (g_client_ssl_ctx == NULL) {
                close(fd);
                buffer_free(&wire);
                atomic_fetch_sub_explicit(&server->active_conns, 1, memory_order_relaxed);
                return APEX_PROXY_ERR_CONNECT;
            }
            ssl = SSL_new(g_client_ssl_ctx);
            if (ssl == NULL) {
                close(fd);
                buffer_free(&wire);
                atomic_fetch_sub_explicit(&server->active_conns, 1, memory_order_relaxed);
                return APEX_PROXY_ERR_CONNECT;
            }
            SSL_set_fd(ssl, fd);

            const char *sni = NULL;
            if (server->ssl_server_name[0] != '\0') {
                sni = server->ssl_server_name;
            } else if (group->ssl_server_name[0] != '\0') {
                sni = group->ssl_server_name;
            } else if (request->ssl_server_name != NULL && request->ssl_server_name[0] != '\0') {
                sni = request->ssl_server_name;
            } else if (server->use_ssl_sni && server->ip[0] != '\0') {
                sni = server->ip;
            }
            if (sni != NULL) {
                SSL_set_tlsext_host_name(ssl, sni);
            }

            apply_io_timeouts(fd, group);
            if (SSL_connect(ssl) <= 0) {
                SSL_free(ssl);
                close(fd);
                buffer_free(&wire);
                apex_upstream_record_failure(group, (size_t)selected);
                atomic_fetch_add_explicit(&server->failed_requests, 1, memory_order_relaxed);
                atomic_fetch_sub_explicit(&server->active_conns, 1, memory_order_relaxed);
                last_error = APEX_PROXY_ERR_CONNECT;
                if (!next_disabled && (conditions & APEX_NEXT_UPSTREAM_ERROR) && attempt < max_retries) {
                    continue;
                }
                return last_error;
            }
            thread_pool.total_created++;
        } else {
            fd = pool_acquire(server, group);
            from_pool = (fd >= 0);
            if (fd < 0) {
                fd = connect_server(server, group->connect_timeout_ms ? group->connect_timeout_ms
                                                                     : APEX_PROXY_DEFAULT_CONNECT_TIMEOUT_MS);
                if (fd < 0) {
                    apex_upstream_record_failure(group, (size_t)selected);
                    atomic_fetch_add_explicit(&server->failed_requests, 1, memory_order_relaxed);
                    atomic_fetch_sub_explicit(&server->active_conns, 1, memory_order_relaxed);
                    buffer_free(&wire);
                    last_error = APEX_PROXY_ERR_CONNECT;
                    if (!next_disabled && (conditions & APEX_NEXT_UPSTREAM_ERROR) && attempt < max_retries) {
                        continue;
                    }
                    return last_error;
                }
                thread_pool.total_created++;
            }

            apply_io_timeouts(fd, group);
        }

        result = send_all(fd, ssl, wire.data, wire.len);
        if (result != APEX_PROXY_OK) {
            if (ssl != NULL) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                ssl = NULL;
                close(fd);
                fd = -1;
            } else {
                pool_close(fd);
                fd = -1;
                if (from_pool) {
                    /* Connection was stale in pool, try fresh connection to the same server */
                    fd = connect_server(server, group->connect_timeout_ms ? group->connect_timeout_ms
                                                                         : APEX_PROXY_DEFAULT_CONNECT_TIMEOUT_MS);
                    if (fd >= 0) {
                        thread_pool.total_created++;
                        apply_io_timeouts(fd, group);
                        result = send_all(fd, NULL, wire.data, wire.len);
                    } else {
                        result = APEX_PROXY_ERR_CONNECT;
                    }
                }
            }
            if (result != APEX_PROXY_OK) {
                if (fd >= 0) {
                    pool_close(fd);
                    fd = -1;
                }
                buffer_free(&wire);
                apex_upstream_record_failure(group, (size_t)selected);
                atomic_fetch_add_explicit(&server->failed_requests, 1, memory_order_relaxed);
                atomic_fetch_sub_explicit(&server->active_conns, 1, memory_order_relaxed);
                last_error = result;
                bool can_retry = !next_disabled &&
                                 (conditions & APEX_NEXT_UPSTREAM_ERROR) &&
                                 (attempt < max_retries) &&
                                 (is_idempotent_method(request->method) || (conditions & APEX_NEXT_UPSTREAM_NON_IDEMPOTENT));
                if (can_retry) {
                    continue;
                }
                return result;
            }
        }
        atomic_fetch_add_explicit(&server->bytes_sent, wire.len, memory_order_relaxed);

        uint64_t limit64 = (uint64_t)(group->max_header_bytes ? group->max_header_bytes
                                                             : APEX_PROXY_DEFAULT_MAX_HEADER_BYTES) +
                           (uint64_t)(group->max_body_bytes ? group->max_body_bytes
                                                            : APEX_PROXY_DEFAULT_MAX_BODY_BYTES) +
                           65536u;
        uint64_t io_timeout = group->io_timeout_ms ? group->io_timeout_ms : APEX_PROXY_DEFAULT_IO_TIMEOUT_MS;
        if (io_timeout > 3600000u) {
            io_timeout = 3600000u;
        }
        reader.fd = fd;
        reader.ssl = ssl;
        reader.limit = limit64 > (uint64_t)SIZE_MAX ? SIZE_MAX : (size_t)limit64;
        reader.deadline_ms = monotonic_ms() + io_timeout;

        result = read_response(&reader, group, request, response);
        if (result != APEX_PROXY_OK) {
            if (ssl != NULL) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                ssl = NULL;
                close(fd);
                fd = -1;
            } else {
                pool_close(fd);
                fd = -1;
            }
            buffer_free(&wire);
            reader_free(&reader);
            apex_proxy_response_free(response);
            apex_upstream_record_failure(group, (size_t)selected);
            atomic_fetch_add_explicit(&server->failed_requests, 1, memory_order_relaxed);
            atomic_fetch_sub_explicit(&server->active_conns, 1, memory_order_relaxed);
            last_error = result;

            uint32_t matched_flag = 0;
            if (result == APEX_PROXY_ERR_TIMEOUT) {
                matched_flag = APEX_NEXT_UPSTREAM_TIMEOUT;
            } else if (result == APEX_PROXY_ERR_PROTOCOL) {
                matched_flag = APEX_NEXT_UPSTREAM_INVALID_HEADER;
            } else {
                matched_flag = APEX_NEXT_UPSTREAM_ERROR;
            }

            bool retry_method_ok = is_idempotent_method(request->method) || (conditions & APEX_NEXT_UPSTREAM_NON_IDEMPOTENT);
            if (!next_disabled && (conditions & matched_flag) && (attempt < max_retries) && retry_method_ok) {
                continue;
            }
            return result;
        }

        bool status_matched = false;
        if (response->status == 500 && (conditions & APEX_NEXT_UPSTREAM_HTTP_500)) status_matched = true;
        else if (response->status == 502 && (conditions & APEX_NEXT_UPSTREAM_HTTP_502)) status_matched = true;
        else if (response->status == 503 && (conditions & APEX_NEXT_UPSTREAM_HTTP_503)) status_matched = true;
        else if (response->status == 504 && (conditions & APEX_NEXT_UPSTREAM_HTTP_504)) status_matched = true;
        else if (response->status == 403 && (conditions & APEX_NEXT_UPSTREAM_HTTP_403)) status_matched = true;
        else if (response->status == 404 && (conditions & APEX_NEXT_UPSTREAM_HTTP_404)) status_matched = true;
        else if (response->status == 429 && (conditions & APEX_NEXT_UPSTREAM_HTTP_429)) status_matched = true;

        bool retry_method_ok = is_idempotent_method(request->method) || (conditions & APEX_NEXT_UPSTREAM_NON_IDEMPOTENT);
        bool timeout_ok = true;
        if (request->next_upstream_timeout_ms > 0) {
            uint64_t elapsed_ms = (monotonic_us() - started_us) / 1000ULL;
            if (elapsed_ms >= request->next_upstream_timeout_ms) {
                timeout_ok = false;
            }
        }

        if (status_matched && !next_disabled && (attempt < max_retries) && retry_method_ok && timeout_ok) {
            apex_upstream_record_failure(group, (size_t)selected);
            atomic_fetch_add_explicit(&server->failed_requests, 1, memory_order_relaxed);
            atomic_fetch_sub_explicit(&server->active_conns, 1, memory_order_relaxed);
            if (ssl != NULL) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                ssl = NULL;
                close(fd);
                fd = -1;
            } else if (fd >= 0) {
                pool_close(fd);
                fd = -1;
            }
            buffer_free(&wire);
            reader_free(&reader);
            apex_proxy_response_free(response);
            continue;
        }

        if (response->status >= 500) {
            apex_upstream_record_failure(group, (size_t)selected);
        } else {
            apex_upstream_record_success(group, (size_t)selected);
        }
        if (response->status == 101) {
            response->upstream_fd = fd;
            size_t unread = reader.len - reader.position;
            if (unread > 0) {
                response->leftover_data = malloc(unread);
                if (response->leftover_data != NULL) {
                    memcpy(response->leftover_data, reader.data + reader.position, unread);
                    response->leftover_len = unread;
                }
            }
            fd = -1;
        }

        bool reusable = !is_ssl && response->keep_alive && request->keep_alive && reader.len == reader.position && !reader.eof;
        response->keep_alive = reusable;
        response->server_index = (size_t)selected;
        response->elapsed_us = monotonic_us() - started_us;

        if (ssl != NULL) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = NULL;
            close(fd);
            fd = -1;
        } else if (reusable) {
            pool_release(server, group, fd);
            fd = -1;
        } else if (fd >= 0) {
            pool_close(fd);
            fd = -1;
        }
        buffer_free(&wire);
        reader_free(&reader);

        atomic_fetch_add_explicit(&server->bytes_received, response->headers_len + response->body_len,
                                  memory_order_relaxed);
        atomic_fetch_sub_explicit(&server->active_conns, 1, memory_order_relaxed);
        return APEX_PROXY_OK;
    }

    return last_error;
}

void apex_proxy_pool_reset(void) {
    for (size_t index = 0; index < thread_pool.count; index++) {
        close(thread_pool.entries[index].fd);
        thread_pool.entries[index].fd = -1;
        thread_pool.total_closed++;
    }
    thread_pool.count = 0;
}

void apex_proxy_pool_get_stats(apex_proxy_pool_stats_t *stats) {
    if (stats == NULL) {
        return;
    }
    stats->idle_connections = thread_pool.count;
    stats->capacity = APEX_PROXY_POOL_CAPACITY;
    stats->total_created = thread_pool.total_created;
    stats->total_reused = thread_pool.total_reused;
    stats->total_closed = thread_pool.total_closed;
}

const char *apex_proxy_strerror(int error_code) {
    switch (error_code) {
    case APEX_PROXY_OK:
        return "success";
    case APEX_PROXY_ERR_INVALID:
        return "invalid argument";
    case APEX_PROXY_ERR_NO_UPSTREAM:
        return "no upstream server";
    case APEX_PROXY_ERR_CONNECT:
        return "upstream connect failed";
    case APEX_PROXY_ERR_TIMEOUT:
        return "upstream timed out";
    case APEX_PROXY_ERR_IO:
        return "upstream I/O error";
    case APEX_PROXY_ERR_PROTOCOL:
        return "upstream protocol error";
    case APEX_PROXY_ERR_TOO_LARGE:
        return "response exceeds configured limit";
    case APEX_PROXY_ERR_ALLOC:
        return "memory allocation failed";
    default:
        return "unknown error";
    }
}

static pthread_t prober_thread;
static _Atomic bool prober_running = false;
static upstream_group_t *prober_groups = NULL;
static size_t prober_group_count = 0;

static void probe_single_server(upstream_group_t *group, upstream_server_t *server) {
    uint64_t timeout_ms = group->health_check_timeout_ms ? group->health_check_timeout_ms : 2000u;
    int fd = connect_server(server, timeout_ms);
    if (fd < 0) {
        atomic_store_explicit(&server->consecutive_successes, 0, memory_order_relaxed);
        uint32_t fails = atomic_fetch_add_explicit(&server->consecutive_failures, 1, memory_order_relaxed) + 1u;
        uint32_t fall = group->health_check_fall ? group->health_check_fall : 2u;
        if (fails >= fall) {
            atomic_store_explicit(&server->healthy, false, memory_order_relaxed);
        }
        atomic_store_explicit(&server->last_failure_time_ms, monotonic_ms(), memory_order_relaxed);
        return;
    }

    bool success = true;
    bool is_ssl = server->use_ssl || group->use_ssl;
    SSL *ssl = NULL;

    if (is_ssl) {
        pthread_once(&g_client_ssl_once, init_client_ssl_ctx);
        if (g_client_ssl_ctx != NULL) {
            ssl = SSL_new(g_client_ssl_ctx);
            if (ssl != NULL) {
                SSL_set_fd(ssl, fd);
                const char *sni = (server->ssl_server_name[0] != '\0') ? server->ssl_server_name : group->ssl_server_name;
                if (sni != NULL && sni[0] != '\0') {
                    SSL_set_tlsext_host_name(ssl, sni);
                }
                if (SSL_connect(ssl) <= 0) {
                    SSL_free(ssl);
                    ssl = NULL;
                    success = false;
                }
            } else {
                success = false;
            }
        } else {
            success = false;
        }
    }

    if (success && group->health_check_uri[0] != '\0') {
        char probe_request[256];
        int req_len = snprintf(probe_request, sizeof(probe_request),
                               "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: apex-health-prober\r\nConnection: close\r\n\r\n",
                               group->health_check_uri, server->ip);
        if (req_len > 0 && (size_t)req_len < sizeof(probe_request)) {
            struct timeval tv;
            tv.tv_sec = (time_t)(timeout_ms / 1000u);
            tv.tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u);
            (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

            if (send_all(fd, ssl, probe_request, (size_t)req_len) == 0) {
                char response_buf[128];
                ssize_t n;
                if (ssl != NULL) {
                    n = (ssize_t)SSL_read(ssl, response_buf, sizeof(response_buf) - 1);
                } else {
                    n = recv(fd, response_buf, sizeof(response_buf) - 1, 0);
                }
                if (n > 12) {
                    response_buf[n] = '\0';
                    int status = 0;
                    if (sscanf(response_buf, "HTTP/%*s %d", &status) == 1) {
                        if (status >= 200 && status < 400) {
                            success = true;
                        } else {
                            success = false;
                        }
                    } else {
                        success = false;
                    }
                } else {
                    success = false;
                }
            } else {
                success = false;
            }
        }
    }
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    } else {
        shutdown(fd, SHUT_WR);
        char drain_buf[512];
        while (recv(fd, drain_buf, sizeof(drain_buf), MSG_DONTWAIT) > 0) {}
    }
    close(fd);

    if (success) {
        atomic_store_explicit(&server->consecutive_failures, 0, memory_order_relaxed);
        uint32_t succ = atomic_fetch_add_explicit(&server->consecutive_successes, 1, memory_order_relaxed) + 1u;
        uint32_t rise = group->health_check_rise ? group->health_check_rise : 2u;
        if (succ >= rise) {
            atomic_store_explicit(&server->healthy, true, memory_order_relaxed);
        }
    } else {
        atomic_store_explicit(&server->consecutive_successes, 0, memory_order_relaxed);
        uint32_t fails = atomic_fetch_add_explicit(&server->consecutive_failures, 1, memory_order_relaxed) + 1u;
        uint32_t fall = group->health_check_fall ? group->health_check_fall : 2u;
        if (fails >= fall) {
            atomic_store_explicit(&server->healthy, false, memory_order_relaxed);
        }
        atomic_store_explicit(&server->last_failure_time_ms, monotonic_ms(), memory_order_relaxed);
    }
}

static void *prober_worker(void *arg) {
    (void)arg;
    while (atomic_load_explicit(&prober_running, memory_order_acquire)) {
        for (size_t g = 0; g < prober_group_count; g++) {
            upstream_group_t *group = &prober_groups[g];
            if (!group->health_check_enabled) {
                continue;
            }
            for (size_t s = 0; s < group->server_count; s++) {
                if (!atomic_load_explicit(&prober_running, memory_order_acquire)) {
                    break;
                }
                probe_single_server(group, &group->servers[s]);
            }
        }

        uint64_t interval = 5000;
        if (prober_group_count > 0 && prober_groups[0].health_check_interval_ms > 0) {
            interval = prober_groups[0].health_check_interval_ms;
        }
        uint64_t slices = interval / 100u;
        if (slices == 0) {
            slices = 1;
        }
        for (uint64_t i = 0; i < slices && atomic_load_explicit(&prober_running, memory_order_acquire); i++) {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 100000000L};
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

int apex_health_prober_start(upstream_group_t *groups, size_t group_count) {
    if (groups == NULL || group_count == 0) {
        return 0;
    }
    bool any_enabled = false;
    for (size_t i = 0; i < group_count; i++) {
        if (groups[i].health_check_enabled) {
            any_enabled = true;
            break;
        }
    }
    if (!any_enabled) {
        return 0;
    }
    if (atomic_load_explicit(&prober_running, memory_order_acquire)) {
        return 0;
    }
    prober_groups = groups;
    prober_group_count = group_count;
    atomic_store_explicit(&prober_running, true, memory_order_release);
    int rc = pthread_create(&prober_thread, NULL, prober_worker, NULL);
    if (rc != 0) {
        atomic_store_explicit(&prober_running, false, memory_order_release);
        return -1;
    }
    return 0;
}

void apex_health_prober_stop(void) {
    if (!atomic_load_explicit(&prober_running, memory_order_acquire)) {
        return;
    }
    atomic_store_explicit(&prober_running, false, memory_order_release);
    pthread_join(prober_thread, NULL);
    prober_groups = NULL;
    prober_group_count = 0;
}
