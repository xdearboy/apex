#include "apex/fastcgi.h"
#include "internal.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define APEX_FCGI_BUF_MAX (1024 * 1024 * 4)  /* 4MB max response buffer */

void apex_fastcgi_response_free(apex_fastcgi_response_t *resp) {
    if (resp == NULL) return;
    free(resp->headers);
    free(resp->body);
    memset(resp, 0, sizeof(*resp));
}

static uint64_t monotonic_now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static int connect_unix_socket(const char *path, uint64_t timeout_ms) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno == EINPROGRESS) {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
        int prc = poll(&pfd, 1, (int)timeout_ms);
        if (prc <= 0) {
            close(fd);
            return -1;
        }
        int err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
            close(fd);
            return -1;
        }
    } else if (rc < 0) {
        close(fd);
        return -1;
    }

    if (flags >= 0) fcntl(fd, F_SETFL, flags);
    return fd;
}

static int connect_tcp_socket(const char *host, uint16_t port, uint64_t timeout_ms) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *result = NULL;
    if (getaddrinfo(host, port_str, &hints, &result) != 0 || result == NULL) {
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc < 0 && errno == EINPROGRESS) {
            struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
            int prc = poll(&pfd, 1, (int)timeout_ms);
            if (prc <= 0) {
                close(fd);
                fd = -1;
                continue;
            }
            int err = 0;
            socklen_t len = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
                close(fd);
                fd = -1;
                continue;
            }
        } else if (rc < 0) {
            close(fd);
            fd = -1;
            continue;
        }

        if (flags >= 0) fcntl(fd, F_SETFL, flags);
        break;
    }

    freeaddrinfo(result);
    return fd;
}

static int connect_target(const char *target, uint64_t timeout_ms) {
    if (strncmp(target, "unix:", 5) == 0) {
        return connect_unix_socket(target + 5, timeout_ms);
    }

    char host[256];
    uint16_t port = 9000;
    const char *colon = strrchr(target, ':');
    if (colon != NULL) {
        size_t hlen = (size_t)(colon - target);
        if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
        memcpy(host, target, hlen);
        host[hlen] = '\0';
        port = (uint16_t)atoi(colon + 1);
    } else {
        snprintf(host, sizeof(host), "%s", target);
    }

    return connect_tcp_socket(host, port, timeout_ms);
}

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} fcgi_buf_t;

static bool fcgi_buf_ensure(fcgi_buf_t *b, size_t extra) {
    if (extra > (size_t)APEX_FCGI_BUF_MAX || b->len > (size_t)APEX_FCGI_BUF_MAX - extra) return false;
    if (b->len + extra <= b->cap) return true;
    size_t ncap = b->cap ? b->cap * 2 : 4096;
    while (ncap < b->len + extra) {
        if (ncap > SIZE_MAX / 2) {
            ncap = b->len + extra;
            break;
        }
        ncap *= 2;
    }
    if (ncap > (size_t)APEX_FCGI_BUF_MAX) {
        ncap = (size_t)APEX_FCGI_BUF_MAX;
    }
    if (ncap < b->len + extra) return false;
    char *ndata = realloc(b->data, ncap);
    if (!ndata) return false;
    b->data = ndata;
    b->cap = ncap;
    return true;
}

static bool fcgi_buf_append(fcgi_buf_t *b, const void *ptr, size_t len) {
    if (!fcgi_buf_ensure(b, len)) return false;
    memcpy(b->data + b->len, ptr, len);
    b->len += len;
    return true;
}

static bool fcgi_add_param(fcgi_buf_t *b, const char *name, const char *val) {
    if (name == NULL) return true;
    if (val == NULL) val = "";

    size_t nlen = strlen(name);
    size_t vlen = strlen(val);

    uint8_t header[8];
    size_t hpos = 0;

    if (nlen < 128) {
        header[hpos++] = (uint8_t)nlen;
    } else {
        header[hpos++] = (uint8_t)((nlen >> 24) | 0x80);
        header[hpos++] = (uint8_t)(nlen >> 16);
        header[hpos++] = (uint8_t)(nlen >> 8);
        header[hpos++] = (uint8_t)nlen;
    }

    if (vlen < 128) {
        header[hpos++] = (uint8_t)vlen;
    } else {
        header[hpos++] = (uint8_t)((vlen >> 24) | 0x80);
        header[hpos++] = (uint8_t)(vlen >> 16);
        header[hpos++] = (uint8_t)(vlen >> 8);
        header[hpos++] = (uint8_t)vlen;
    }

    if (!fcgi_buf_append(b, header, hpos)) return false;
    if (nlen > 0 && !fcgi_buf_append(b, name, nlen)) return false;
    if (vlen > 0 && !fcgi_buf_append(b, val, vlen)) return false;

    return true;
}

static bool send_all_bytes(int fd, const void *buf, size_t len, uint64_t timeout_ms) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t rem = len;
    while (rem > 0) {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
        int prc = poll(&pfd, 1, (int)timeout_ms);
        if (prc <= 0) return false;

        ssize_t n = send(fd, p, rem, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue;
            }
            return false;
        }
        p += n;
        rem -= (size_t)n;
    }
    return true;
}

static bool send_fcgi_record(int fd, uint8_t type, uint16_t req_id, const void *content, size_t content_len, uint64_t timeout_ms) {
    fcgi_header_t hdr = {
        .version = FCGI_VERSION_1,
        .type = type,
        .request_id_b1 = (uint8_t)(req_id >> 8),
        .request_id_b0 = (uint8_t)(req_id & 0xFF),
        .content_length_b1 = (uint8_t)(content_len >> 8),
        .content_length_b0 = (uint8_t)(content_len & 0xFF),
        .padding_length = 0,
        .reserved = 0,
    };
    if (!send_all_bytes(fd, &hdr, sizeof(hdr), timeout_ms)) return false;
    if (content_len > 0 && !send_all_bytes(fd, content, content_len, timeout_ms)) return false;
    return true;
}

static bool read_exact_bytes(int fd, void *buf, size_t len, uint64_t timeout_ms) {
    uint8_t *p = (uint8_t *)buf;
    size_t rem = len;
    while (rem > 0) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};
        int prc = poll(&pfd, 1, (int)timeout_ms);
        if (prc <= 0) return false;

        ssize_t n = recv(fd, p, rem, 0);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue;
            }
            return false;
        }
        p += n;
        rem -= (size_t)n;
    }
    return true;
}

int apex_fastcgi_forward(const apex_fastcgi_request_t *req, apex_fastcgi_response_t *resp) {
    if (req == NULL || resp == NULL || req->target == NULL) {
        return -1;
    }
    memset(resp, 0, sizeof(*resp));

    uint64_t start_us = monotonic_now_us();
    uint64_t conn_timeout = req->connect_timeout_ms ? req->connect_timeout_ms : 5000;
    uint64_t read_timeout = req->read_timeout_ms ? req->read_timeout_ms : 30000;

    int fd = connect_target(req->target, conn_timeout);
    if (fd < 0) {
        return -1;
    }

    uint16_t req_id = 1;

    /* 1. Send FCGI_BEGIN_REQUEST */
    fcgi_begin_request_body_t begin_body = {
        .role_b1 = 0,
        .role_b0 = FCGI_RESPONDER,
        .flags = 0,
        .reserved = {0},
    };
    if (!send_fcgi_record(fd, FCGI_BEGIN_REQUEST, req_id, &begin_body, sizeof(begin_body), conn_timeout)) {
        close(fd);
        return -2;
    }

    /* 2. Build FCGI_PARAMS buffer */
    fcgi_buf_t pbuf = {0};

    char client_port_str[16];
    char server_port_str[16];
    snprintf(client_port_str, sizeof(client_port_str), "%u", (unsigned)req->client_port);
    snprintf(server_port_str, sizeof(server_port_str), "%u", (unsigned)req->server_port);

    fcgi_add_param(&pbuf, "REQUEST_METHOD", req->method);
    fcgi_add_param(&pbuf, "REQUEST_URI", req->uri);
    fcgi_add_param(&pbuf, "DOCUMENT_URI", req->uri);
    fcgi_add_param(&pbuf, "DOCUMENT_ROOT", req->document_root ? req->document_root : "");
    fcgi_add_param(&pbuf, "SCRIPT_FILENAME", req->script_filename ? req->script_filename : "");
    fcgi_add_param(&pbuf, "SCRIPT_NAME", req->script_name ? req->script_name : req->uri);
    fcgi_add_param(&pbuf, "QUERY_STRING", req->query_string ? req->query_string : "");
    fcgi_add_param(&pbuf, "SERVER_PROTOCOL", "HTTP/1.1");
    fcgi_add_param(&pbuf, "GATEWAY_INTERFACE", "CGI/1.1");
    fcgi_add_param(&pbuf, "SERVER_SOFTWARE", "apex");
    fcgi_add_param(&pbuf, "REMOTE_ADDR", req->client_ip ? req->client_ip : "127.0.0.1");
    fcgi_add_param(&pbuf, "REMOTE_PORT", client_port_str);
    fcgi_add_param(&pbuf, "SERVER_ADDR", req->server_addr ? req->server_addr : "127.0.0.1");
    fcgi_add_param(&pbuf, "SERVER_PORT", server_port_str);
    fcgi_add_param(&pbuf, "SERVER_NAME", req->server_name ? req->server_name : "localhost");

    if (req->body_len > 0) {
        char clen_buf[32];
        snprintf(clen_buf, sizeof(clen_buf), "%zu", req->body_len);
        fcgi_add_param(&pbuf, "CONTENT_LENGTH", clen_buf);
    }

    /* Parse request headers to extract CONTENT_TYPE and HTTP_* params */
    if (req->raw_request != NULL && req->raw_request_len > 0) {
        const char *cursor = req->raw_request;
        const char *end = req->raw_request + req->raw_request_len;

        /* Skip request line */
        const char *first_crlf = memmem(cursor, (size_t)(end - cursor), "\r\n", 2);
        if (first_crlf != NULL) {
            cursor = first_crlf + 2;
            while (cursor < end) {
                const char *next_crlf = memmem(cursor, (size_t)(end - cursor), "\r\n", 2);
                if (next_crlf == NULL || next_crlf == cursor) break;

                const char *colon = memchr(cursor, ':', (size_t)(next_crlf - cursor));
                if (colon != NULL) {
                    size_t hname_len = (size_t)(colon - cursor);
                    const char *hval = colon + 1;
                    while (hval < next_crlf && (*hval == ' ' || *hval == '\t')) hval++;
                    size_t hval_len = (size_t)(next_crlf - hval);

                    char val_copy[1024];
                    if (hval_len < sizeof(val_copy)) {
                        memcpy(val_copy, hval, hval_len);
                        val_copy[hval_len] = '\0';

                        if (strncasecmp(cursor, "Content-Type", hname_len) == 0 && hname_len == 12) {
                            fcgi_add_param(&pbuf, "CONTENT_TYPE", val_copy);
                        } else if (strncasecmp(cursor, "Content-Length", hname_len) == 0 && hname_len == 14) {
                            /* Suppress duplicate: CONTENT_LENGTH already emitted from req->body_len */
                            if (req->body_len == 0) {
                                fcgi_add_param(&pbuf, "CONTENT_LENGTH", "0");
                            }
                        } else if ((strncasecmp(cursor, "Transfer-Encoding", hname_len) == 0 && hname_len == 17) ||
                                   (strncasecmp(cursor, "Connection", hname_len) == 0 && hname_len == 10)) {
                            /* Strip Transfer-Encoding and Connection hop-by-hop headers */
                        } else {
                            char http_name[128];
                            if (hname_len + 5 < sizeof(http_name)) {
                                memcpy(http_name, "HTTP_", 5);
                                for (size_t k = 0; k < hname_len; k++) {
                                    char c = cursor[k];
                                    if (c == '-') c = '_';
                                    http_name[5 + k] = (char)toupper((unsigned char)c);
                                }
                                http_name[5 + hname_len] = '\0';
                                fcgi_add_param(&pbuf, http_name, val_copy);
                            }
                        }
                    }
                }
                cursor = next_crlf + 2;
            }
        }
    }

    /* Send FCGI_PARAMS chunks */
    size_t pos = 0;
    while (pos < pbuf.len) {
        size_t chunk = pbuf.len - pos;
        if (chunk > 65535) chunk = 65535;
        if (!send_fcgi_record(fd, FCGI_PARAMS, req_id, pbuf.data + pos, chunk, conn_timeout)) {
            free(pbuf.data);
            close(fd);
            return -3;
        }
        pos += chunk;
    }
    free(pbuf.data);

    /* Empty FCGI_PARAMS closes the param stream */
    if (!send_fcgi_record(fd, FCGI_PARAMS, req_id, NULL, 0, conn_timeout)) {
        close(fd);
        return -3;
    }

    /* 3. Send FCGI_STDIN with request body */
    if (req->body != NULL && req->body_len > 0) {
        pos = 0;
        while (pos < req->body_len) {
            size_t chunk = req->body_len - pos;
            if (chunk > 65535) chunk = 65535;
            if (!send_fcgi_record(fd, FCGI_STDIN, req_id, req->body + pos, chunk, conn_timeout)) {
                close(fd);
                return -4;
            }
            pos += chunk;
        }
    }
    /* Empty FCGI_STDIN signals EOF */
    if (!send_fcgi_record(fd, FCGI_STDIN, req_id, NULL, 0, conn_timeout)) {
        close(fd);
        return -4;
    }

    /* 4. Read response records */
    fcgi_buf_t stdout_buf = {0};

    while (true) {
        fcgi_header_t h;
        if (!read_exact_bytes(fd, &h, sizeof(h), read_timeout)) {
            break;
        }
        if (h.version != FCGI_VERSION_1) {
            break;
        }

        uint16_t clen = ((uint16_t)h.content_length_b1 << 8) | (uint16_t)h.content_length_b0;
        uint8_t plen = h.padding_length;

        if (h.type == FCGI_STDOUT) {
            if (clen > 0) {
                if (stdout_buf.len + clen > (size_t)APEX_FCGI_BUF_MAX || !fcgi_buf_ensure(&stdout_buf, clen)) {
                    free(stdout_buf.data);
                    stdout_buf.data = NULL;
                    stdout_buf.len = 0;
                    close(fd);
                    resp->status = 502;
                    snprintf(resp->status_text, sizeof(resp->status_text), "Bad Gateway");
                    return -5;
                }
                if (!read_exact_bytes(fd, stdout_buf.data + stdout_buf.len, clen, read_timeout)) {
                    break;
                }
                stdout_buf.len += clen;
            }
            if (plen > 0) {
                char pad[256];
                if (!read_exact_bytes(fd, pad, plen, read_timeout)) {
                    break;
                }
            }
        } else if (h.type == FCGI_STDERR) {
            char discard[512];
            size_t to_read = (size_t)clen + (size_t)plen;
            while (to_read > 0) {
                size_t step = to_read > sizeof(discard) ? sizeof(discard) : to_read;
                if (!read_exact_bytes(fd, discard, step, read_timeout)) break;
                to_read -= step;
            }
        } else if (h.type == FCGI_END_REQUEST) {
            fcgi_end_request_body_t end_body;
            if (clen >= sizeof(end_body)) {
                (void)read_exact_bytes(fd, &end_body, sizeof(end_body), read_timeout);
                clen -= sizeof(end_body);
            }
            if (clen + plen > 0) {
                char pad[256];
                size_t to_read = (size_t)clen + (size_t)plen;
                while (to_read > 0) {
                    size_t step = to_read > sizeof(pad) ? sizeof(pad) : to_read;
                    if (!read_exact_bytes(fd, pad, step, read_timeout)) break;
                    to_read -= step;
                }
            }
            break;
        } else {
            /* Unknown or other record type: drain */
            size_t to_read = (size_t)clen + (size_t)plen;
            char discard[512];
            while (to_read > 0) {
                size_t step = to_read > sizeof(discard) ? sizeof(discard) : to_read;
                if (!read_exact_bytes(fd, discard, step, read_timeout)) break;
                to_read -= step;
            }
        }
    }
    close(fd);

    resp->elapsed_us = monotonic_now_us() - start_us;

    /* 5. Parse FastCGI stdout stream (Headers + Body) */
    resp->status = 200;
    snprintf(resp->status_text, sizeof(resp->status_text), "OK");

    if (stdout_buf.len == 0 || stdout_buf.data == NULL) {
        free(stdout_buf.data);
        return 0;
    }

    const char *header_sep = memmem(stdout_buf.data, stdout_buf.len, "\r\n\r\n", 4);
    size_t sep_len = 4;
    if (header_sep == NULL) {
        header_sep = memmem(stdout_buf.data, stdout_buf.len, "\n\n", 2);
        sep_len = 2;
    }

    if (header_sep == NULL) {
        /* Entire stdout is body */
        resp->body = stdout_buf.data;
        resp->body_len = stdout_buf.len;
        return 0;
    }

    size_t raw_hdr_len = (size_t)(header_sep - stdout_buf.data);
    const char *body_start = header_sep + sep_len;
    size_t body_len = stdout_buf.len - raw_hdr_len - sep_len;

    /* Extract Status: <status_code> <reason> if present */
    fcgi_buf_t clean_hdrs = {0};
    const char *line = stdout_buf.data;
    const char *hdr_end = stdout_buf.data + raw_hdr_len;

    while (line < hdr_end) {
        const char *next_line = memmem(line, (size_t)(hdr_end - line), "\r\n", 2);
        size_t line_len;
        size_t adv;
        if (next_line != NULL) {
            line_len = (size_t)(next_line - line);
            adv = line_len + 2;
        } else {
            next_line = memchr(line, '\n', (size_t)(hdr_end - line));
            if (next_line != NULL) {
                line_len = (size_t)(next_line - line);
                adv = line_len + 1;
            } else {
                line_len = (size_t)(hdr_end - line);
                adv = line_len;
            }
        }

        if (line_len > 7 && strncasecmp(line, "Status:", 7) == 0) {
            const char *val = line + 7;
            while (val < line + line_len && (*val == ' ' || *val == '\t')) val++;
            int sc = atoi(val);
            if (sc > 0) {
                resp->status = sc;
                while (val < line + line_len && isdigit((unsigned char)*val)) val++;
                while (val < line + line_len && (*val == ' ' || *val == '\t')) val++;
                size_t reason_len = (size_t)((line + line_len) - val);
                if (reason_len >= sizeof(resp->status_text)) {
                    reason_len = sizeof(resp->status_text) - 1;
                }
                if (reason_len > 0) {
                    memcpy(resp->status_text, val, reason_len);
                    resp->status_text[reason_len] = '\0';
                }
            }
        } else if (line_len > 0) {
            fcgi_buf_append(&clean_hdrs, line, line_len);
            fcgi_buf_append(&clean_hdrs, "\r\n", 2);
        }

        line += adv;
    }

    if (clean_hdrs.len > 0) {
        resp->headers = clean_hdrs.data;
        resp->headers_len = clean_hdrs.len;
    } else {
        free(clean_hdrs.data);
    }

    if (body_len > 0) {
        resp->body = malloc(body_len + 1);
        if (resp->body == NULL) {
            free(resp->headers);
            resp->headers = NULL;
            resp->headers_len = 0;
            free(stdout_buf.data);
            return -1;
        }
        memcpy(resp->body, body_start, body_len);
        resp->body[body_len] = '\0';
        resp->body_len = body_len;
    }
    free(stdout_buf.data);

    return 0;
}
