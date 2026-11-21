#include "internal.h"

#include <limits.h>
#include <netdb.h>
#include <openssl/err.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/uio.h>

typedef struct {
    char host[APEX_CONFIG_HOST_MAX];
    uint16_t port;
    bool tls;
    char certificate[APEX_CONFIG_PATH_MAX];
    char private_key[APEX_CONFIG_PATH_MAX];
    struct sockaddr_storage address;
    socklen_t address_length;
} listen_endpoint_t;

apex_server_stats_t g_apex_stats = {0};

static int close_fd(int *fd);
static bool configure_client(int fd);
static void register_connection(worker_arg_t *worker, int fd);
static bool tls_handshake_step(worker_arg_t *worker, conn_t *connection);
static void process_read_event(worker_arg_t *worker, conn_t *connection);
static inline void flush_write(worker_arg_t *worker, conn_t *connection);

static int close_fd(int *fd) {
    if (*fd < 0) {
        return 0;
    }
    int descriptor = *fd;
    *fd = -1;
    if (close(descriptor) != 0) {
        perror("apex: close");
        return -1;
    }
    return 0;
}

static int notify_fd(int fd) {
    const uint64_t notification = 1u;
    ssize_t written;
    do {
        written = write(fd, &notification, sizeof(notification));
    } while (written < 0 && errno == EINTR);
    if (written == (ssize_t)sizeof(notification) || (written < 0 && errno == EAGAIN)) {
        return 0;
    }
    if (written >= 0) {
        errno = EIO;
    }
    perror("apex: eventfd write");
    return -1;
}

static int drain_notification(int fd) {
    uint64_t notification;
    ssize_t received;
    do {
        received = read(fd, &notification, sizeof(notification));
    } while (received < 0 && errno == EINTR);
    if (received == (ssize_t)sizeof(notification) || (received < 0 && errno == EAGAIN)) {
        return 0;
    }
    if (received >= 0) {
        errno = EIO;
    }
    perror("apex: eventfd read");
    return -1;
}

static inline void close_conn(worker_arg_t *worker, conn_t *connection) {
    if (connection->h2 != NULL) {
        h2_connection_destroy(connection);
        connection->h2 = NULL;
    }
    if (connection->ssl != NULL) {
        /* Best-effort close_notify: sends FIN-path bytes while the socket is
         * still open so peers observe an orderly TLS close, not a RST. */
        SSL_shutdown(connection->ssl);
        SSL_free(connection->ssl);
        connection->ssl = NULL;
        connection->tls_phase = APEX_TLS_HANDSHAKE;
        connection->tls_want_write = 0;
    }

    free(connection->aux_buffer);
    connection->aux_buffer = NULL;
    connection->aux_length = 0;
    connection->aux_offset = 0;
    connection->aux_capacity = 0;

    if (connection->sendfile_remain > 0 && connection->sendfile_fd >= 0) {
        close(connection->sendfile_fd);
        connection->sendfile_fd = -1;
        connection->sendfile_remain = 0;
    }

    if (connection->active) {
        if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, connection->fd, NULL) != 0 && errno != ENOENT) {
            perror("apex: epoll_ctl remove connection");
        }
        if (close_fd(&connection->fd) != 0) {
            atomic_store_explicit(&worker->error, EIO, memory_order_relaxed);
        }
        atomic_fetch_sub_explicit(&g_apex_stats.active_connections, 1, memory_order_relaxed);
        if (connection->conn_state == 0) {
            atomic_fetch_sub_explicit(&g_apex_stats.reading_connections, 1, memory_order_relaxed);
        } else if (connection->conn_state == 1) {
            atomic_fetch_sub_explicit(&g_apex_stats.writing_connections, 1, memory_order_relaxed);
        } else if (connection->conn_state == 2) {
            atomic_fetch_sub_explicit(&g_apex_stats.waiting_connections, 1, memory_order_relaxed);
        }
        connection->active = 0;
        connection->conn_state = 0;
        worker->connection_count--;
        connection->read_length = 0;
        connection->write_length = 0;
        connection->write_offset = 0;
        connection->close_after_write = 0;
        connection->epollout_active = 0;
        connection->corked = 0;
        connection->transport = APEX_TRANSPORT_PLAIN;
    }
}

/* Transport and connection helpers shared with the HTTP/2 session layer. */

int apex_transport_write(conn_t *connection, const void *data, size_t length) {
    if (length > (size_t)INT_MAX) {
        length = (size_t)INT_MAX;
    }
    if (connection->transport == APEX_TRANSPORT_PLAIN) {
        ssize_t written = send(connection->fd, data, length, MSG_NOSIGNAL);
        if (written > 0) {
            return (int)written;
        }
        if (written < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            return -1;
        }
        return -2;
    }
    ERR_clear_error();
    int written = SSL_write(connection->ssl, data, (int)length);
    if (written > 0) {
        return written;
    }
    int ssl_error = SSL_get_error(connection->ssl, written);
    if (ssl_error == SSL_ERROR_WANT_WRITE || ssl_error == SSL_ERROR_WANT_READ) {
        errno = EAGAIN;
        return -1;
    }
    if (ssl_error == SSL_ERROR_SYSCALL && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
        return -1;
    }
    if (errno == 0) {
        errno = EIO;
    }
    return -2;
}

/* Transport read: bytes received (>0), 0 clean EOF, -1 retry
 * (errno EAGAIN/EINTR; WANT_WRITE also arms tls_want_write), -2 fatal. */
ssize_t apex_transport_read(conn_t *connection) {
    size_t space = sizeof(connection->read_buffer) - connection->read_length;
    if (space == 0) {
        return -1;
    }
    if (connection->transport == APEX_TRANSPORT_PLAIN) {
        ssize_t received = recv(connection->fd, connection->read_buffer + connection->read_length, space, 0);
        if (received >= 0) {
            return received;
        }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            return -1;
        }
        return -2;
    }
    ERR_clear_error();
    int received = SSL_read(connection->ssl, connection->read_buffer + connection->read_length, (int)space);
    if (received > 0) {
        return received;
    }
    int ssl_error = SSL_get_error(connection->ssl, received);
    switch (ssl_error) {
    case SSL_ERROR_ZERO_RETURN:
        return 0;
    case SSL_ERROR_WANT_READ:
        errno = EAGAIN;
        return -1;
    case SSL_ERROR_WANT_WRITE:
        connection->tls_want_write = 1;
        errno = EAGAIN;
        return -1;
    case SSL_ERROR_SYSCALL:
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            return -1;
        }
        if (errno == 0) {
            errno = ECONNRESET;
        }
        return -2;
    default:
        errno = EIO;
        return -2;
    }
}

static void tls_log_error(const char *message) {
    const unsigned long code = ERR_get_error();
    if (code != 0) {
        char reason[128];
        ERR_error_string_n(code, reason, sizeof(reason));
        fprintf(stderr, "apex: %s: %s\n", message, reason);
    } else {
        fprintf(stderr, "apex: %s\n", message);
    }
}

static bool tls_accept_connection(worker_arg_t *worker, conn_t *connection) {
    SSL *ssl = SSL_new(worker->generation->tls_context);
    if (ssl == NULL) {
        return false;
    }
    if (SSL_set_fd(ssl, connection->fd) != 1) {
        SSL_free(ssl);
        return false;
    }
    SSL_set_accept_state(ssl);
    connection->transport = APEX_TRANSPORT_TLS;
    connection->ssl = ssl;
    connection->tls_phase = APEX_TLS_HANDSHAKE;
    return true;
}

/* Returns true while the handshake is still progressing or just completed;
 * false means the connection was closed. */
static bool tls_handshake_step(worker_arg_t *worker, conn_t *connection) {
    ERR_clear_error();
    int result = SSL_do_handshake(connection->ssl);
    if (result == 1) {
        connection->tls_phase = APEX_TLS_READY;
        const unsigned char *protocol = NULL;
        unsigned int length = 0;
        SSL_get0_alpn_selected(connection->ssl, &protocol, &length);
        connection->alpn_h2 = (protocol != NULL && length == 2u && memcmp(protocol, "h2", 2u) == 0);
        if (connection->alpn_h2 && h2_connection_create(connection, worker) != 0) {
            tls_log_error("h2 session setup failed");
            close_conn(worker, connection);
            return false;
        }
        return true;
    }
    int ssl_error = SSL_get_error(connection->ssl, result);
    if (ssl_error == SSL_ERROR_WANT_READ) {
        return true;
    }
    if (ssl_error == SSL_ERROR_WANT_WRITE) {
        connection->tls_want_write = 1;
        if (!connection->epollout_active) {
            struct epoll_event event_config;
            event_config.events = EPOLLIN | EPOLLRDHUP | EPOLLOUT | EPOLLET;
            event_config.data.fd = connection->fd;
            if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, connection->fd, &event_config) != 0) {
                perror("apex: epoll_ctl handshake output");
                close_conn(worker, connection);
                return false;
            }
        }
        return true;
    }
    tls_log_error("tls handshake failed");
    close_conn(worker, connection);
    return false;
}

static void register_connection(worker_arg_t *worker, int fd) {
    if (fd >= MAX_FDS) {
        if (close_fd(&fd) != 0) {
            atomic_store_explicit(&worker->error, EIO, memory_order_relaxed);
        }
        return;
    }
    conn_t *connection = &worker->connections[fd];
    memset(connection, 0, sizeof(*connection));
    connection->fd = fd;
    connection->active = 1;
    connection->conn_state = 0; /* READING */
    worker->connection_count++;
    atomic_fetch_add_explicit(&g_apex_stats.accepts, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_apex_stats.handled, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_apex_stats.active_connections, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_apex_stats.reading_connections, 1, memory_order_relaxed);
    if (fd > worker->highest_fd) {
        worker->highest_fd = fd;
    }
    if (worker->listener_tls && (worker->generation->tls_context == NULL ||
                                 !tls_accept_connection(worker, connection))) {
        tls_log_error("tls accept setup failed");
        close_conn(worker, connection);
        return;
    }
    struct epoll_event client_event;
    client_event.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
    client_event.data.fd = fd;
    if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, fd, &client_event) != 0) {
        perror("apex: epoll_ctl add connection");
        close_conn(worker, connection);
    }
}

void apex_conn_write(conn_t *connection, const void *data, size_t length) {
    if (connection == NULL || data == NULL || length == 0) {
        return;
    }

    if (!connection->is_virtual && connection->conn_state != 1) {
        if (connection->conn_state == 0) {
            atomic_fetch_sub_explicit(&g_apex_stats.reading_connections, 1, memory_order_relaxed);
        } else if (connection->conn_state == 2) {
            atomic_fetch_sub_explicit(&g_apex_stats.waiting_connections, 1, memory_order_relaxed);
        }
        connection->conn_state = 1;
        atomic_fetch_add_explicit(&g_apex_stats.writing_connections, 1, memory_order_relaxed);
    }

    bool aux_pending = connection->aux_length > connection->aux_offset;

    if (!aux_pending && length <= sizeof(connection->write_buffer) - connection->write_length) {
        memcpy(connection->write_buffer + connection->write_length, data, length);
        connection->write_length += (uint32_t)length;
        return;
    }

    if (length > SIZE_MAX - connection->aux_length) {
        connection->close_after_write = 1;
        return;
    }

    size_t needed = connection->aux_length + length;
    if (needed > connection->aux_capacity) {
        size_t new_cap = connection->aux_capacity == 0 ? 16384 : connection->aux_capacity * 2;
        while (new_cap < needed) {
            if (new_cap > SIZE_MAX / 2) {
                new_cap = needed;
                break;
            }
            new_cap *= 2;
        }
        char *grown = realloc(connection->aux_buffer, new_cap);
        if (grown == NULL) {
            connection->close_after_write = 1;
            return;
        }
        connection->aux_buffer = grown;
        connection->aux_capacity = new_cap;
    }
    memcpy(connection->aux_buffer + connection->aux_length, data, length);
    connection->aux_length += length;
}

void apex_conn_sendfile(conn_t *connection, int file_fd, off_t offset, size_t length) {
    if (connection == NULL || file_fd < 0 || length == 0) {
        if (file_fd >= 0) {
            close(file_fd);
        }
        return;
    }
    if (!connection->is_virtual && connection->conn_state != 1) {
        if (connection->conn_state == 0) {
            atomic_fetch_sub_explicit(&g_apex_stats.reading_connections, 1, memory_order_relaxed);
        } else if (connection->conn_state == 2) {
            atomic_fetch_sub_explicit(&g_apex_stats.waiting_connections, 1, memory_order_relaxed);
        }
        connection->conn_state = 1;
        atomic_fetch_add_explicit(&g_apex_stats.writing_connections, 1, memory_order_relaxed);
    }
#if defined(__linux__)
    if (!connection->is_virtual && connection->transport == APEX_TRANSPORT_PLAIN) {
        if (connection->sendfile_remain > 0 && connection->sendfile_fd >= 0) {
            close(connection->sendfile_fd);
        }
        connection->sendfile_fd = file_fd;
        connection->sendfile_offset = offset;
        connection->sendfile_remain = length;
        return;
    }
#endif
    void *map = mmap(NULL, length, PROT_READ, MAP_PRIVATE, file_fd, offset);
    if (map != MAP_FAILED) {
        apex_conn_write(connection, map, length);
        munmap(map, length);
    } else {
        char buf[8192];
        if (lseek(file_fd, offset, SEEK_SET) != (off_t)-1) {
            size_t rem = length;
            while (rem > 0) {
                size_t to_read = rem < sizeof(buf) ? rem : sizeof(buf);
                ssize_t n = read(file_fd, buf, to_read);
                if (n <= 0) {
                    break;
                }
                apex_conn_write(connection, buf, (size_t)n);
                rem -= (size_t)n;
            }
        }
    }
    close(file_fd);
}

void apex_close_connection(worker_arg_t *worker, conn_t *connection) {
    close_conn(worker, connection);
}

void apex_arm_connection_output(worker_arg_t *worker, conn_t *connection) {
    if (connection->fd < 0 || connection->epollout_active) {
        return;
    }
    struct epoll_event event_config;
    event_config.events = EPOLLIN | EPOLLRDHUP | EPOLLOUT | EPOLLET;
    event_config.data.fd = connection->fd;
    if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, connection->fd, &event_config) != 0) {
        perror("apex: epoll_ctl arm output");
        close_conn(worker, connection);
        return;
    }
    connection->epollout_active = 1;
}

static inline void flush_write(worker_arg_t *worker, conn_t *connection) {
    while (connection->fd >= 0) {
        int bytes_sent = 0;

#if defined(__linux__) || defined(__unix__)
        if (connection->transport == APEX_TRANSPORT_PLAIN &&
            connection->write_length > connection->write_offset &&
            connection->aux_length > connection->aux_offset) {
            struct iovec iov[2];
            size_t w0 = connection->write_length - connection->write_offset;
            size_t w1 = connection->aux_length - connection->aux_offset;
            iov[0].iov_base = connection->write_buffer + connection->write_offset;
            iov[0].iov_len = w0;
            iov[1].iov_base = connection->aux_buffer + connection->aux_offset;
            iov[1].iov_len = w1;
            ssize_t written = writev(connection->fd, iov, 2);
            if (written > 0) {
                if ((size_t)written <= w0) {
                    connection->write_offset += (uint32_t)written;
                    if (connection->write_offset == connection->write_length) {
                        connection->write_offset = 0;
                        connection->write_length = 0;
                    }
                } else {
                    connection->write_offset = 0;
                    connection->write_length = 0;
                    size_t rem = (size_t)written - w0;
                    connection->aux_offset += rem;
                    if (connection->aux_offset == connection->aux_length) {
                        connection->aux_offset = 0;
                        connection->aux_length = 0;
                    }
                }
                continue;
            }
            if (written < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                bytes_sent = -1;
            } else {
                bytes_sent = -2;
            }
        } else
#endif
        if (connection->write_length > connection->write_offset) {
            size_t bytes_to_send = connection->write_length - connection->write_offset;
            bytes_sent = apex_transport_write(connection, connection->write_buffer + connection->write_offset,
                                              bytes_to_send);
            if (bytes_sent > 0) {
                connection->write_offset += (uint32_t)bytes_sent;
                if (connection->write_offset == connection->write_length) {
                    connection->write_offset = 0;
                    connection->write_length = 0;
                }
            }
        } else if (connection->aux_length > connection->aux_offset) {
            size_t bytes_to_send = connection->aux_length - connection->aux_offset;
            bytes_sent = apex_transport_write(connection, connection->aux_buffer + connection->aux_offset,
                                              bytes_to_send);
            if (bytes_sent > 0) {
                connection->aux_offset += (size_t)bytes_sent;
                if (connection->aux_offset == connection->aux_length) {
                    connection->aux_length = 0;
                    connection->aux_offset = 0;
                }
            }
        } else {
            break;
        }

        if (bytes_sent > 0 || (bytes_sent < 0 && errno == EINTR)) {
            continue;
        }
        if (bytes_sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        close_conn(worker, connection);
        return;
    }

#if defined(__linux__)
    if (connection->fd >= 0 && connection->transport == APEX_TRANSPORT_PLAIN &&
        connection->sendfile_remain > 0 && !connection->corked) {
        int cork = 1;
        setsockopt(connection->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
        connection->corked = 1;
    }

    if (connection->fd >= 0 && connection->transport == APEX_TRANSPORT_PLAIN &&
        connection->write_length == connection->write_offset &&
        connection->aux_length == connection->aux_offset &&
        connection->sendfile_remain > 0) {
        while (connection->sendfile_remain > 0) {
            ssize_t sent = sendfile(connection->fd, connection->sendfile_fd,
                                    &connection->sendfile_offset, connection->sendfile_remain);
            if (sent > 0) {
                connection->sendfile_remain -= (size_t)sent;
                if (connection->sendfile_remain == 0) {
                    close(connection->sendfile_fd);
                    connection->sendfile_fd = -1;
                    break;
                }
                continue;
            }
            if (sent < 0 && errno == EINTR) {
                continue;
            }
            if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            }
            close(connection->sendfile_fd);
            connection->sendfile_fd = -1;
            connection->sendfile_remain = 0;
            close_conn(worker, connection);
            return;
        }
    }

    if (connection->corked && connection->sendfile_remain == 0 &&
        connection->write_length == connection->write_offset &&
        connection->aux_length == connection->aux_offset && connection->fd >= 0) {
        int cork = 0;
        setsockopt(connection->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
        connection->corked = 0;
    }
#endif

    if (connection->fd < 0) {
        return;
    }

    bool pending = connection->write_length > connection->write_offset ||
                   connection->aux_length > connection->aux_offset ||
                   connection->sendfile_remain > 0;

    if (!pending && connection->close_after_write) {
        close_conn(worker, connection);
        return;
    }

    if (!pending && connection->conn_state == 1) {
        connection->conn_state = 2; /* WAITING */
        atomic_fetch_sub_explicit(&g_apex_stats.writing_connections, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&g_apex_stats.waiting_connections, 1, memory_order_relaxed);
    }

    if (pending && !connection->epollout_active) {
        struct epoll_event event_config;
        event_config.events = EPOLLOUT | EPOLLRDHUP | EPOLLET;
        if (!connection->close_after_write) {
            event_config.events |= EPOLLIN;
        }
        event_config.data.fd = connection->fd;
        if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, connection->fd, &event_config) != 0) {
            perror("apex: epoll_ctl enable output");
            close_conn(worker, connection);
            return;
        }
        connection->epollout_active = 1;
    } else if (!pending && connection->epollout_active) {
        struct epoll_event event_config;
        event_config.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
        event_config.data.fd = connection->fd;
        if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, connection->fd, &event_config) != 0) {
            perror("apex: epoll_ctl disable output");
            close_conn(worker, connection);
            return;
        }
        connection->epollout_active = 0;
    }
}

static inline bool request_has_connection_close(const char *headers, size_t len) {
    if (len < 16) {
        return false;
    }
    const char *p = headers;
    const char *end = headers + len - 11;
    while (p <= end) {
        char ch = *p;
        if (ch == 'C' || ch == 'c') {
            if (strncasecmp(p, "connection:", 11) == 0) {
                size_t offset = (size_t)(p - headers) + 11;
                const char *val = headers + offset;
                size_t rem = len - offset;
                const char *crlf = memchr(val, '\r', rem);
                size_t line_len = crlf != NULL ? (size_t)(crlf - val) : rem;
                for (size_t i = 0; i + 5 <= line_len; i++) {
                    if ((val[i] == 'c' || val[i] == 'C') && strncasecmp(val + i, "close", 5) == 0) {
                        return true;
                    }
                }
                return false;
            }
        }
        p++;
    }
    return false;
}

static inline char *find_crlfcrlf(const char *buf, size_t len) {
    if (len < 4) {
        return NULL;
    }
    const char *p = buf;
    const char *end = buf + len - 3;
    while (p < end) {
        p = memchr(p, '\r', (size_t)(end - p));
        if (p == NULL) {
            return NULL;
        }
        uint32_t val;
        memcpy(&val, p, 4);
        if (val == 0x0a0d0a0du) {
            return (char *)p;
        }
        p++;
    }
    return NULL;
}

/* Reads available transport bytes, runs the pipelined h1 parser over them
 * and flushes any generated output. The EPOLLIN and EPOLLOUT handlers both
 * funnel here so a TLS read that wants a write resumes without a peer kick. */
static void process_read_event(worker_arg_t *worker, conn_t *connection) {
    if (connection->h2 != NULL) {
        h2_read(worker, connection);
        return;
    }

    if (connection->conn_state == 2) {
        connection->conn_state = 0; /* READING */
        atomic_fetch_sub_explicit(&g_apex_stats.waiting_connections, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&g_apex_stats.reading_connections, 1, memory_order_relaxed);
    }

    while (connection->fd >= 0) {
        ssize_t bytes_received = apex_transport_read(connection);
        if (bytes_received > 0) {
            connection->read_length += (uint32_t)bytes_received;
            if (find_crlfcrlf(connection->read_buffer, connection->read_length) != NULL) {
                break;
            }
        } else if (bytes_received == 0) {
            close_conn(worker, connection);
            return;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        } else {
            close_conn(worker, connection);
            return;
        }

        if (connection->read_length == sizeof(connection->read_buffer)) {
            break;
        }
    }

    if (connection->fd < 0 || connection->read_length == 0) {
        return;
    }

    static const char H2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if (connection->read_length >= sizeof(H2_PREFACE) - 1u &&
        memcmp(connection->read_buffer, H2_PREFACE, sizeof(H2_PREFACE) - 1u) == 0) {
        if (h2_start_prior_knowledge(worker, connection) != 0) {
            close_conn(worker, connection);
        }
        return;
    }
    if (connection->read_length < sizeof(H2_PREFACE) - 1u &&
        memcmp(connection->read_buffer, H2_PREFACE, connection->read_length) == 0) {
        return;
    }

    char *buffer_cursor = connection->read_buffer;
    size_t remaining_bytes = connection->read_length;

    while (remaining_bytes >= 4) {
        char *crlf_delimiter = find_crlfcrlf(buffer_cursor, remaining_bytes);
        if (!crlf_delimiter) {
            break;
        }

        size_t header_length = (size_t)((crlf_delimiter + 4) - buffer_cursor);
        size_t content_length = 0;

        /* Fast search for Content-Length */
        if (header_length > 18) {
            const char *cl = buffer_cursor;
            const char *cl_end = buffer_cursor + header_length - 15;
            while (cl <= cl_end) {
                char ch = *cl;
                if (ch == 'C' || ch == 'c') {
                    if (strncasecmp(cl, "content-length:", 15) == 0) {
                        const char *val = cl + 15;
                        while (*val == ' ' || *val == '\t') val++;
                        content_length = strtoul(val, NULL, 10);
                        break;
                    }
                }
                cl++;
            }
        }

        if (content_length > sizeof(connection->read_buffer) - header_length) {
            close_conn(worker, connection);
            return;
        }
        if (remaining_bytes - header_length < content_length) {
            break;
        }

        if (request_has_connection_close(buffer_cursor, header_length)) {
            connection->close_after_write = 1;
        }

        apex_res_t response = {.conn = connection};
        const apex_runtime_t *runtime = worker->generation != NULL ? worker->generation->runtime : NULL;
        apex_dispatch_runtime(worker->app, runtime, buffer_cursor, header_length,
                              buffer_cursor + header_length, content_length, &response);

        size_t total_request_length = header_length + content_length;
        buffer_cursor += total_request_length;
        remaining_bytes -= total_request_length;
        if (atomic_load_explicit(&worker->control->shutdown, memory_order_acquire) != WORKERS_RUNNING) {
            connection->close_after_write = 1;
            remaining_bytes = 0;
            break;
        }
    }

    if (connection->fd < 0) {
        return;
    }

    if (remaining_bytes > 0 && buffer_cursor != connection->read_buffer) {
        memmove(connection->read_buffer, buffer_cursor, remaining_bytes);
    }
    connection->read_length = (uint32_t)remaining_bytes;

    /* A TLS read may need a write first (renegotiation, key update): the
     * socket must then also watch EPOLLOUT or the connection stalls. */
    if (connection->tls_want_write && !connection->epollout_active) {
        struct epoll_event event_config;
        event_config.events = EPOLLIN | EPOLLRDHUP | EPOLLOUT | EPOLLET;
        event_config.data.fd = connection->fd;
        if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, connection->fd, &event_config) != 0) {
            perror("apex: epoll_ctl read output interest");
            close_conn(worker, connection);
            return;
        }
    }

    flush_write(worker, connection);
}

static void adopt_generation(worker_arg_t *worker) {
    apex_generation_t *generation =
        atomic_exchange_explicit(&worker->pending_generation, NULL, memory_order_acq_rel);
    if (generation != NULL) {
        /* Mailbox exchange transfers its reference to this worker. No request
         * is active at this boundary, so the previous generation can go. */
        apex_proxy_pool_reset();
        apex_generation_release(worker->generation);
        worker->generation = generation;
    }
}

static void begin_drain(worker_arg_t *worker) {
    /* Adopt everything already queued on the listener before it goes away so
     * queued connections close with FIN instead of a listener-close RST. */
    for (;;) {
        int queued_fd = accept4(worker->listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (queued_fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) {
                continue;
            }
            break;
        }
        if (queued_fd < MAX_FDS && configure_client(queued_fd)) {
            register_connection(worker, queued_fd);
            continue;
        }
        if (close_fd(&queued_fd) != 0) {
            atomic_store_explicit(&worker->error, EIO, memory_order_relaxed);
        }
    }

    if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, worker->listen_fd, NULL) != 0) {
        perror("apex: epoll_ctl stop listener");
        atomic_store_explicit(&worker->error, EIO, memory_order_relaxed);
    }
    worker->listen_fd = -1;
    for (int fd = 0; fd <= worker->highest_fd; fd++) {
        conn_t *connection = &worker->connections[fd];
        if (connection->active) {
            connection->close_after_write = 1;
            if (connection->h2 != NULL) {
                h2_drain(worker, connection);
            } else {
                flush_write(worker, connection);
            }
        }
    }
}

static inline bool configure_client(int fd) {
#if !defined(__linux__)
    const int enabled = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
#else
    (void)fd;
#endif
    return true;
}

static void *worker_main(void *arg) {
    worker_arg_t *worker = arg;
    conn_t *connections = worker->connections;
    int epoll_fd = worker->epoll_fd;
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(worker->cpu, &affinity);
    int affinity_error = pthread_setaffinity_np(pthread_self(), sizeof(affinity), &affinity);
    if (affinity_error != 0) {
        fprintf(stderr, "apex: cannot pin worker to CPU %d: %s\n", worker->cpu, strerror(affinity_error));
    }

    struct epoll_event events[MAX_EVENTS];
    bool draining = false;
    for (;;) {
        adopt_generation(worker);
        int shutdown = atomic_load_explicit(&worker->control->shutdown, memory_order_acquire);
        if (shutdown == WORKERS_STOPPING) {
            break;
        }
        if (shutdown == WORKERS_DRAINING && !draining) {
            begin_drain(worker);
            draining = true;
        }
        if (draining && worker->connection_count == 0) {
            break;
        }

        int ready_events_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (ready_events_count < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("apex: epoll_wait");
            atomic_store_explicit(&worker->error, errno != 0 ? errno : EIO, memory_order_relaxed);
            break;
        }

        for (int event_index = 0; event_index < ready_events_count; event_index++) {
            if (atomic_load_explicit(&worker->control->shutdown, memory_order_acquire) != WORKERS_RUNNING &&
                !draining) {
                break;
            }
            if (atomic_load_explicit(&worker->control->shutdown, memory_order_acquire) == WORKERS_STOPPING) {
                goto worker_finished;
            }
            int active_fd = events[event_index].data.fd;
            uint32_t active_event_flags = events[event_index].events;

            if (active_fd == worker->wake_fd) {
                if (drain_notification(worker->wake_fd) != 0) {
                    atomic_store_explicit(&worker->error, EIO, memory_order_relaxed);
                    goto worker_finished;
                }
                continue;
            }
            if (active_fd == worker->listen_fd) {
                while (1) {
                    if (atomic_load_explicit(&worker->control->shutdown, memory_order_acquire) != WORKERS_RUNNING) {
                        break;
                    }
                    int client_socket_fd = accept4(worker->listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
                    if (client_socket_fd < 0) {
                        if (errno == EINTR || errno == ECONNABORTED) {
                            continue;
                        }
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        perror("apex: accept4");
                        atomic_store_explicit(&worker->error, errno != 0 ? errno : EIO, memory_order_relaxed);
                        goto worker_finished;
                    }

                    if (client_socket_fd >= MAX_FDS || !configure_client(client_socket_fd)) {
                        if (close_fd(&client_socket_fd) != 0) {
                            atomic_store_explicit(&worker->error, EIO, memory_order_relaxed);
                        }
                        continue;
                    }

                    register_connection(worker, client_socket_fd);
                }
                continue;
            }

            if (active_fd < 0 || active_fd >= MAX_FDS) {
                continue;
            }
            conn_t *connection = &connections[active_fd];
            if (!connection->active) {
                continue;
            }

            if (active_event_flags & (EPOLLERR | EPOLLHUP)) {
                close_conn(worker, connection);
                continue;
            }
            /* TLS peers signal orderly close via close_notify, which surfaces
             * as readable bytes; a bare EPOLLRDHUP must not pre-empt them. */
            if ((active_event_flags & EPOLLRDHUP) && connection->transport == APEX_TRANSPORT_PLAIN) {
                close_conn(worker, connection);
                continue;
            }

            if ((active_event_flags & EPOLLIN) && (!draining || connection->h2 != NULL)) {
                if (connection->transport == APEX_TRANSPORT_TLS && connection->tls_phase == APEX_TLS_HANDSHAKE) {
                    if (!tls_handshake_step(worker, connection)) {
                        continue;
                    }
                    if (connection->tls_phase != APEX_TLS_READY) {
                        continue;
                    }
                }
                process_read_event(worker, connection);
            }

            if ((active_event_flags & EPOLLOUT) && connection->fd >= 0) {
                if (connection->h2 != NULL) {
                    h2_flush(worker, connection);
                    continue;
                }
                flush_write(worker, connection);
                if (connection->fd >= 0 && connection->tls_want_write) {
                    connection->tls_want_write = 0;
                    bool ready = connection->tls_phase == APEX_TLS_READY;
                    if (!ready && !tls_handshake_step(worker, connection)) {
                        continue;
                    }
                    if (connection->fd >= 0) {
                        process_read_event(worker, connection);
                    }
                }
            }

        }
    }

worker_finished:
    for (int fd = 0; fd <= worker->highest_fd; fd++) {
        if (connections[fd].active) {
            close_conn(worker, &connections[fd]);
        }
    }
    apex_proxy_pool_reset();
    apex_generation_release(worker->generation);
    worker->generation = NULL;
    atomic_store_explicit(&worker->finished, true, memory_order_release);
    if (notify_fd(worker->control->status_fd) != 0) {
        atomic_store_explicit(&worker->error, EIO, memory_order_relaxed);
    }
    return NULL;
}

static int listener_error(const apex_config_t *config, int line, apex_config_error_t *error, const char *message) {
    memset(error, 0, sizeof(*error));
    error->code = APEX_CONFIG_ERR_RUNTIME;
    error->line = line;
    snprintf(error->file, sizeof(error->file), "%s", config->source);
    snprintf(error->message, sizeof(error->message), "%s", message);
    return -1;
}

static int config_listener(const apex_config_t *config, listen_endpoint_t *endpoint, apex_config_error_t *error) {
    if (config->server_count == 0) {
        return listener_error(config, 0, error, "configuration needs a server with a listen directive");
    }
    const apex_server_config_t *first = &config->servers[0];
    for (size_t index = 0; index < config->server_count; index++) {
        const apex_server_config_t *server = &config->servers[index];
        if (server->listen_tls != first->listen_tls) {
            return listener_error(config, server->line, error,
                                  "cannot mix tls and plaintext servers on one listen endpoint");
        }
        if (server->listen_port == 0) {
            return listener_error(config, server->line, error, "the standalone core requires a nonzero listen port");
        }
        if (server->listen_port != first->listen_port || strcmp(server->listen_host, first->listen_host) != 0) {
            return listener_error(config, server->line, error,
                                  "the standalone core supports one listening endpoint; virtual hosts must share it");
        }
    }
    snprintf(endpoint->host, sizeof(endpoint->host), "%s", first->listen_host);
    endpoint->port = first->listen_port;
    endpoint->tls = first->listen_tls;
    if (first->listen_tls) {
        snprintf(endpoint->certificate, sizeof(endpoint->certificate), "%s", first->tls.certificate);
        snprintf(endpoint->private_key, sizeof(endpoint->private_key), "%s", first->tls.private_key);
    }
    return 0;
}

static void report_config_error(const char *prefix, const apex_config_error_t *error) {
    fprintf(stderr, "apex: %s: %s:%d:%d: %s\n", prefix, error->file, error->line, error->column, error->message);
    if (error->hint[0] != '\0') {
        fprintf(stderr, "  hint: %s\n", error->hint);
    }
}

static int resolve_listener(listen_endpoint_t *endpoint) {
    char service[6];
    int written = snprintf(service, sizeof(service), "%u", (unsigned)endpoint->port);
    if (written < 0 || (size_t)written >= sizeof(service)) {
        fprintf(stderr, "apex: cannot format listen port\n");
        return -1;
    }
    struct addrinfo hints = {0};
    hints.ai_family = strchr(endpoint->host, ':') != NULL ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    struct addrinfo *addresses = NULL;
    int status = getaddrinfo(endpoint->host[0] != '\0' ? endpoint->host : NULL, service, &hints, &addresses);
    if (status != 0) {
        fprintf(stderr, "apex: cannot resolve listen address: %s\n",
                status == EAI_SYSTEM ? strerror(errno) : gai_strerror(status));
        return -1;
    }
    if (addresses == NULL || addresses->ai_addrlen > sizeof(endpoint->address)) {
        fprintf(stderr, "apex: unsupported listen address\n");
        if (addresses != NULL) {
            freeaddrinfo(addresses);
        }
        return -1;
    }
    memcpy(&endpoint->address, addresses->ai_addr, addresses->ai_addrlen);
    endpoint->address_length = addresses->ai_addrlen;
    freeaddrinfo(addresses);
    return 0;
}

static int create_listener_socket(const listen_endpoint_t *endpoint) {
    int fd = socket(endpoint->address.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("apex: socket listener");
        return -1;
    }
    const int enabled = 1;
    const int idle_seconds = 15;
    const int interval_seconds = 5;
    const int probe_count = 3;
    const unsigned int user_timeout_ms = 15000;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0 ||
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled)) != 0 ||
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle_seconds, sizeof(idle_seconds)) != 0 ||
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval_seconds, sizeof(interval_seconds)) != 0 ||
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &probe_count, sizeof(probe_count)) != 0 ||
        setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms, sizeof(user_timeout_ms)) != 0 ||
        (endpoint->address.ss_family == AF_INET6 &&
         setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled)) != 0)) {
        perror("apex: configure listener socket");
        close(fd);
        return -1;
    }
    if (bind(fd, (const struct sockaddr *)&endpoint->address, endpoint->address_length) != 0) {
        perror("apex: bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 65535) != 0) {
        perror("apex: listen");
        close(fd);
        return -1;
    }
    return fd;
}

static int prepare_worker(worker_arg_t *worker, const listen_endpoint_t *endpoint, int shared_listen_fd) {
    worker->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (worker->epoll_fd < 0) {
        perror("apex: epoll_create1");
        return -1;
    }
    worker->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (worker->wake_fd < 0) {
        perror("apex: eventfd worker");
        return -1;
    }
    worker->listen_fd = shared_listen_fd;
    struct epoll_event event = {.events = EPOLLIN | EPOLLEXCLUSIVE, .data.fd = worker->listen_fd};
    if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, worker->listen_fd, &event) != 0) {
        perror("apex: epoll_ctl listener");
        return -1;
    }
    event.events = EPOLLIN;
    event.data.fd = worker->wake_fd;
    if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, worker->wake_fd, &event) != 0) {
        perror("apex: epoll_ctl worker control");
        return -1;
    }
    worker->connections = mmap(NULL, sizeof(conn_t) * MAX_FDS, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (worker->connections == MAP_FAILED) {
        worker->connections = NULL;
        perror("apex: mmap connections");
        return -1;
    }
    /* Zero-filled mappings use active == 0, so startup need not dirty every
     * connection page merely to initialize a file-descriptor sentinel. */
    worker->generation = worker->app->generation;
    apex_generation_retain(worker->generation);
    worker->listener_tls = endpoint->tls;
    return 0;
}

static int wake_workers(worker_arg_t *workers, size_t count) {
    int status = 0;
    for (size_t index = 0; index < count; index++) {
        if (notify_fd(workers[index].wake_fd) != 0) {
            status = -1;
        }
    }
    return status;
}

static int reload_config(apex_app_t *app, const char *path, const listen_endpoint_t *listener,
                         worker_arg_t *workers, size_t count) {
    apex_config_error_t error = {0};
    apex_config_t *config = NULL;
    if (apex_config_parse_file(path, &config, &error) != APEX_CONFIG_OK) {
        report_config_error("reload rejected; keeping previous configuration", &error);
        return 0;
    }
    listen_endpoint_t candidate = {0};
    if (config_listener(config, &candidate, &error) != 0) {
        report_config_error("reload rejected; keeping previous configuration", &error);
        apex_config_free(config);
        return 0;
    }
    if (candidate.port != listener->port || strcmp(candidate.host, listener->host) != 0 || candidate.tls != listener->tls ||
        (candidate.tls && (strcmp(candidate.certificate, listener->certificate) != 0 ||
                           strcmp(candidate.private_key, listener->private_key) != 0))) {
        listener_error(config, config->servers[0].line, &error, "changing the listening endpoint requires a restart");
        report_config_error("reload rejected; keeping previous configuration", &error);
        apex_config_free(config);
        return 0;
    }
    apex_generation_t *generation = apex_generation_create(config, &error);
    if (generation == NULL) {
        report_config_error("reload rejected; keeping previous configuration", &error);
        apex_config_free(config);
        return 0;
    }

    apex_generation_t *previous = app->generation;
    app->generation = generation;
    for (size_t index = 0; index < count; index++) {
        apex_generation_retain(generation);
        apex_generation_t *pending =
            atomic_exchange_explicit(&workers[index].pending_generation, generation, memory_order_acq_rel);
        apex_generation_release(pending);
    }
    apex_generation_release(previous);
    if (wake_workers(workers, count) != 0) {
        return -1;
    }
    fprintf(stderr, "apex: configuration reloaded: %s\n", path);
    return 0;
}

static int run_app(apex_app_t *app, int port, const char *config_path) {
    if (app == NULL || (config_path != NULL && (config_path[0] == '\0' || app->generation == NULL))) {
        fprintf(stderr, "apex: invalid application or configuration path\n");
        return 1;
    }
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(&app->running, &expected, true,
                                                 memory_order_acq_rel, memory_order_acquire)) {
        fprintf(stderr, "apex: application is already running\n");
        return 1;
    }

    int result = 1;
    int signal_fd = -1;
    int shared_listen_fd = -1;
    size_t worker_count = 0;
    size_t started = 0;
    worker_arg_t *workers = NULL;
    run_control_t control = {.status_fd = -1};
    atomic_init(&control.shutdown, WORKERS_RUNNING);
    bool mask_changed = false;
    bool pipe_changed = false;
    sigset_t signals;
    sigset_t previous_mask;
    struct sigaction previous_pipe;
    listen_endpoint_t listener = {0};

    if (app->generation != NULL && (config_path != NULL || app->generation->config->server_count > 0)) {
        apex_config_error_t error;
        if (config_listener(app->generation->config, &listener, &error) != 0) {
            report_config_error("cannot start", &error);
            goto cleanup;
        }
    }
    if (config_path == NULL) {
        if (port <= 0) {
            port = listener.port != 0 ? listener.port : 8080;
        }
        const char *port_env = getenv("PORT");
        if (port_env != NULL && port_env[0] != '\0') {
            char *end;
            errno = 0;
            long value = strtol(port_env, &end, 10);
            if (errno == 0 && end != port_env && *end == '\0' && value > 0 && value <= UINT16_MAX) {
                port = (int)value;
            } else {
                fprintf(stderr, "apex: ignoring invalid PORT value\n");
            }
        }
        if (port <= 0 || port > UINT16_MAX) {
            fprintf(stderr, "apex: listen port is outside 1..65535\n");
            goto cleanup;
        }
        listener.port = (uint16_t)port;
    }
    if (resolve_listener(&listener) != 0) {
        goto cleanup;
    }

    if (sigemptyset(&signals) != 0 || sigaddset(&signals, SIGHUP) != 0 || sigaddset(&signals, SIGQUIT) != 0 ||
        sigaddset(&signals, SIGINT) != 0 || sigaddset(&signals, SIGTERM) != 0) {
        perror("apex: construct signal mask");
        goto cleanup;
    }
    int mask_error = pthread_sigmask(SIG_BLOCK, &signals, &previous_mask);
    if (mask_error != 0) {
        fprintf(stderr, "apex: block signals: %s\n", strerror(mask_error));
        goto cleanup;
    }
    mask_changed = true;
    struct sigaction ignore_pipe = {.sa_handler = SIG_IGN};
    if (sigemptyset(&ignore_pipe.sa_mask) != 0 || sigaction(SIGPIPE, &ignore_pipe, &previous_pipe) != 0) {
        perror("apex: ignore SIGPIPE");
        goto cleanup;
    }
    pipe_changed = true;
    signal_fd = signalfd(-1, &signals, SFD_NONBLOCK | SFD_CLOEXEC);
    if (signal_fd < 0) {
        perror("apex: signalfd");
        goto cleanup;
    }
    control.status_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (control.status_fd < 0) {
        perror("apex: eventfd controller");
        goto cleanup;
    }

    cpu_set_t cpus;
    if (sched_getaffinity(0, sizeof(cpus), &cpus) != 0) {
        perror("apex: sched_getaffinity");
        goto cleanup;
    }
    size_t available_cpus[CPU_SETSIZE];
    size_t num_cpus = 0;
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (CPU_ISSET(cpu, &cpus)) {
            available_cpus[num_cpus++] = (size_t)cpu;
        }
    }
    if (num_cpus == 0) {
        fprintf(stderr, "apex: no available worker CPUs\n");
        goto cleanup;
    }
    if (app->generation != NULL && app->generation->config != NULL &&
        app->generation->config->worker_processes > 0) {
        worker_count = (size_t)app->generation->config->worker_processes;
    } else {
        worker_count = num_cpus;
    }
    if (worker_count == 0) {
        worker_count = 1;
    }
    workers = calloc(worker_count, sizeof(*workers));
    if (workers == NULL) {
        perror("apex: allocate workers");
        goto cleanup;
    }
    size_t index = 0;
    for (index = 0; index < worker_count; index++) {
        workers[index].epoll_fd = -1;
        workers[index].listen_fd = -1;
        workers[index].wake_fd = -1;
        workers[index].highest_fd = -1;
        workers[index].app = app;
        workers[index].control = &control;
        atomic_init(&workers[index].pending_generation, NULL);
        atomic_init(&workers[index].error, 0);
        atomic_init(&workers[index].finished, false);
        workers[index].cpu = (int)available_cpus[index % num_cpus];
    }
    shared_listen_fd = create_listener_socket(&listener);
    if (shared_listen_fd < 0) {
        goto cleanup;
    }
    for (index = 0; index < worker_count; index++) {
        if (prepare_worker(&workers[index], &listener, shared_listen_fd) != 0) {
            close(shared_listen_fd);
            shared_listen_fd = -1;
            goto cleanup;
        }
    }
    for (index = 0; index < worker_count; index++) {
        int thread_error = pthread_create(&workers[index].thread, NULL, worker_main, &workers[index]);
        if (thread_error != 0) {
            fprintf(stderr, "apex: create worker: %s\n", strerror(thread_error));
            goto cleanup;
        }
        started++;
    }
    fprintf(stderr, "apex: listening on %s:%u with %zu worker(s)\n",
            listener.host[0] != '\0' ? listener.host : "0.0.0.0", (unsigned)listener.port, worker_count);
    result = 0;

    struct pollfd descriptors[2] = {
        {.fd = signal_fd, .events = POLLIN},
        {.fd = control.status_fd, .events = POLLIN},
    };
    for (;;) {
        size_t finished = 0;
        for (index = 0; index < started; index++) {
            if (atomic_load_explicit(&workers[index].error, memory_order_relaxed) != 0) {
                result = 1;
                goto cleanup;
            }
            if (atomic_load_explicit(&workers[index].finished, memory_order_acquire)) {
                finished++;
            }
        }
        if (finished == started) {
            break;
        }
        if (finished > 0 && atomic_load_explicit(&control.shutdown, memory_order_acquire) == WORKERS_RUNNING) {
            fprintf(stderr, "apex: worker exited unexpectedly\n");
            result = 1;
            goto cleanup;
        }
        int ready = poll(descriptors, 2, -1);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("apex: poll controller");
            result = 1;
            goto cleanup;
        }
        if ((descriptors[0].revents | descriptors[1].revents) & (POLLERR | POLLHUP | POLLNVAL)) {
            fprintf(stderr, "apex: controller descriptor failed\n");
            result = 1;
            goto cleanup;
        }
        if ((descriptors[1].revents & POLLIN) && drain_notification(control.status_fd) != 0) {
            result = 1;
            goto cleanup;
        }
        if (descriptors[0].revents & POLLIN) {
            struct signalfd_siginfo notification;
            for (;;) {
                ssize_t received = read(signal_fd, &notification, sizeof(notification));
                if (received < 0 && errno == EINTR) {
                    continue;
                }
                if (received < 0 && errno == EAGAIN) {
                    break;
                }
                if (received != (ssize_t)sizeof(notification)) {
                    if (received >= 0) {
                        errno = EIO;
                    }
                    perror("apex: signalfd read");
                    result = 1;
                    goto cleanup;
                }
                int shutdown = atomic_load_explicit(&control.shutdown, memory_order_acquire);
                if (notification.ssi_signo == SIGHUP) {
                    if (config_path != NULL && shutdown == WORKERS_RUNNING &&
                        reload_config(app, config_path, &listener, workers, started) != 0) {
                        result = 1;
                        goto cleanup;
                    }
                    continue;
                }
                if (notification.ssi_signo == SIGQUIT && shutdown == WORKERS_RUNNING) {
                    fprintf(stderr, "apex: graceful shutdown requested\n");
                    atomic_store_explicit(&control.shutdown, WORKERS_DRAINING, memory_order_release);
                } else if (notification.ssi_signo == SIGINT || notification.ssi_signo == SIGTERM) {
                    fprintf(stderr, "apex: shutdown requested\n");
                    atomic_store_explicit(&control.shutdown, WORKERS_STOPPING, memory_order_release);
                }
                if (wake_workers(workers, started) != 0) {
                    result = 1;
                    goto cleanup;
                }
            }
        }
    }

cleanup:
    if (shared_listen_fd >= 0) {
        close(shared_listen_fd);
        shared_listen_fd = -1;
        if (workers != NULL) {
            for (size_t i = 0; i < worker_count; i++) {
                workers[i].listen_fd = -1;
            }
        }
    }
    atomic_store_explicit(&control.shutdown, WORKERS_STOPPING, memory_order_release);
    if (started > 0 && wake_workers(workers, started) != 0) {
        result = 1;
    }
    for (size_t index = 0; index < started; index++) {
        int join_error = pthread_join(workers[index].thread, NULL);
        if (join_error != 0) {
            /* Continuing would free storage still reachable by a worker. */
            fprintf(stderr, "apex: join worker: %s\n", strerror(join_error));
            abort();
        }
        if (atomic_load_explicit(&workers[index].error, memory_order_relaxed) != 0) {
            result = 1;
        }
    }
    if (workers != NULL) {
        for (size_t index = 0; index < worker_count; index++) {
            apex_generation_release(atomic_exchange_explicit(&workers[index].pending_generation, NULL,
                                                              memory_order_acq_rel));
            apex_generation_release(workers[index].generation);
            if (workers[index].connections != NULL &&
                munmap(workers[index].connections, sizeof(conn_t) * MAX_FDS) != 0) {
                perror("apex: munmap connections");
                result = 1;
            }
            if (close_fd(&workers[index].listen_fd) != 0) {
                result = 1;
            }
            if (close_fd(&workers[index].wake_fd) != 0) {
                result = 1;
            }
            if (close_fd(&workers[index].epoll_fd) != 0) {
                result = 1;
            }
        }
        free(workers);
    }
    if (mask_changed && signal_fd >= 0) {
        /* Consume shutdown/reload signals queued during joins before restoring
         * the caller's mask and its original dispositions. */
        struct signalfd_siginfo notification;
        ssize_t received;
        do {
            received = read(signal_fd, &notification, sizeof(notification));
        } while (received == (ssize_t)sizeof(notification) || (received < 0 && errno == EINTR));
        if (received >= 0 || errno != EAGAIN) {
            fprintf(stderr, "apex: cannot drain pending control signals\n");
            result = 1;
        }
    }
    if (close_fd(&signal_fd) != 0) {
        result = 1;
    }
    if (close_fd(&control.status_fd) != 0) {
        result = 1;
    }
    if (pipe_changed && sigaction(SIGPIPE, &previous_pipe, NULL) != 0) {
        perror("apex: restore SIGPIPE disposition");
        result = 1;
    }
    if (mask_changed) {
        int mask_error = pthread_sigmask(SIG_SETMASK, &previous_mask, NULL);
        if (mask_error != 0) {
            fprintf(stderr, "apex: restore signal mask: %s\n", strerror(mask_error));
            result = 1;
        }
    }
    atomic_store_explicit(&app->running, false, memory_order_release);
    return result;
}

int apex_run(apex_app_t *app, int port) {
    return run_app(app, port, NULL);
}

int apex_run_config(apex_app_t *app, const char *config_path) {
    if (config_path == NULL) {
        fprintf(stderr, "apex: configuration path is null\n");
        return 1;
    }
    return run_app(app, 0, config_path);
}
