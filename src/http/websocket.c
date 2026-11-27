#include "apex/websocket.h"
#include "apex/proxy.h"
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void apex_proxy_ws_tunnel(conn_t *client_conn, int upstream_fd, void *upstream_ssl,
                          void *upstream_server, uint64_t timeout_ms) {
    if (client_conn == NULL || client_conn->fd < 0 || upstream_fd < 0) {
        if (upstream_ssl != NULL) {
            SSL_shutdown((SSL *)upstream_ssl);
            SSL_free((SSL *)upstream_ssl);
        }
        if (upstream_fd >= 0) {
            close(upstream_fd);
        }
        if (upstream_server != NULL) {
            atomic_fetch_sub_explicit(&((upstream_server_t *)upstream_server)->active_conns, 1, memory_order_relaxed);
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
        bool upstream_has_pending = false;
        if (upstream_ssl != NULL && SSL_pending((SSL *)upstream_ssl) > 0) {
            upstream_has_pending = true;
        }

        int timeout = (client_has_pending || upstream_has_pending) ? 0 : poll_timeout;
        int ret = poll(fds, 2, timeout);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (ret == 0 && !client_has_pending && !upstream_has_pending) {
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
                    ssize_t sent = 0;
                    if (upstream_ssl != NULL) {
                        int w = SSL_write((SSL *)upstream_ssl, buffer + total_sent, (int)((size_t)nread - total_sent));
                        if (w > 0) {
                            sent = w;
                        } else {
                            int err = SSL_get_error((SSL *)upstream_ssl, w);
                            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                                sent = -1;
                                errno = EAGAIN;
                            } else {
                                goto tunnel_done;
                            }
                        }
                    } else {
                        sent = send(upstream_fd, buffer + total_sent, (size_t)nread - total_sent, MSG_NOSIGNAL);
                    }
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
        if (upstream_has_pending || (fds[1].revents & (POLLIN | POLLERR | POLLHUP | POLLRDHUP))) {
            ssize_t nread = 0;
            if (upstream_ssl != NULL) {
                int r = SSL_read((SSL *)upstream_ssl, buffer, sizeof(buffer));
                if (r > 0) {
                    nread = r;
                } else {
                    int err = SSL_get_error((SSL *)upstream_ssl, r);
                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                        nread = -1;
                        errno = EAGAIN;
                    } else {
                        nread = 0;
                    }
                }
            } else {
                nread = recv(upstream_fd, buffer, sizeof(buffer), 0);
            }

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
    if (upstream_ssl != NULL) {
        SSL_shutdown((SSL *)upstream_ssl);
        SSL_free((SSL *)upstream_ssl);
    }
    close(upstream_fd);
    if (upstream_server != NULL) {
        atomic_fetch_sub_explicit(&((upstream_server_t *)upstream_server)->active_conns, 1, memory_order_relaxed);
    }
    client_conn->close_after_write = 1;
}
