#include "worker.h"
#include "metrics.h"
#include "tls.h"
#include "http.h"

static const char RESP_204[] = "HTTP/1.1 204\r\n\r\n";
static const char RESP_200[] = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1";

static const char *g_resp = RESP_204;
static size_t g_resp_len = sizeof(RESP_204) - 1;
static size_t g_batch_len = (sizeof(RESP_204) - 1) * BATCH_COPIES;
static char g_batch[(sizeof(RESP_200) - 1) * BATCH_COPIES];

static conn_t *conns = NULL;

void worker_init_batch(void) {
    if (g_config.http_status == 200) {
        g_resp = RESP_200;
        g_resp_len = sizeof(RESP_200) - 1;
    } else {
        g_resp = RESP_204;
        g_resp_len = sizeof(RESP_204) - 1;
    }
    g_batch_len = g_resp_len * BATCH_COPIES;

    for (int i = 0; i < BATCH_COPIES; i++) {
        memcpy(g_batch + (size_t)i * g_resp_len, g_resp, g_resp_len);
    }
}

static void send_stats(int fd, conn_t *c, uint64_t local_requests, int worker_id) {
    atomic_store_explicit(&worker_metrics[worker_id].published, local_requests, memory_order_relaxed);
    const uint64_t total = total_requests();
    const uint64_t rps = current_rps(total);
    const uint64_t peak = atomic_load_explicit(&global_metric->peak_rps, memory_order_relaxed);

    char body[512];
    int body_len = snprintf(body, sizeof(body),
        "{\n"
        "  \"server\": \"tachyon/" TACHYON_VERSION "\",\n"
        "  \"current_rps\": %llu,\n"
        "  \"peak_rps\": %llu,\n"
        "  \"total_requests\": %llu,\n"
        "  \"workers\": %d,\n"
        "  \"ktls_tx\": %s,\n"
        "  \"ktls_rx\": %s,\n"
        "  \"cipher\": \"TLS_AES_128_GCM_SHA256 (TLS 1.3)\"\n"
        "}\n",
        (unsigned long long)rps,
        (unsigned long long)(peak > rps ? peak : rps),
        (unsigned long long)total,
        g_config.num_workers,
        c->ktls_tx ? "true" : "false",
        c->ktls_rx ? "true" : "false");

    char response[1024];
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Cache-Control: no-store, no-cache\r\n"
        "Connection: close\r\n"
        "Content-Length: %d\r\n\r\n%s",
        body_len, body);

    if (len > 0 && (size_t)len < sizeof(response)) {
        if (c->ktls_tx)
            (void)send(fd, response, (size_t)len, MSG_NOSIGNAL);
        else if (c->ssl)
            (void)SSL_write(c->ssl, response, len);
    }
}

static void close_conn(int epoll_fd, int fd, int conn_cap) {
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    if (fd < conn_cap && conns[fd].in_use) {
        if (conns[fd].ssl) {
            SSL_free(conns[fd].ssl);
            conns[fd].ssl = NULL;
        }
        conns[fd].in_use = 0;
    }
    close(fd);
}

static int flush_conn(int epoll_fd, int fd, conn_t *c) {
    while (c->custom_len > 0) {
        size_t chunk = c->custom_len - c->custom_off;
        ssize_t w;
        if (c->ktls_tx) {
            w = send(fd, c->custom_buf + c->custom_off, chunk, MSG_NOSIGNAL);
        } else {
            w = SSL_write(c->ssl, c->custom_buf + c->custom_off, (int)chunk);
        }

        if (w > 0) {
            c->custom_off += (size_t)w;
            if (c->custom_off >= c->custom_len) {
                c->custom_len = 0;
                c->custom_off = 0;
                c->custom_buf = NULL;
            }
            continue;
        }

        int want_out = 0;
        if (c->ktls_tx) {
            if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) want_out = 1;
            else if (w < 0 && errno == EINTR) continue;
            else return -1;
        } else {
            int err = SSL_get_error(c->ssl, (int)w);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) want_out = 1;
            else return -1;
        }

        if (want_out) {
            if (!c->want_write) {
                struct epoll_event ev = {
                    .events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP,
                    .data.fd = fd
                };
                if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == 0)
                    c->want_write = 1;
            }
            return 0;
        }
        return -1;
    }

    while (c->pending > 0) {
        size_t chunk = g_batch_len - c->off;
        if (chunk > c->pending) chunk = c->pending;

        ssize_t w;
        if (c->ktls_tx) {
            w = send(fd, g_batch + c->off, chunk, MSG_NOSIGNAL);
        } else {
            w = SSL_write(c->ssl, g_batch + c->off, (int)chunk);
        }

        if (w > 0) {
            c->pending -= (size_t)w;
            c->off += (size_t)w;
            if (c->off >= g_batch_len) c->off = 0;
            continue;
        }

        int want_out = 0;
        if (c->ktls_tx) {
            if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) want_out = 1;
            else if (w < 0 && errno == EINTR) continue;
            else return -1;
        } else {
            int err = SSL_get_error(c->ssl, (int)w);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) want_out = 1;
            else return -1;
        }

        if (want_out) {
            if (!c->want_write) {
                struct epoll_event ev = {
                    .events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP,
                    .data.fd = fd
                };
                if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == 0)
                    c->want_write = 1;
            }
            return 0;
        }
        return -1;
    }

    if (c->want_write) {
        struct epoll_event ev = {
            .events = EPOLLIN | EPOLLET | EPOLLRDHUP,
            .data.fd = fd
        };
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
        c->want_write = 0;
    }
    return 0;
}

static int do_tls_handshake(int epoll_fd, int fd, conn_t *c) {
    int ret = SSL_do_handshake(c->ssl);
    if (ret == 1) {
        c->handshake_done = 1;

        BIO *wbio = SSL_get_wbio(c->ssl);
        BIO *rbio = SSL_get_rbio(c->ssl);
#ifdef BIO_get_ktls_send
        if (wbio && BIO_get_ktls_send(wbio)) c->ktls_tx = 1;
#endif
#ifdef BIO_get_ktls_recv
        if (rbio && BIO_get_ktls_recv(rbio)) c->ktls_rx = 1;
#endif

        struct epoll_event ev = {
            .events = EPOLLIN | EPOLLET | EPOLLRDHUP,
            .data.fd = fd
        };
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
        return 1;
    }

    int err = SSL_get_error(c->ssl, ret);
    if (err == SSL_ERROR_WANT_READ) {
        struct epoll_event ev = {
            .events = EPOLLIN | EPOLLET | EPOLLRDHUP,
            .data.fd = fd
        };
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
        return 0;
    }
    if (err == SSL_ERROR_WANT_WRITE) {
        struct epoll_event ev = {
            .events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP,
            .data.fd = fd
        };
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
        return 0;
    }
    return -1;
}

void worker_run(int listen_fd, int cpu, int worker_id, int conn_cap) {
    int epoll_fd;
    struct epoll_event ev, *events;
    int max_fd_seen = 0;
    time_t last_sweep;
    uint64_t local_requests = atomic_load_explicit(&worker_metrics[worker_id].published, memory_order_relaxed);
    uint64_t last_published = local_requests;

    signal(SIGPIPE, SIG_IGN);

#ifdef __linux__
    if (cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        sched_setaffinity(0, sizeof(set), &set);
    }
#else
    (void)cpu;
#endif

    events = calloc(MAX_EVENTS, sizeof(struct epoll_event));
    conns  = calloc((size_t)conn_cap, sizeof(conn_t));
    if (!events || !conns) { perror("calloc"); exit(EXIT_FAILURE); }

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { perror("epoll_create1"); exit(EXIT_FAILURE); }

    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = listen_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        perror("epoll_ctl: listen_fd"); exit(EXIT_FAILURE);
    }

    char buf[READ_BUF];
    last_sweep = time(NULL);

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }

        time_t now = time(NULL);

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;

            if (fd == listen_fd) {
                while (1) {
#ifdef __linux__
                    int client_fd = accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
                    int client_fd = accept(listen_fd, NULL, NULL);
#endif
                    if (client_fd < 0) {
                        if (errno == EINTR) continue;
                        if (errno != EAGAIN && errno != EWOULDBLOCK) perror("accept");
                        break;
                    }
                    if (client_fd >= conn_cap) { close(client_fd); continue; }

                    int flag = 1;
                    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

                    conn_t *c = &conns[client_fd];
                    c->in_use = 1;
                    c->want_write = 0;
                    c->closing = 0;
                    c->mstate = 0;
                    c->uri_parsed = 0;
                    c->uri_parsing = 0;
                    c->uri_len = 0;
                    c->custom_buf = NULL;
                    c->custom_len = 0;
                    c->custom_off = 0;
                    c->pending = 0;
                    c->off = 0;
                    c->handshake_done = 0;
                    c->ktls_tx = 0;
                    c->ktls_rx = 0;
                    c->last_active = now;
                    if (client_fd > max_fd_seen) max_fd_seen = client_fd;

                    c->ssl = SSL_new(g_ssl_ctx);
                    if (!c->ssl) { close(client_fd); c->in_use = 0; continue; }
                    SSL_set_fd(c->ssl, client_fd);
                    SSL_set_accept_state(c->ssl);

                    ev.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP;
                    ev.data.fd = client_fd;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);

                    if (do_tls_handshake(epoll_fd, client_fd, c) < 0) {
                        close_conn(epoll_fd, client_fd, conn_cap);
                    }
                }
                continue;
            }

            if (fd >= conn_cap || !conns[fd].in_use) continue;
            conn_t *c = &conns[fd];

            if (events[i].events & (EPOLLHUP | EPOLLERR)) {
                close_conn(epoll_fd, fd, conn_cap);
                continue;
            }

            if (!c->handshake_done) {
                int hs = do_tls_handshake(epoll_fd, fd, c);
                if (hs < 0) {
                    close_conn(epoll_fd, fd, conn_cap);
                    continue;
                }
                if (!c->handshake_done) continue;
            }

            if (events[i].events & EPOLLOUT) {
                if (flush_conn(epoll_fd, fd, c) < 0) {
                    close_conn(epoll_fd, fd, conn_cap);
                    continue;
                }
            }

            if (events[i].events & (EPOLLIN | EPOLLRDHUP)) {
                int nreq = 0, stats_request = 0, dead = 0;

                for (;;) {
                    ssize_t n;
                    if (c->ktls_rx) {
                        n = read(fd, buf, sizeof(buf));
                    } else {
                        n = SSL_read(c->ssl, buf, sizeof(buf));
                    }

                    if (n > 0) {
                        uint8_t st = c->mstate;
                        for (ssize_t k = 0; k < n; k++) {
                            char ch = buf[k];

                            if (!c->uri_parsed) {
                                if (!c->uri_parsing) {
                                    if (ch == ' ' || ch == '/') {
                                        c->uri_parsing = 1;
                                        c->uri_len = 0;
                                        if (ch == '/') c->uri[c->uri_len++] = '/';
                                    }
                                } else {
                                    if (ch == ' ' || ch == '?' || ch == '\r' || ch == '\n') {
                                        c->uri_parsed = 1;
                                        c->uri[c->uri_len] = '\0';
                                    } else if (c->uri_len < sizeof(c->uri) - 1) {
                                        c->uri[c->uri_len++] = ch;
                                    }
                                }
                            }

                            if (st == 0)      st = (ch == '\r') ? 1 : 0;
                            else if (st == 1) st = (ch == '\n') ? 2 : (ch == '\r' ? 1 : 0);
                            else if (st == 2) st = (ch == '\r') ? 3 : 0;
                            else {
                                if (ch == '\n') {
                                    if (c->uri_len >= 6 && strncmp(c->uri, "/stats", 6) == 0 && (c->uri[6] == '\0' || c->uri[6] == '?')) {
                                        stats_request = 1;
                                    } else {
                                        const http_route_t *route = http_find_route(c->uri, c->uri_len);
                                        if (route) {
                                            c->custom_buf = route->response_buf;
                                            c->custom_len = route->response_len;
                                            c->custom_off = 0;
                                            nreq++;
                                        } else if (c->uri_len == 1 && c->uri[0] == '/' && (!g_config.root_dir || !g_config.root_dir[0])) {
                                            nreq++;
                                        } else {
                                            size_t l404;
                                            c->custom_buf = http_get_404_response(&l404);
                                            c->custom_len = l404;
                                            c->custom_off = 0;
                                            nreq++;
                                        }
                                    }
                                    c->uri_parsed = 0;
                                    c->uri_parsing = 0;
                                    c->uri_len = 0;
                                    st = 0;
                                } else {
                                    st = (ch == '\r') ? 1 : 0;
                                }
                            }
                        }
                        c->mstate = st;

                        if (!c->ktls_rx && SSL_pending(c->ssl) > 0) continue;
                        if ((size_t)n < sizeof(buf)) break;
                        continue;
                    }

                    if (n == 0) { c->closing = 1; break; }

                    if (c->ktls_rx) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        if (errno == EINTR) continue;
                    } else {
                        int err = SSL_get_error(c->ssl, (int)n);
                        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) break;
                    }
                    dead = 1; break;
                }

                if (nreq > 0) {
                    if (c->custom_len == 0)
                        c->pending += (size_t)nreq * g_resp_len;
                    c->last_active = now;
                    local_requests += (uint64_t)nreq;
                }
                if (stats_request) {
                    ++local_requests;
                    send_stats(fd, c, local_requests, worker_id);
                    close_conn(epoll_fd, fd, conn_cap);
                    continue;
                }
                if (local_requests - last_published >= STATS_PUBLISH_EVERY) {
                    atomic_store_explicit(&worker_metrics[worker_id].published,
                                          local_requests, memory_order_relaxed);
                    last_published = local_requests;
                }
                if (!dead && flush_conn(epoll_fd, fd, c) < 0) dead = 1;

                if (dead || (c->closing && c->pending == 0 && c->custom_len == 0)) {
                    close_conn(epoll_fd, fd, conn_cap);
                    continue;
                }
            }
        }

        if (now - last_sweep >= IDLE_TIMEOUT) {
            last_sweep = now;
            for (int fd = 0; fd <= max_fd_seen; fd++) {
                if (!conns[fd].in_use) continue;
                if (now - conns[fd].last_active > IDLE_TIMEOUT)
                    close_conn(epoll_fd, fd, conn_cap);
            }
        }
    }
}
