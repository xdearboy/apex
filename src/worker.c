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
        /* todo: ignores short writes; ok for now since the payload is tiny and we close right after */
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
        if (conns[fd].frag) {
            free(conns[fd].frag);
            conns[fd].frag = NULL;
        }
        conns[fd].fraglen = 0;
        if (conns[fd].out) {
            free(conns[fd].out);
            conns[fd].out = NULL;
        }
        conns[fd].out_len = conns[fd].out_off = conns[fd].out_cap = 0;
        conns[fd].in_use = 0;
    }
    close(fd);
}

static void reset_conn(int epoll_fd, int fd, int conn_cap) {
    struct linger lg = { .l_onoff = 1, .l_linger = 0 };
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    close_conn(epoll_fd, fd, conn_cap);
}

/* append a full response to the connection's ordered output buffer */
static int conn_append(conn_t *c, const char *data, size_t len) {
    if (c->out_len + len > c->out_cap) {
        size_t ncap = c->out_cap ? c->out_cap : 8192;
        while (ncap < c->out_len + len) ncap *= 2;
        char *nb = realloc(c->out, ncap);
        if (!nb) return -1;
        c->out = nb;
        c->out_cap = ncap;
    }
    memcpy(c->out + c->out_len, data, len);
    c->out_len += len;
    return 0;
}

static int flush_conn(int epoll_fd, int fd, conn_t *c) {
    while (c->out_off < c->out_len) {
        size_t chunk = c->out_len - c->out_off;
        ssize_t w;
        if (c->ktls_tx) {
            w = send(fd, c->out + c->out_off, chunk, MSG_NOSIGNAL);
        } else {
            w = SSL_write(c->ssl, c->out + c->out_off, (int)chunk);
        }

        if (w > 0) {
            c->out_off += (size_t)w;
            if (c->out_off >= c->out_len) {
                c->out_len = 0;
                c->out_off = 0;
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
    time_t last_sweep, last_rps_sample;
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
    last_rps_sample = last_sweep;

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }

        time_t now = time(NULL);

        if (now - last_rps_sample >= 1) {
            last_rps_sample = now;
            current_rps(total_requests());
        }

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
                    c->out_len = 0;
                    c->out_off = 0;
                    c->frag = NULL;
                    c->fraglen = 0;
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
                int nreq = 0, n204 = 0, stats_request = 0, reset_request = 0, dead = 0;

                for (;;) {
                    size_t base = c->fraglen;
                    if (base) memcpy(buf, c->frag, base);

                    ssize_t n;
                    if (c->ktls_rx) {
                        n = read(fd, buf + base, sizeof(buf) - base);
                    } else {
                        n = SSL_read(c->ssl, buf + base, (int)(sizeof(buf) - base));
                    }

                    if (n > 0) {
                        char *ptr = buf;
                        char *buf_end = buf + base + (size_t)n;

                        while (ptr < buf_end) {
                            char *eoh = memmem(ptr, (size_t)(buf_end - ptr), "\r\n\r\n", 4);
                            if (!eoh) break;

                            if (ptr[0] == 'G' && ptr[1] == 'E' && ptr[2] == 'T' && ptr[3] == ' ') {
                                char *u = ptr + 4;
                                while (*u == ' ') u++;
                                char *sp = memchr(u, ' ', (size_t)(eoh - u));
                                if (sp) {
                                    size_t ulen = (size_t)(sp - u);
                                    char *q = memchr(u, '?', ulen);
                                    if (q) ulen = (size_t)(q - u);

                                    size_t stats_plen = strlen(g_config.stats_path);
                                    size_t reset_plen = strlen(g_config.reset_path);
                                    if (reset_plen > 0 && ulen == reset_plen &&
                                        memcmp(u, g_config.reset_path, reset_plen) == 0) {
                                        reset_request = 1;
                                    } else if (g_config.enable_stats && stats_plen > 0 &&
                                        ulen == stats_plen && memcmp(u, g_config.stats_path, stats_plen) == 0) {
                                        stats_request = 1;
                                    } else {
                                        const http_route_t *route = http_find_route(u, ulen);
                                        if (route) {
                                            if (conn_append(c, route->response_buf, route->response_len) < 0) dead = 1;
                                            nreq++;
                                        } else if (ulen == 1 && u[0] == '/' && !g_config.root_dir[0]) {
                                            n204++;
                                            nreq++;
                                        } else {
                                            size_t l404;
                                            const char *r404 = http_get_404_response(&l404);
                                            if (conn_append(c, r404, l404) < 0) dead = 1;
                                            nreq++;
                                        }
                                    }
                                }
                            } else {
                                /* not a GET: refuse instead of parsing the body as pipelined requests */
                                dead = 1;
                                break;
                            }
                            ptr = eoh + 4;
                        }

                        /* carry an incomplete tail over to the next read so split requests aren't lost */
                        if (!dead) {
                            size_t tail = (size_t)(buf_end - ptr);
                            if (tail >= sizeof(buf)) {
                                dead = 1;               /* one request larger than the buffer */
                            } else if (tail > 0) {
                                if (!c->frag) c->frag = malloc(sizeof(buf));
                                if (!c->frag) dead = 1;
                                else { memcpy(c->frag, ptr, tail); c->fraglen = tail; }
                            } else {
                                c->fraglen = 0;
                            }
                        }
                        if (dead) break;

                        if (!c->ktls_rx && SSL_pending(c->ssl) > 0) continue;
                        if (base + (size_t)n < sizeof(buf)) break;
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
                    c->pending += (size_t)n204 * g_resp_len;
                    c->last_active = now;
                    local_requests += (uint64_t)nreq;
                }
                if (reset_request) {
                    ++local_requests;
                    if (local_requests - last_published >= STATS_PUBLISH_EVERY) {
                        atomic_store_explicit(&worker_metrics[worker_id].published,
                                              local_requests, memory_order_relaxed);
                        last_published = local_requests;
                    }
                    reset_conn(epoll_fd, fd, conn_cap);
                    continue;
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

                if (dead || (c->closing && c->pending == 0 && c->out_len == 0)) {
                    close_conn(epoll_fd, fd, conn_cap);
                    continue;
                }
            }
        }

        if (now - last_sweep >= SWEEP_INTERVAL) {
            last_sweep = now;
            for (int fd = 0; fd <= max_fd_seen; fd++) {
                conn_t *cc = &conns[fd];
                if (!cc->in_use) continue;
                time_t idle = now - cc->last_active;
                /* stalled TLS handshake (slowloris) gets a much shorter leash than idle keep-alive */
                if (!cc->handshake_done) {
                    if (idle > HANDSHAKE_TIMEOUT) close_conn(epoll_fd, fd, conn_cap);
                } else if (idle > IDLE_TIMEOUT) {
                    close_conn(epoll_fd, fd, conn_cap);
                }
            }
        }
    }
}
