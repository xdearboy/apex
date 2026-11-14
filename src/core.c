#include "internal.h"

typedef struct {
    int thread_id;
    int port;
    int nprocs;
    apex_app_t *app;
} worker_arg_t;

static inline void close_conn(int epfd, conn_t *c) {
    if (c->fd >= 0) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
        c->fd = -1;
        c->rlen = 0;
        c->wlen = 0;
        c->woff = 0;
        c->close_after_write = 0;
        c->epollout_active = 0;
    }
}

static inline void flush_write(int epfd, conn_t *c) {
    if (c->wlen > c->woff) {
        size_t to_send = c->wlen - c->woff;
        ssize_t s = send(c->fd, c->wbuf + c->woff, to_send, MSG_NOSIGNAL);
        if (s > 0) {
            c->woff += (uint32_t)s;
            if (c->woff == c->wlen) {
                c->woff = 0;
                c->wlen = 0;
                if (c->close_after_write) {
                    close_conn(epfd, c);
                    return;
                }
            }
        } else if (s < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
            close_conn(epfd, c);
            return;
        }
    }

    if (c->fd < 0) {
        return;
    }

    if (c->wlen > c->woff) {
        if (!c->epollout_active) {
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;
            ev.data.fd = c->fd;
            epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev);
            c->epollout_active = 1;
        }
    } else if (c->epollout_active) {
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
        ev.data.fd = c->fd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev);
        c->epollout_active = 0;
    }
}

static void *worker_main(void *arg) {
    worker_arg_t *w = (worker_arg_t *)arg;
    int tid = w->thread_id;
    int port = w->port;
    apex_app_t *app = w->app;
    int nprocs = w->nprocs;

    if (nprocs > 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(tid % nprocs, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    }

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        perror("epoll_create1");
        return NULL;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listen_fd < 0) {
        perror("socket");
        close(epfd);
        return NULL;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(listen_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    setsockopt(listen_fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &opt, sizeof(opt));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t)port);
    sin.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind");
        close(listen_fd);
        close(epfd);
        return NULL;
    }

    if (listen(listen_fd, 65535) < 0) {
        perror("listen");
        close(listen_fd);
        close(epfd);
        return NULL;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = listen_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        perror("epoll_ctl listen_fd");
        close(listen_fd);
        close(epfd);
        return NULL;
    }

    conn_t *conns = (conn_t *)mmap(NULL, sizeof(conn_t) * MAX_FDS,
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (conns == MAP_FAILED) {
        perror("mmap");
        close(listen_fd);
        close(epfd);
        return NULL;
    }

    for (int i = 0; i < MAX_FDS; i++) {
        conns[i].fd = -1;
    }

    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            uint32_t evts = events[i].events;

            if (fd == listen_fd) {
                while (1) {
                    int cfd = accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
                    if (cfd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        break;
                    }

                    if (cfd >= MAX_FDS) {
                        close(cfd);
                        continue;
                    }

                    int one = 1;
                    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                    setsockopt(cfd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));

                    conn_t *c = &conns[cfd];
                    c->fd = cfd;
                    c->rlen = 0;
                    c->wlen = 0;
                    c->woff = 0;
                    c->close_after_write = 0;
                    c->epollout_active = 0;

                    struct epoll_event cev;
                    cev.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
                    cev.data.fd = cfd;
                    epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &cev);
                }
                continue;
            }

            conn_t *c = &conns[fd];
            if (c->fd < 0) {
                continue;
            }

            if (evts & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
                close_conn(epfd, c);
                continue;
            }

            if (evts & EPOLLIN) {
                while (1) {
                    ssize_t n = recv(c->fd, c->rbuf + c->rlen, sizeof(c->rbuf) - c->rlen, 0);
                    if (n > 0) {
                        c->rlen += (uint32_t)n;
                        if (memmem(c->rbuf, c->rlen, "\r\n\r\n", 4)) {
                            break;
                        }
                    } else if (n == 0) {
                        close_conn(epfd, c);
                        goto next_event;
                    } else {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        close_conn(epfd, c);
                        goto next_event;
                    }

                    if (c->rlen == sizeof(c->rbuf)) {
                        break;
                    }
                }

                char *ptr = c->rbuf;
                size_t rem = c->rlen;

                while (rem >= 4) {
                    char *crlf = (char *)memmem(ptr, rem, "\r\n\r\n", 4);
                    if (!crlf) {
                        break;
                    }

                    size_t header_len = (size_t)((crlf + 4) - ptr);
                    size_t content_len = 0;

                    if (ptr[0] == 'P' && ptr[1] == 'O' && ptr[2] == 'S' && ptr[3] == 'T') {
                        char *cl = (char *)memmem(ptr, header_len, "Content-Length:", 15);
                        if (!cl) {
                            cl = (char *)memmem(ptr, header_len, "content-length:", 15);
                        }
                        if (cl) {
                            content_len = strtoul(cl + 15, NULL, 10);
                        }
                    }

                    if (rem < header_len + content_len) {
                        break;
                    }

                    if (memmem(ptr, header_len, "close", 5)) {
                        c->close_after_write = 1;
                    }

                    apex_res_t res = { .conn = c };
                    apex_dispatch(app, ptr, header_len, ptr + header_len, content_len, &res);

                    size_t total_req_len = header_len + content_len;
                    ptr += total_req_len;
                    rem -= total_req_len;
                }

                if (rem > 0 && ptr != c->rbuf) {
                    memmove(c->rbuf, ptr, rem);
                }
                c->rlen = (uint32_t)rem;

                flush_write(epfd, c);
            }

            if ((evts & EPOLLOUT) && c->fd >= 0) {
                flush_write(epfd, c);
            }

        next_event:;
        }
    }

    munmap(conns, sizeof(conn_t) * MAX_FDS);
    close(listen_fd);
    close(epfd);
    return NULL;
}

int apex_run(apex_app_t *app, int port) {
    signal(SIGPIPE, SIG_IGN);

    int nprocs = get_nprocs();
    if (nprocs <= 0) {
        nprocs = 1;
    }

    pthread_t *threads = (pthread_t *)calloc((size_t)nprocs, sizeof(pthread_t));
    worker_arg_t *args = (worker_arg_t *)calloc((size_t)nprocs, sizeof(worker_arg_t));
    if (!threads || !args) {
        fprintf(stderr, "Memory allocation error\n");
        return 1;
    }

    for (int i = 0; i < nprocs; i++) {
        args[i].thread_id = i;
        args[i].port = port;
        args[i].nprocs = nprocs;
        args[i].app = app;
        if (pthread_create(&threads[i], NULL, worker_main, &args[i]) != 0) {
            fprintf(stderr, "Failed to create worker thread %d\n", i);
            return 1;
        }
    }

    for (int i = 0; i < nprocs; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    free(args);
    return 0;
}
