#ifndef TACHYON_H
#define TACHYON_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifdef __linux__
#include <sys/epoll.h>
#include <linux/filter.h>
#ifndef SO_ATTACH_REUSEPORT_CBPF
#define SO_ATTACH_REUSEPORT_CBPF 51
#endif
#elif defined(__APPLE__)
#include <sys/event.h>
#include <sys/time.h>

#define EPOLLIN      0x001
#define EPOLLOUT     0x004
#define EPOLLERR     0x008
#define EPOLLHUP     0x010
#define EPOLLRDHUP   0x2000
#define EPOLLET      (1u << 31)

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

typedef union epoll_data {
    void    *ptr;
    int      fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event {
    uint32_t     events;
    epoll_data_t data;
};

static inline int epoll_create1(int flags) {
    (void)flags;
    return kqueue();
}

static inline int epoll_ctl(int kq, int op, int fd, struct epoll_event *event) {
    struct kevent kev[2];
    int n = 0;
    if (op == EPOLL_CTL_DEL) {
        EV_SET(&kev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        EV_SET(&kev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        kevent(kq, kev, 2, NULL, 0, NULL);
        return 0;
    }
    if (op == EPOLL_CTL_MOD) {
        EV_SET(&kev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        EV_SET(&kev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        kevent(kq, kev, 2, NULL, 0, NULL);
    }
    if (event && (event->events & EPOLLIN)) {
        EV_SET(&kev[n++], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void *)(uintptr_t)fd);
    }
    if (event && (event->events & EPOLLOUT)) {
        EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, (void *)(uintptr_t)fd);
    }
    return (n > 0) ? kevent(kq, kev, n, NULL, 0, NULL) : 0;
}

static inline int epoll_wait(int kq, struct epoll_event *events, int maxevents, int timeout) {
    struct kevent kevs[1024];
    struct timespec ts, *pts = NULL;
    if (timeout >= 0) {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
        pts = &ts;
    }
    int nev = kevent(kq, NULL, 0, kevs, (maxevents > 1024) ? 1024 : maxevents, pts);
    if (nev < 0) return -1;
    for (int i = 0; i < nev; i++) {
        events[i].data.fd = (int)kevs[i].ident;
        events[i].events = 0;
        if (kevs[i].filter == EVFILT_READ) events[i].events |= EPOLLIN;
        if (kevs[i].filter == EVFILT_WRITE) events[i].events |= EPOLLOUT;
        if (kevs[i].flags & (EV_EOF | EV_ERROR)) events[i].events |= EPOLLHUP | EPOLLRDHUP;
    }
    return nev;
}
#endif

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0
#endif

#define TACHYON_VERSION      "1.0.0"
#define MAX_EVENTS           8192
#define DEFAULT_PORT         8443
#define DEFAULT_BIND_ADDR    "0.0.0.0"
#define MAX_WORKERS          256
#define READ_BUF             16384
#define BATCH_COPIES         256
#define IDLE_TIMEOUT         60
#define STATS_PUBLISH_EVERY  64

typedef struct {
    int         port;
    const char *bind_addr;
    const char *cert_file;
    const char *key_file;
    const char *root_dir;
    int         num_workers;
    int         enable_steer;
    int         http_status;
} tachyon_config_t;

extern tachyon_config_t g_config;

#endif /* TACHYON_H */
