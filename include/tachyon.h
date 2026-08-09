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
#include <ctype.h>
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

#ifdef __linux__
#include <sys/epoll.h>
#include <linux/filter.h>
#ifndef SO_ATTACH_REUSEPORT_CBPF
#define SO_ATTACH_REUSEPORT_CBPF 51
#endif
#else
#include <sys/select.h>
#define EPOLLIN      0x001
#define EPOLLOUT     0x004
#define EPOLLERR     0x008
#define EPOLLHUP     0x010
#define EPOLLRDHUP   0x2000
#define EPOLLET      0
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3
typedef union epoll_data { void *ptr; int fd; uint32_t u32; uint64_t u64; } epoll_data_t;
struct epoll_event { uint32_t events; epoll_data_t data; };
static inline int epoll_create1(int flags) { (void)flags; return 0; }
static inline int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) { (void)epfd; (void)op; (void)fd; (void)event; return 0; }
static inline int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) { (void)epfd; (void)events; (void)maxevents; (void)timeout; return 0; }
#endif

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0
#endif

#define TACHYON_VERSION      "1.0.0"
#define MAX_EVENTS           8192
#define DEFAULT_PORT         8443
#define DEFAULT_BIND_ADDR    "0.0.0.0"
#define DEFAULT_STATS_PATH   "/stats"
#define MAX_WORKERS          256
#define READ_BUF             16384
#define BATCH_COPIES         256
#define IDLE_TIMEOUT         60
#define STATS_PUBLISH_EVERY  64

typedef struct {
    int         port;
    char        bind_addr[64];
    char        cert_file[256];
    char        key_file[256];
    char        root_dir[256];
    char        stats_path[64];
    int         num_workers;
    int         enable_steer;
    int         enable_stats;
    int         http_status;
} tachyon_config_t;

extern tachyon_config_t g_config;

/* strncpy не ставит \0 если строка впритык к буферу — свой копир, всегда терминирует */
static inline void str_copy(char *dst, const char *src, size_t dst_size) {
    if (dst_size == 0) return;
    size_t i = 0;
    for (; i + 1 < dst_size && src[i]; i++) dst[i] = src[i];
    dst[i] = '\0';
}

#endif /* TACHYON_H */
