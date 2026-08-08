#include "net.h"

int net_create_listener(int port, const char *bind_addr) {
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) { perror("socket"); return -1; }

    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
        fprintf(stderr, "Error: invalid bind address: %s\n", bind_addr);
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 65535) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

#ifdef __linux__
int net_attach_cpu_steering(int fd, int nsock) {
    struct sock_filter code[] = {
        { BPF_LD  | BPF_W   | BPF_ABS, 0, 0, (uint32_t)(SKF_AD_OFF + SKF_AD_CPU) },
        { BPF_ALU | BPF_MOD | BPF_K,   0, 0, (uint32_t)nsock },
        { BPF_RET | BPF_A,             0, 0, 0 },
    };
    struct sock_fprog prog = { .len = 3, .filter = code };
    return setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &prog, sizeof(prog));
}
#else
int net_attach_cpu_steering(int fd, int nsock) {
    (void)fd; (void)nsock;
    return -1;
}
#endif

int net_get_max_fds(void) {
    struct rlimit rl;
    int conn_cap = 1048576;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
        conn_cap = (int)rl.rlim_cur;
    }
    if (conn_cap <= 0 || conn_cap > 1048576) conn_cap = 1048576;
    return conn_cap;
}
