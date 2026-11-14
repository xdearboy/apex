# Apex

Apex is an ultra-high-performance, zero-allocation web micro-framework for Linux written in modern C.

Designed for extreme throughput and sub-millisecond tail latency, Apex utilizes a lock-free thread-per-core architecture, edge-triggered epoll, kernel connection load balancing, and direct vector response streaming.

## Features

- **Thread-per-Core Architecture**: Automatically spawns dedicated worker threads pinned to CPU cores (`pthread_setaffinity_np`) to eliminate context switches and cross-core cache invalidation.
- **Kernel Load Balancing (`SO_REUSEPORT`)**: Independent listening sockets per thread with kernel 4-tuple connection hashing, `TCP_DEFER_ACCEPT`, and `TCP_NODELAY`.
- **Edge-Triggered Epoll (`EPOLLET`)**: Non-blocking event loop using `accept4(SOCK_NONBLOCK | SOCK_CLOEXEC)`.
- **Zero-Allocation Hot Path**: Pre-allocated connection state indexed by file descriptor; zero dynamic heap allocations per request.
- **HTTP Pipelining**: Drains and batches pipelined requests in a single read/write syscall cycle.
- **Microsecond Precision**: Microsecond-resolution timer heap with sub-millisecond polling accuracy.

## Quick Start

```c
#include "apex.h"

static void handle_root(apex_req_t *req, apex_res_t *res) {
    (void)req;
    static const char body[] = "Hello from Apex!";
    apex_res_send(res, 200, body, sizeof(body) - 1);
}

static void handle_user(apex_req_t *req, apex_res_t *res) {
    apex_res_send(res, 200, req->param, req->param_len);
}

int main(void) {
    apex_app_t *app = apex_create();
    apex_get(app, "/", handle_root);
    apex_get(app, "/user/:id", handle_user);
    return apex_run(app, 3000);
}
```

## Building

```bash
make
./examples/web_frameworks
```

## License

MIT License.
