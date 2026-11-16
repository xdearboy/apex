# Apex

[![HTTP Arena H/1.1](https://img.shields.io/endpoint?url=https://http-arena.com/badge/apex-tuned/h1.json)](https://http-arena.com/#tuned=1)
[![HTTP Arena H/2](https://img.shields.io/endpoint?url=https://http-arena.com/badge/apex-tuned/h2.json)](https://http-arena.com/#tuned=1)

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

## Repository Structure

- [`include/`](include/) & [`src/`](src/): The core public C micro-framework library (`libapex.a`) powering [the-benchmarker/web-frameworks](https://github.com/the-benchmarker/web-frameworks).
- [`engine/`](engine/): The high-performance tuned HTTP/1.1 & HTTP/2 engine with TLS 1.3, asynchronous timer heaps, static asset compression, and multi-port routing powering [HttpArena](https://http-arena.com).
- [`examples/`](examples/): Example applications (`web_frameworks`, `hello_world`).

## Performance & Benchmarks

Apex is engineered for extreme throughput, sub-millisecond tail latency, and zero heap allocations on the hot path.

### Bare-Metal Benchmark Results
*Tested on AMD EPYC 4244P (Zen 4, 6 physical cores / 12 threads @ up to 5.3 GHz, 32 GB DDR5 ECC, Linux 6.12)*

| Benchmark Scenario | Tool / Mode | Throughput (RPS) | Latency (p50) | Latency (p99) | Transfer Rate |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **GET / (Pipelined depth=128)** | `wrk` (12 threads, 192 conn) | **20,285,838 req/s** | 1.30 ms | 19.10 ms | 1.70 GB/s |
| **GET / (Pipelined depth=64)** | `wrk` (10 threads, 160 conn) | **14,645,742 req/s** | 1.02 ms | 34.05 ms | 1.23 GB/s |
| **GET / (Pipelined depth=16)** | `wrk` (6 threads, 100 conn) | **4,062,962 req/s** | 1.15 ms | 30.34 ms | 348.7 MB/s |
| **GET / (TLS 1.3 HTTPS)** | `zrk` (closed-loop, 50 conn) | **407,405 req/s** | **81 µs** | 1.23 ms | 34.97 MB/s |
| **GET / (Plaintext HTTP/1.1)** | `zrk` (closed-loop, 100 conn) | **380,778 req/s** | **176 µs** | 3.30 ms | 32.57 MB/s |
| **GET /baseline11 (Query Math)** | `zrk` (closed-loop, 100 conn) | **369,839 req/s** | **178 µs** | 3.29 ms | 31.74 MB/s |

### Worldwide HttpArena League Standing (64-core Dedicated Bare-Metal)
- **`json-tls`**: **1,868,684 RPS** (🥇 **Rank 1 Worldwide**)
- **`limited-conn`**: **2,751,635 RPS** (🥇 **Rank 1 Worldwide**)
- **`pipelined`**: **54,435,798 RPS** (54.4M RPS throughput)
- **`async` (32,000 connections)**: **2,082,812 RPS** (2.08M RPS on 32k concurrent connections)
- **`baseline-4096`**: **4,175,936 RPS**

### Official Web Frameworks Benchmark
- Included in **[the-benchmarker/web-frameworks](https://github.com/the-benchmarker/web-frameworks)** (PR [#10329](https://github.com/the-benchmarker/web-frameworks/pull/10329) merged).

---

## Live Public Stress-Test Endpoint

A live instance is running on dedicated bare-metal hardware and exposed directly to the public internet for stress testing:

* **HTTPS**: **[`https://apex.d3vo.ru/`](https://apex.d3vo.ru/)** (Port 443, TLS 1.3 with Let's Encrypt wildcard certificate)
* **HTTP**: **[`http://apex.d3vo.ru:8088/`](http://apex.d3vo.ru:8088/)** (Port 8088, raw plaintext socket)

### Try it with `zrk` or `curl`:
```bash
# Verify connection
curl -v https://apex.d3vo.ru/

# Stress test over HTTPS with zrk
zrk --plain --closed -t 4 -c 50 -d 10s https://apex.d3vo.ru/pipeline

# Stress test with wrk
wrk -t4 -c100 -d10s https://apex.d3vo.ru/
```

---

## Building

```bash
make
./examples/web_frameworks
```

## License

MIT License.
