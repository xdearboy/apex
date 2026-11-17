# Apex

[![HTTP Arena H/1.1](https://img.shields.io/endpoint?url=https://http-arena.com/badge/apex-tuned/h1.json)](https://http-arena.com/#tuned=1)
[![HTTP Arena H/2](https://img.shields.io/endpoint?url=https://http-arena.com/badge/apex-tuned/h2.json)](https://http-arena.com/#tuned=1)

Apex is an ultra-high-performance, zero-allocation web micro-framework for Linux written in modern C.

Designed for extreme throughput and sub-millisecond tail latency, Apex utilizes a lock-free thread-per-core architecture, edge-triggered epoll, kernel connection load balancing, and direct vector response streaming.

## Features

- **Thread-per-Core Architecture**: Automatically spawns one worker per allowed CPU. The kernel schedules workers by default for co-located loads; set `APEX_PIN_CPUS=1` to pin workers on dedicated CPUs.
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

- [`include/`](include/) & [`src/`](src/): The core public C micro-framework library (`libapex.a`) and the standalone `apex` server binary powering [the-benchmarker/web-frameworks](https://github.com/the-benchmarker/web-frameworks).
- [`engine/`](engine/): The high-performance tuned HTTP/1.1 & HTTP/2 engine with TLS 1.3, asynchronous timer heaps, static asset compression, and multi-port routing powering [HttpArena](https://http-arena.com). Self-contained: own Makefile and Dockerfile, built independently of the library.
- [`examples/`](examples/): Example applications (`web_frameworks`, `hello_world`, `proxy_demo`, `config_demo`).
- [`tests/`](tests/): Integration tests (`make test`).
- [`conf/`](conf/): Reference configuration.
- [`docs/`](docs/): Design documents — reverse-proxy architecture, web-server roadmap, configuration language spec.
- [`scripts/`](scripts/): Benchmarking and OS-tuning helpers.

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

### Official HttpArena Worldwide Standing (64-core Bare-Metal)

Apex is ranked **#1 in HTTP/2** and **Top 5 in HTTP/1.1** overall across all web frameworks in the official [HttpArena](https://http-arena.com) benchmark running on dedicated 64-core AMD Threadripper hardware.

| Profile / Scenario | Official Rank | Throughput (RPS) | Tail Latency (p99) | Bandwidth | Protocol |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`pipelined` (depth=16, 4k conn)** | 🥇 **#1 of 180** | **59,539,961 req/s** | 1.39 ms | 3.55 GB/s | HTTP/1.1 |
| **`baseline-h2c` (1024 conn)** | 🥇 **#1 of 70** | **16,634,930 req/s** | 16.26 ms | 337.8 MB/s | HTTP/2 Cleartext |
| **`baseline-h2c` (256 conn)** | 🥇 **#1 of 70** | **16,350,916 req/s** | 44.38 ms | 328.8 MB/s | HTTP/2 Cleartext |
| **`baseline-h2` (1024 conn)** | 🥇 **#1 of 81** | **16,030,277 req/s** | 86.69 ms | 324.3 MB/s | HTTP/2 over TLS |
| **`baseline-h2c` (4096 conn)** | 🥇 **#1 of 70** | **15,055,383 req/s** | 29.38 ms | 307.0 MB/s | HTTP/2 Cleartext |
| **`limited-conn` (4096 conn)** | 🥇 **#1 of 195** | **2,822,803 req/s** | 1.80 ms | 172.2 MB/s | HTTP/1.1 |
| **`baseline-h2` (256 conn)** | 🥈 **#2 of 81** | **16,094,035 req/s** | 30.55 ms | 324.3 MB/s | HTTP/2 over TLS |
| **`json-h2c` (1024 conn)** | 🥈 **#2 of 68** | **5,961,855 req/s** | 60.23 ms | 19.85 GB/s | HTTP/2 Cleartext |
| **`json-h2c` (4096 conn)** | 🥈 **#2 of 68** | **5,232,884 req/s** | 86.51 ms | 17.59 GB/s | HTTP/2 Cleartext |
| **`baseline-4096`** | 🥉 **#3 of 195** | **4,403,856 req/s** | 1.96 ms | 268.7 MB/s | HTTP/1.1 |
| **`static-h2` (256 conn)** | **Top 5** (#5 of 80) | **1,431,689 req/s** | 189.1 ms | 21.87 GB/s | HTTP/2 over TLS |
| **`static-h2` (1024 conn)** | **Top 5** (#4 of 80) | **1,424,828 req/s** | 213.3 ms | 21.89 GB/s | HTTP/2 over TLS |
| **`json-tls` (4096 conn)** | **Top 6** (#6 of 174) | **1,822,383 req/s** | 79.25 ms | 6.14 GB/s | HTTP/1.1 + TLS 1.3 |
| **`async` (32,000 conn)** | **2.0M req/s** | **1,997,036 req/s** | 21.50 ms | 171.4 MB/s | HTTP/1.1 Timers |

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

## CLI (`apex`)

`make` also builds the standalone server binary `./apex`:

```bash
./apex -t conf/apex.conf        # validate configuration, exit 0/1
./apex -c /etc/apex/apex.conf   # serve (default config path: /etc/apex/apex.conf)
./apex -v                       # version and build flags
```

Signals: `SIGHUP` rebuilds and validates the candidate configuration in place —
routing (static/proxy) changes on the same listening endpoint, active requests
keep serving their generation, and a rejected reload keeps the previous
configuration. `SIGQUIT` drains in-flight requests and queued responses, then
stops; `SIGINT`/`SIGTERM` stop workers after the current handler returns.

Scope of the standalone core: one plaintext listening endpoint (virtual hosts
may share it), no TLS yet. Changing the listener on reload requires a restart
and is rejected with a message; `PORT` is honored only by `apex_run()` library
users, the CLI follows the configuration. Integration tests live in
`tests/test_cli.py` (`make test`).

## License

MIT License.
