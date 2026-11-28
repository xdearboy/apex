# Apex

[![HTTP Arena H/1.1](https://img.shields.io/endpoint?url=https://http-arena.com/badge/apex-tuned/h1.json)](https://http-arena.com/#tuned=1)
[![HTTP Arena H/2](https://img.shields.io/endpoint?url=https://http-arena.com/badge/apex-tuned/h2.json)](https://http-arena.com/#tuned=1)
[![Release](https://img.shields.io/github/v/release/xdearboy/apex?color=brightgreen)](https://github.com/xdearboy/apex/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Apex is an ultra-high-performance reverse proxy, load balancer, and edge router written in modern C23 for Linux.

Engineered for extreme throughput and sub-millisecond tail latency, Apex combines native asynchronous **`io_uring`** and **edge-triggered `epoll`** event engines, a lock-free thread-per-core architecture, zero-allocation hot paths, and modern protocol support (**HTTP/3 QUIC**, **gRPC**, **HTTP/2**, **HTTP/1.1**).

---

## ⚡ Key Highlights & Architecture

- **Native `io_uring` & `epoll` Dual Engine**: Automatic runtime detection of Linux `io_uring` with zero-syscall multishot polling and submission queues; transparent zero-downtime fallback to edge-triggered `epoll` (`EPOLLET`).
- **Extreme Single-Core & Multi-Core Scalability**: Benchmarked at **630,223 req/s on a single core** and **59.5M+ req/s** in pipelined bare-metal tests.
- **Next-Gen Protocol Stack**:
  - **HTTP/3 & QUIC**: Full RFC 9000 & RFC 9114 engine via `ngtcp2`, `nghttp3`, and OpenSSL 3.5.9 with dynamic CID routing and 0-RTT handshakes.
  - **Full gRPC Streaming**: Unary, client-, server-, and bidirectional gRPC proxying over HTTP/2 with trailers and metadata propagation.
  - **HTTP/2**: Zero-copy flow control and prioritized frame multiplexing.
- **Dynamic Extensibility**:
  - **LuaJIT 2.1**: In-line request rewriting, auth, and routing hooks running at native JIT speeds.
  - **WasmEdge WebAssembly**: Sandboxed, multi-tenant WebAssembly filters (WasmEdge 0.14.1).
  - **Coraza WAF**: Embedded CRS / OWASP application security inspection.
- **Automated ACME TLS (RFC 8555)**: Automated Let's Encrypt / ZeroSSL background certificate issuance, renewal, and zero-downtime context swapping.
- **Nginx-style Modular Configuration**: Familiar syntax supporting `include "conf.d/*.conf";`, upstream balancing policies (P2C, round-robin), keepalive pools, disk caching, and rate limiting.
- **Zero-Downtime Operations**: Seamless `SIGHUP` reload validating candidate config before swap; in-flight requests finish gracefully without dropping keep-alive sockets.

---

## 🚀 Quick Install (1-Line Universal Installer)

Supports **Debian, Ubuntu, Fedora, RHEL, Rocky, Alma, Arch Linux, and Alpine**:

```bash
curl -fsSL https://raw.githubusercontent.com/xdearboy/apex/main/scripts/install.sh | sudo bash
```

The installer automatically detects your distro, configures runtime dependencies, creates a sandboxed `apex` system user, installs the binary, sets up `/etc/apex/` and `/var/log/apex/`, and enables the systemd service.

### Standalone Downloads (.deb / tar.gz)
Pre-built packages are available on the **[Releases Page](https://github.com/xdearboy/apex/releases/latest)**:
- Debian / Ubuntu: `apex_1.5.0_amd64.deb` (`dpkg -i apex_1.5.0_amd64.deb`)
- Standalone Tarball: `apex_1.5.0_linux_amd64.tar.gz`

---

## 📂 Configuration & Standard Paths

Apex follows Linux FHS standards and Nginx-like modularity:

| Path | Purpose |
| :--- | :--- |
| **`/etc/apex/apex.conf`** | Main configuration file (events, workers, buffers, http block) |
| **`/etc/apex/conf.d/*.conf`** | Modular virtual hosts and upstream definitions (included automatically) |
| **`/var/log/apex/`** | Access (`access.log`) and error (`error.log`) logs (owned by `apex:apex`) |
| **`/var/cache/apex/`** | Fast proxy cache storage |
| **`/var/www/static/`** | Default static asset root |
| **`/etc/logrotate.d/apex`** | Automated log rotation config with USR1 signaling |

### Minimal Example: Reverse Proxy (`/etc/apex/conf.d/api.conf`)
```nginx
upstream backend_cluster {
    policy p2c; # Power-of-Two-Choices with EWMA latency
    server 127.0.0.1:9001 weight=2 max_conns=1024;
    server 127.0.0.1:9002 weight=1 max_conns=1024;
    keepalive 128;
    connect_timeout 2s;
    read_timeout 10s;
}

server {
    listen ":8080";
    server_name api.example.com;

    # Health check
    location "=" "/health" {
        access_log off;
        return 200 "OK\n";
    }

    # Reverse proxy with rate limiting
    location "/api/" {
        proxy_pass backend_cluster;
        proxy_set_header "Host" "$host";
        proxy_set_header "X-Real-IP" "$remote_addr";
        proxy_set_header "X-Forwarded-For" "$proxy_add_x_forwarded_for";
        proxy_set_header "X-Forwarded-Proto" "$scheme";
        proxy_http_version 1.1;

        limit_req zone=req_limit burst=50 nodelay;
    }

    # Static assets with caching
    location "/static/" {
        root "/var/www/static";
        proxy_cache apex_cache;
        proxy_cache_valid 200 1h;
        add_header "Cache-Control" "public, max-age=3600";
    }
}
```

### CLI & Service Management
```bash
# Validate configuration without starting
apex -t -c /etc/apex/apex.conf

# Run in foreground
apex -c /etc/apex/apex.conf

# Systemd commands
sudo systemctl enable --now apex   # Start & enable on boot
sudo systemctl reload apex         # Zero-downtime reload via SIGHUP
sudo systemctl status apex         # Inspect service & worker status
sudo journalctl -u apex -f         # Follow live logs
```

---

## 📊 Benchmarks & Performance

Apex is engineered for bare-metal performance, predictable tail latency, and zero dynamic allocations on request hot paths.

### 1. `io_uring` vs `epoll` Single-Core Event Engine
*Tested on Linux 6.12 with AMD EPYC (single worker, closed-loop / keep-alive benchmarking)*:

| Event Engine | Throughput (RPS) | Latency (p50) | Latency (p99) | Syscall Overhead |
| :--- | :---: | :---: | :---: | :---: |
| **Apex (io_uring native)** | **630,223 req/s** | **68 µs** | **310 µs** | Minimal (batched CQE) |
| **Apex (epoll fallback)** | 140,240 req/s | 280 µs | 1.12 ms | Standard `epoll_wait` |
| **Gain** | 🚀 **+349%** | **-75% latency** | **-72% tail** | **Zero-syscall polling** |

### 2. Multi-Core Pipelined & TLS Throughput
*Tested on AMD EPYC 4244P (6 cores / 12 threads @ 5.3 GHz, 32 GB DDR5 ECC)*:

| Scenario | Concurrency | Throughput (RPS) | Tail Latency (p99) | Bandwidth |
| :--- | :---: | :---: | :---: | :---: |
| **GET / (Pipelined depth=128)** | 192 conn | **20,285,838 req/s** | 19.10 ms | 1.70 GB/s |
| **GET / (Pipelined depth=64)** | 160 conn | **14,645,742 req/s** | 34.05 ms | 1.23 GB/s |
| **GET / (TLS 1.3 HTTPS)** | 50 conn | **407,405 req/s** | **1.23 ms** | 34.97 MB/s |
| **GET / (Plaintext HTTP/1.1)** | 100 conn | **380,778 req/s** | **3.30 ms** | 32.57 MB/s |

### 3. Official HttpArena Worldwide Standing (64-core Bare-Metal)

Apex is ranked **#1 in HTTP/2** and **Top 5 in HTTP/1.1** overall across all web frameworks in the official [HttpArena](https://http-arena.com) benchmark on 64-core AMD Threadripper:

| Profile / Scenario | Official Rank | Throughput (RPS) | Tail Latency (p99) | Protocol |
| :--- | :---: | :---: | :---: | :---: |
| **`pipelined` (depth=16, 4k conn)** | 🥇 **#1 of 180** | **59,539,961 req/s** | 1.39 ms | HTTP/1.1 |
| **`baseline-h2c` (1024 conn)** | 🥇 **#1 of 70** | **16,634,930 req/s** | 16.26 ms | HTTP/2 Cleartext |
| **`baseline-h2` (1024 conn)** | 🥇 **#1 of 81** | **16,030,277 req/s** | 86.69 ms | HTTP/2 over TLS |
| **`limited-conn` (4096 conn)** | 🥇 **#1 of 195** | **2,822,803 req/s** | 1.80 ms | HTTP/1.1 |
| **`json-h2c` (1024 conn)** | 🥈 **#2 of 68** | **5,961,855 req/s** | 60.23 ms | HTTP/2 Cleartext |
| **`baseline-4096`** | 🥉 **#3 of 195** | **4,403,856 req/s** | 1.96 ms | HTTP/1.1 |

---

## 🤖 AI Agent & LLM Integration (Agent Skill)

For AI coding assistants, autonomous agents, and DevOps bots (such as Hermes Agent, Antigravity, Claude Code, Cursor), Apex includes an official skill definition:

- **Location**: [`skills/apex-proxy/SKILL.md`](skills/apex-proxy/SKILL.md)
- **Provides**: Automated rules for generating valid `apex.conf` blocks, safe reload procedures (`apex -t` prior to SIGHUP), kernel parameter verification, and diagnostic steps.

---

## 🛠️ Building from Source

### Prerequisites
- GCC or Clang with C23 support (`-std=c2x`)
- Libraries: `libssl-dev`, `libnghttp2-dev`, `libbrotli-dev`, `libzstd-dev`, `zlib1g-dev`, `libluajit-5.1-dev`, `liburing-dev`, `libngtcp2-dev`, `libnghttp3-dev`, `libwasmedge-dev`

```bash
# Clone and build
git clone https://github.com/xdearboy/apex.git
cd apex
make -j$(nproc)

# Run full integration test suite
make test

# Build Debian .deb package
./scripts/build_deb.sh 1.5.0
```

---

## 📜 License

Released under the [MIT License](LICENSE).
