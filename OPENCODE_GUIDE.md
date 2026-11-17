# APEX — Complete Project Context & Handover Guide for OpenCode

> **TARGET AUDIENCE**: OpenCode AI Agents, `gpt-6.1-sol`, `qwen-plus`, `grok-4.7`, and human developers.
> **LAST UPDATED**: 2026-11-17
> **PRIMARY REPOSITORY**: `https://github.com/xdearboy/apex` (branch: `main`)
> **WORKING DIRECTORY (LOCAL)**: `/Users/devo/Documents/antigravity/splendid-pascal/apex`
> **PRODUCTION / TEST VPS**: `root@57.129.105.196` (Debian 6.12 x86_64, path: `/root/apex-build`)

---

## 1. What is Apex?
Apex is an ultra-high-performance **Hybrid C23 Web Application Server & Reverse Proxy / Load Balancer** designed as a modern, lightweight alternative to Nginx / HAProxy / Envoy.

### Key Capabilities
1. **Application Server**: In-process C handlers via `apex_get()`, `apex_post()`, `apex_route()`. Zero memory allocation per request.
2. **Reverse Proxy / Load Balancer**: Nginx-style `upstream` blocks, `proxy_pass`, thread-local persistent connection pooling with keep-alive, and sub-microsecond load balancing algorithms (Weighted Round-Robin & Power-of-Two-Choices / P2C).
3. **Static File Server**: `root /path/to/static;` directive inside `location` blocks with MIME auto-detection, zero-copy `mmap`, path-traversal protection, and `HEAD` request support.
4. **Configuration Engine**: Declarative, Nginx-compatible configuration syntax (`apex.conf`) with `include`, environment expansion, syntax validation (`-t`), and hot-reloading architecture.
5. **Network Engine**: Linux `epoll` edge-triggered (`EPOLLET`), multi-worker shared listen sockets via `SO_REUSEPORT`, non-blocking I/O, pipelining, and zero-copy send buffers.

---

## 2. Critical Lessons & Strict Rules (NEVER BREAK THESE)

### Rule 1: No Synthetic Benchmark Hacks (Zero Cheat Policy)
- **Do NOT** bypass the HTTP parser or router with raw string searches (`memcmp(buf, "GET /json/", ...)`).
- **Do NOT** pre-render or pre-bake hardcoded responses for specific benchmark parameters.
- HttpArena maintainer explicitly rejected PR #1821 for hacky fast-paths. Apex must remain a **100% spec-compliant, general-purpose HTTP server**.
- All requests must parse cleanly and dispatch through the routing table.

### Rule 2: C23 Engineering Standards
- Strict C23 standard (`-std=c2x` or `-std=c23`), `-Wall -Wextra -Werror`.
- Zero placeholders: no `// TODO`, no dummy returns (`return true;`, `return 0;`), complete error handling on every syscall.
- Clean resource lifecycle: all memory, sockets, file descriptors, and `mmap` allocations must have explicit free/close paths.

---

## 3. Architecture & Codebase Map

```
apex/
├── Makefile                     # Build system (libapex.a, tests, examples)
├── conf/
│   └── apex.conf                # Reference Nginx-style configuration file
├── include/
│   ├── apex.h                   # Public API (apex_create, apex_get, apex_run, etc.)
│   └── apex/
│       ├── config.h             # Configuration AST, parser and runtime interfaces
│       └── proxy.h              # Reverse proxy, upstream pools, balancing policies
├── src/
│   ├── core.c                   # Epoll worker loop, SO_REUSEPORT, TCP tuning, accept4
│   ├── router.c                 # HTTP request dispatching, proxy forwarding, static file serving
│   ├── proxy.c                  # Upstream connection pool, p2c/round-robin balancing, HTTP/1.1 client
│   ├── config.c                 # Tokenizer, recursive-descent parser, runtime matching
│   └── internal.h               # Internal server data structures, connections, routes
├── engine/                      # Benchmark engine used for HttpArena sync
└── examples/
    ├── config_demo.c            # Test suite & CLI demonstration of config parser
    ├── proxy_demo.c             # Multi-threaded stress test & validation of proxy core
    ├── hello_world.c            # Basic app server example
    └── web_frameworks.c         # Route performance demo
```

---

## 4. How to Build & Test

### Local Build (macOS)
*Note: `src/core.c` uses Linux `sys/epoll.h`. On macOS, build components or test on the VPS.*

### Remote Build & Test on Linux VPS (`57.129.105.196`)
```bash
# 1. Connect
ssh root@57.129.105.196

# 2. Go to build directory and pull latest
cd /root/apex-build
git pull origin main

# 3. Build library and run test suites
make test
```
Tests will execute:
- `./examples/config_demo --selftest` (syntax, semantic, environment variables, include validation)
- `./examples/proxy_demo` (212+ requests across 4 worker threads, upstream timeouts, edge cases, P2C balance)

---

## 5. Configuration File Syntax (`conf/apex.conf`)

Apex uses clean Nginx-like syntax:

```nginx
events {
    worker_connections 10240;
}

http {
    keepalive_timeout 75s;
    client_header_timeout 15s;
    client_body_timeout 30s;

    upstream backend_api {
        balance p2c; # or round_robin
        server 127.0.0.1:8081 weight=5;
        server 127.0.0.1:8082 weight=10;
        keepalive 32;
        connect_timeout 2s;
        read_timeout 5s;
    }

    server {
        listen 8080;
        server_name localhost apex.local;

        # Static files
        location /static/ {
            root /var/www/static;
        }

        # Reverse Proxy to upstream pool
        location /api/ {
            proxy_pass backend_api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_connect_timeout 2s;
            proxy_read_timeout 5s;
        }

        # Direct Proxy to single host
        location /auth/ {
            proxy_pass http://127.0.0.1:9000;
        }
    }
}
```

---

## 6. Multi-Agent Setup in OpenCode

OpenCode is pre-configured in `~/.config/opencode/opencode.jsonc`:

| Agent | Model | Role |
| :--- | :--- | :--- |
| **`architect`** (Default Primary) | `agentrouter/gpt-6.1-sol` | Lead System Architect & Reviewer. Designs `.h` interfaces, validates RFC compliance, oversees tasks. |
| **`coder`** (Subagent) | `reformboss/qwen-plus` | High-performance C implementer. Writes clean, robust C23 code without shortcuts. |
| **`reviewer`** (Subagent) | `reformboss/grok-4.7` | Adversarial code reviewer. Audits memory safety, boundary conditions, buffers, and syscall returns. |

*Local Responses-API Proxy for `agentrouter/gpt-6.1-sol` runs via `node /Users/devo/.local/share/agentrouter-proxy/proxy.mjs` on port `8789`.*

---

## 7. Next Tasks Roadmap for OpenCode

If continuing without the parent assistant, prompt OpenCode with the following specific tasks:

1. **Standalone CLI Binary (`src/main.c`)**:
   - Add CLI executable `apex` with flags:
     - `-c <config_path>`: path to config file (default `/etc/apex/apex.conf`).
     - `-t`: test configuration syntax and exit with code 0 or 1.
     - `-v`: print version and build flags.
   - Connect signal handlers (`SIGHUP` for configuration reload, `SIGQUIT` for graceful shutdown).

2. **HTTP/2 Support for Reverse Proxy**:
   - Integrate ALPN negotiation in `src/core.c` using OpenSSL and `nghttp2`.
   - Implement H2-to-H1.1 translation in `src/proxy.c`.

3. **Active Health Checks for Upstreams**:
   - Add periodic background probes (`GET /health` or TCP connect) in `src/proxy.c`.
   - Automatically mark servers unhealthy and restore them when alive.

4. **Microcaching Module**:
   - In-memory lock-free cache for cacheable `GET` responses (based on `Cache-Control` / `Expires`).
