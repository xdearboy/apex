# Apex Engine: The Definitive Next-Gen Web Server & Reverse Proxy Specification

> **Architectural Vision**: An uncompromising, bare-metal C23 web server and L7 reverse proxy engineered to outperform NGINX, Envoy, and H2O. Designed to process tens of millions of requests per second per node, sustain sub-microsecond proxy latencies, and serve as the high-throughput, impenetrable data plane for **NeoGate**.

---

## 1. Core Runtime & Zero-Overhead Data Plane

### 1.1. Shared-Nothing Thread-per-Core (NUMA-Aware)
- **CPU Affinity & Isolcpus**: Every worker thread is pinned to an isolated CPU core via `pthread_setaffinity_np`. Memory buffers, epoll instances, connection pools, and timers are allocated strictly on the local NUMA node (`numa_alloc_onnode` / `mmap(MAP_PRIVATE|MAP_ANONYMOUS)` with `mbind`).
- **Zero Cross-Core Contention**: Zero global mutexes, zero atomic reference counts, and zero cross-thread cache-line invalidations (`false sharing`) on the hot request/proxy path.
- **Kernel Connection Load Balancing**: Dedicated listening sockets per worker with `SO_REUSEPORT`, `SO_ATTACH_REUSEPORT_CBPF` (or `eBPF SO_REUSEPORT`) for direct NUMA-aware connection steering, `TCP_DEFER_ACCEPT`, and `TCP_NODELAY`.

### 1.2. Kernel-Bypass & Zero-Copy I/O Mechanics
- **Edge-Triggered Event Loops**: Dual-backend reactor supporting:
  - Linux `io_uring` with registered buffers (`IORING_REGISTER_BUFFERS`) and fixed file descriptors (`IORING_REGISTER_FILES`) for pure asynchronous zero-syscall networking.
  - Linux `epoll` (`EPOLLET | EPOLLONESHOT`) using `accept4(SOCK_NONBLOCK | SOCK_CLOEXEC)` as universal ultra-fast fallback.
- **Downstream-to-Upstream Zero-Copy Forwarding**:
  - **Linux `splice(2)` Pipeline**: Plaintext HTTP/1.1 and raw stream proxying pipes client socket data directly to backend sockets via circular kernel pipe buffers without traversing userspace memory.
  - **Vectorized `vmsplice` & Ring Buffers**: Dynamic payload rewriting, TLS termination, and header modification utilize pre-allocated slab rings with `struct iovec` arrays.
- **Static Assets & Disk I/O**:
  - Asynchronous disk reading via `io_uring` (or `sendfile64`) combined with memory-mapped immutable page caches (`mmap` with `MAP_SHARED`).
  - Cached files pre-compressed in `.br`, `.zst`, and `.gz` twins selected branchlessly by client `Accept-Encoding`.

---

## 2. Advanced Protocol Engine

### 2.1. HTTP/2 with Vectorized HPACK Engine
- **Custom Vectorized HPACK Implementation**:
  - Independent static and dynamic header tables per H2 connection.
  - Fixed-size ring buffer for the dynamic table with zero heap allocations on table evictions.
  - SWAR (SIMD Within A Register) and AVX2/NEON Huffman decoder parsing multiple 4-byte / 8-byte symbols per cycle.
  - Pre-encoded static wire headers for common response patterns (`:status: 200`, `server: apex`, `content-type: ...`).
- **Prioritization & Flow Control**:
  - RFC 9218 (Extensible Prioritization Scheme for HTTP) using urgency (`u=0..7`) and incremental (`i`) flags.
  - Adaptive per-stream window management to eliminate head-of-line blocking on heavy downstream pipes.
- **Multiplexed Frame Coalescing**:
  - Automatic batching of multiple `DATA` frames and `HEADERS` frames across concurrent streams into contiguous 64KB TLS records, slashing `writev` / `SSL_write` syscall overhead by up to 90%.

### 2.2. HTTP/3 & QUIC Transport
- **Independent UDP Socket per Worker Core**:
  - Sockets configured with `SO_REUSEPORT` and `UDP_GRO` (Generic Receive Offload) / `UDP_GSO` (Generic Segmentation Offload) to ingest 64KB UDP datagram batches in a single syscall.
- **Custom QPACK Encoder/Decoder**:
  - Streaming instruction parser without blocking head-of-line control streams.
- **0-RTT Handshake & Session Resumption**:
  - Local per-worker TLS 1.3 ticket key cache for instantaneous connection establishment.

### 2.3. WebSocket & gRPC Streaming
- **RFC 6455 Fast Gateway**:
  - SIMD-accelerated XOR masking and unmasking (AVX2/NEON 32-byte chunks per cycle).
  - Transparent bidirectional proxy tunnel mode between downstream clients and microservice backends.
- **gRPC Unary & Bidirectional Streaming**:
  - Native Protobuf frame pass-through over HTTP/2 with sub-microsecond header inspection for trailer status codes (`grpc-status`, `grpc-message`).

---

## 3. High-Performance Reverse Proxy & Upstream Engine

### 3.1. Thread-Local Upstream Connection Pool
- **Persistent Keep-Alive Rings**:
  - Every worker core maintains its own isolated pool of established TCP/TLS connections to configured upstream server clusters.
  - Zero cross-thread handoffs: client requests are serviced end-to-end on the thread where the connection landed.
- **Proactive Health Checking & Circuit Breaking**:
  - Sub-millisecond passive health checking: tracking 5xx rates, TCP resets (`RST`), and connection timeouts.
  - 3-state circuit breaker (Closed, Open, Half-Open) per backend node with automatic background health probing.

### 3.2. Microsecond Load Balancing Algorithms
1. **Power of Two Random Choices (`p2c` with Peak EWMA)**:
   - Selects two candidate backends at random and picks the one with the lowest Exponentially Weighted Moving Average latency. Prevents the "herding effect" common in standard Least Connections.
2. **Maglev / Ketama Consistent Hashing**:
   - Zero-allocation hashing on client IP, request headers, or cookie values to guarantee cache affinity with minimal reshuffling on node changes.
3. **Round-Robin & Weighted Distribution**:
   - Branchless atomic-free index cycling through pre-computed flat backend slot arrays.

### 3.3. Upstream Buffering & Request/Response Rewriting
- **Adaptive Memory Spooling**:
  - Small responses (< 64KB) buffered entirely in thread-local ring slabs to release backend connections immediately.
  - Large responses streamed instantly via kernel pipes (`splice`) to protect reverse proxy RAM.
- **Zero-Allocation Header Morphing**:
  - In-place header filtering and insertion (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Real-IP`, `CF-Connecting-IP`, `traceparent`).

---

## 4. Pluggable Phase-Based Module Architecture (C23 / DSO)

Apex provides a deterministic 7-phase execution pipeline. Modules are compiled as standalone `.so` shared libraries (`-O3 -fPIC -march=native`) and dynamically loaded with `dlopen`/`dlsym` during startup.

```
       [ Client Connection ]
                 │
                 ▼
     ┌───────────────────────┐
     │ 1. PRE_ROUTING Phase  │ ──► eBPF/XDP drop, Geo-IP, Connection Limits
     └───────────────────────┘
                 │
                 ▼
     ┌───────────────────────┐
     │ 2. TLS_HANDSHAKE Phase│ ──► SNI Route, JA4/JA3 Fingerprint, mTLS
     └───────────────────────┘
                 │
                 ▼
     ┌───────────────────────┐
     │ 3. HEADER_FILTER Phase│ ──► Header sanitization, Cookie, Rewrite
     └───────────────────────┘
                 │
                 ▼
     ┌───────────────────────┐
     │ 4. ACCESS_CTRL Phase  │ ──► Token Bucket Rate Limit, Auth, PoW / WAF
     └───────────────────────┘
                 │
                 ▼
     ┌───────────────────────┐
     │ 5. CONTENT / PROXY    │ ──► Upstream Proxy (splice/H2), FastCGI, Static
     └───────────────────────┘
                 │
                 ▼
     ┌───────────────────────┐
     │ 6. RESPONSE_FILTER    │ ──► Dynamic Brotli/zstd, Security Headers, Inject
     └───────────────────────┘
                 │
                 ▼
     ┌───────────────────────┐
     │ 7. LOGGING Phase      │ ──► Async Ring-Buffer structured logging
     └───────────────────────┘
```

### 4.1. Module C Interface (`apex_module.h`)
```c
typedef enum {
    APEX_PHASE_PRE_ROUTING,
    APEX_PHASE_TLS_HANDSHAKE,
    APEX_PHASE_HEADER_FILTER,
    APEX_PHASE_ACCESS_CONTROL,
    APEX_PHASE_CONTENT_PROXY,
    APEX_PHASE_RESPONSE_FILTER,
    APEX_PHASE_LOGGING,
    APEX_PHASE_COUNT
} apex_phase_t;

typedef enum {
    APEX_ACTION_CONTINUE,
    APEX_ACTION_STOP_OK,
    APEX_ACTION_ERROR_DROP,
    APEX_ACTION_CHALLENGE
} apex_action_t;

typedef struct apex_module {
    const char *name;
    const char *version;
    int (*init)(apex_engine_config_t *config);
    void (*destroy)(void);
    apex_action_t (*handlers[APEX_PHASE_COUNT])(apex_ctx_t *ctx);
} apex_module_t;
```

---

## 5. NeoGate Native Integration (The Shield Architecture)

Apex is explicitly architected to become the core reverse proxy and packet-filtering engine for **NeoGate**, replacing generic third-party reverse proxies with specialized bare-metal code.

### 5.1. Sub-Millisecond L7 Anti-DDoS
- **Lock-Free Thread-Local Sliding Window**:
  - Per-worker compact 64-bit Robin Hood hash tables tracking client IP rates across 1-second and 10-second sliding windows.
  - Multi-tier thresholds: Soft Rate Limit (delayed queueing) -> Challenge (Proof-of-Work) -> Hard Ban (kernel IP set offload via `ipset` / eBPF map).

### 5.2. Client Fingerprinting (JA4 / JA3 / HTTP/2 Fingerprint)
- **Zero-Copy TLS Handshake Inspection**:
  - Inspecting `ClientHello` raw records before cipher negotiation.
  - Extracting JA4 signature: Protocol (`t13d`), Cipher list hash, Extension list hash, ALPN signature.
  - Comparing against malicious bot & headless browser database in **sub-100 nanoseconds**.
- **HTTP/2 SETTINGS & Window Size Fingerprint**:
  - Analyzing initial H2 frame flags, priority trees, and initial window sizes to identify forged User-Agent headers.

### 5.3. Embedded WAF (Web Application Firewall)
- **SIMD/Hyperscan Regex Accelerator**:
  - Pre-compiled multi-pattern matching database for SQL Injection, Cross-Site Scripting (XSS), Remote Code Execution (RCE), and Path Traversal.
  - Single-pass scanning of URI query parameters, cookies, and JSON body streams.

### 5.4. Active Bot Mitigation: Cryptographic Proof-of-Work & JS Challenges
- **Stateless Cryptographic Challenge**:
  - Generates an HMAC-signed SHA-256 / Argon2 micro-puzzle returned in a lightweight 1.2KB HTML/WASM payload.
  - Client solves puzzle in browser (~30ms) and returns nonce cookie.
  - Reverse proxy validates nonce in **< 1 microsecond** without maintaining server state.

---

## 6. Implementation Milestones

```
Phase 1: Arena Benchmark Dominance (Active)
   ├── 59.5M pipelined, 16.6M H2C (Complete)
   ├── 560k baseline-4096 (Beat Zix, Complete)
   └── Immutable pre-computed JSON/gzip pipeline (Complete)

Phase 2: Upstream Connection Engine & Reverse Proxy Core
   ├── Per-worker keep-alive upstream socket pools
   ├── Linux splice(2) zero-copy proxying pipe
   └── HPACK full dynamic table & RFC 9218 prioritization

Phase 3: Modular Architecture & Dynamic Module Loader
   ├── 7-Phase execution pipeline
   ├── dlopen dynamic DSO plugin system
   └── Hot-reloadable zero-downtime configuration parser

Phase 4: NeoGate Shield Engine
   ├── Sub-microsecond JA4 / TLS fingerprinting
   ├── In-memory lock-free sliding-window rate limiters
   ├── SIMD WAF query/body inspection module
   └── Stateless WASM / JS Proof-of-Work challenge injector
```

---

## 7. Production Hardening, Observability & Lifecycle Management

To fully replace NGINX, Envoy, and H2O in real-world mission-critical edge deployments, Apex includes:

### 7.1. Zero-Downtime Hot Upgrades & Configuration Reloads (`SIGHUP` / Socket Passing)
- **Binary Upgrades without Dropping a Single Packet**:
  - Fork-and-exec workflow: Master process spawns new Apex binary and passes listening socket file descriptors via `SCM_RIGHTS` UNIX domain socket control messages.
  - Old workers enter graceful drain mode: stop accepting new connections, finish in-flight requests, and cleanly terminate (`close_idle_connections`).
- **Live Configuration Reloads**:
  - Atomic pointer swap (`RCU` pattern) for routing tables, upstream backend clusters, TLS certificates, and ACL lists.
  - Workers swap to new configuration trees in **zero CPU cycles of latency overhead**.

### 7.2. High-Performance Caching & Microcaching Engine
- **Hierarchical Tiered Cache**:
  - **L1 RAM Cache**: Lock-free thread-local LRU slab for hot microcached objects (<128KB).
  - **L2 Fast NVMe / SSD Cache**: Asynchronous direct I/O (`io_uring` + `O_DIRECT`) eliminating OS buffer cache pollution.
- **Cache-Control & Revalidation Protocols**:
  - Full RFC 9111 HTTP caching compliance: `stale-while-revalidate`, `stale-if-error`, and conditional upstream probing (`304 Not Modified`).
  - Single-Flight Request Collapsing: If 10,000 requests hit an expired cache entry simultaneously, only **one** request passes through to the upstream backend, while 9,999 wait for the response fill.

### 7.3. Dynamic Scripting Engine: Embedded LuaJIT / WASM (WebAssembly)
- **Ultra-Fast Custom Edge Logic**:
  - Embedded **LuaJIT** integration (FFI-based) with pre-compiled bytecode execution for custom routing, token validation, and header injection with near-native C performance.
  - Optional **WASM Runtime (wasmtime / wasmer)** support allowing developers to compile proxy filters written in Rust, Go, or Zig directly into Apex.

### 7.4. Observability & Zero-Cost Telemetry
- **Prometheus / OpenMetrics Native Scraper Endpoint**:
  - Sub-microsecond `/metrics` handler exposing per-worker throughput, tail latencies (p50, p90, p99, p99.9 histograms), upstream connection pool health, and active stream counts.
- **OpenTelemetry & W3C Distributed Tracing**:
  - Sub-nanosecond parsing and injection of `traceparent` / `tracestate` headers across downstream-to-upstream boundaries.
- **eBPF-Assisted Telemetry**:
  - Kernel tracepoints for measuring TCP round-trip times (RTT), socket buffer bloat, and retransmission rates directly from kernel `tcp_info`.
