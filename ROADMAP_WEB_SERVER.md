# Apex: Vision & Roadmap to Next-Gen Web Server & Reverse Proxy

> **Mission**: Transform Apex from an ultra-fast benchmark micro-framework into a production-grade, modular Web Server & Reverse Proxy — an uncompromising, modern C23 alternative to NGINX, Envoy, and H2O, purpose-built to power high-throughput edge systems and serve as the core engine for **NeoGate**.

---

## 1. Core Architectural Tenets

1. **Shared-Nothing Thread-per-Core**:
   - Worker threads strictly pinned to hardware CPU cores (`pthread_setaffinity_np`).
   - Independent `epoll` / `io_uring` instances per core with `SO_REUSEPORT` kernel connection steering.
   - Zero locks or atomic contention on the hot request/proxy forwarding path.

2. **Zero-Allocation Data Plane**:
   - Ring buffers and slab allocators for headers, connection state, and upstream forwarding.
   - Zero memory copies for static file serving (`sendfile` / pre-mapped page caches) and streaming reverse proxying (`splice` / `vmsplice` / vectorized rings).

3. **Multi-Protocol Modernity**:
   - HTTP/1.1 (pipelining, chunked transfer).
   - HTTP/2 (multiplexing, HPACK/QPACK, flow control).
   - HTTP/3 & QUIC (UDP socket per core, 0-RTT handshakes).
   - WebSockets (RFC 6455) & gRPC unary/streaming proxying.

---

## 2. Reverse Proxy & Upstream Engine

- **High-Performance Upstream Connection Pooling**:
  - Keep-alive connection caches to backend upstream servers per worker thread.
  - Sub-millisecond health checking, passive circuit breakers, and automatic failover.
- **Load Balancing Algorithms**:
  - Round Robin, Least Connections, Consistent Hashing (Ketama) by IP/header/cookie.
  - Power of Two Random Choices (`p2c`) for optimal latency distribution.
- **Streaming Pipeline (`splice` / Zero-Copy Tunneling)**:
  - Direct kernel pipe splicing between downstream client sockets and upstream backend sockets without roundtripping through userspace buffers.
- **TLS Offloading & Termination**:
  - Modern TLS 1.3 (OpenSSL / BoringSSL / aws-lc) with asynchronous crypto offload.
  - Zero-RTT session resumption, dynamic certificate loading via SNI, automated ACME/Let's Encrypt renewal integration.

---

## 3. Pluggable Module Architecture (Extensibility)

To support modular capabilities without runtime performance penalty:

1. **Phase-Based Request Pipeline**:
   - `PRE_ROUTING`: Early packet inspection, IP ACL, connection limits.
   - `SSL_HANDSHAKE`: SNI inspection, mTLS client cert validation, JA4/JA3 fingerprinting.
   - `HEADER_FILTER`: Header rewrite, CORS, cookie parsing, security headers.
   - `ACCESS_CONTROL`: Rate limiting, token verification (JWT, HMAC), authentication.
   - `CONTENT_HANDLER`: Static file, FastCGI, internal handler, or Upstream Proxying.
   - `RESPONSE_FILTER`: Compression (Brotli/zstd/gzip on the fly or pre-cached), response rewriting, metrics collection.
   - `LOGGING`: Asynchronous non-blocking structured access logs (JSON, binary ring buffers).

2. **DSO / Dynamic Shared Object Modules**:
   - Clean C API (`apex_module_t`) allowing independent `.so` plugins compiled with `-O3`.
   - Optional eBPF / XDP integration modules for DDoS filtering directly in the kernel before reaching userspace.

---

## 4. NeoGate Integration & Edge Protection

Apex will serve as the bare-metal foundation for rewriting and powering **NeoGate**:

- **L7 Reverse Proxy & Ingress**: Replace external reverse proxies with native Apex, achieving multi-million RPS per node.
- **Anti-DDoS & Traffic Scrubbing**:
  - In-memory sliding window rate limiters (token bucket / leaky bucket) per IP / subnet.
  - TLS Fingerprinting (JA4 / JA3 / cipher suite analysis) to block malicious scrapers and bots at handshake phase.
  - Proof-of-Work (PoW) and JS challenge inject filter module for suspicious traffic.
- **WAF Engine**:
  - Fast SIMD/Hyperscan regex matching module for SQLi, XSS, and command injection rules.
  - Real-time IP reputation and geo-IP lookup with zero-allocation memory mapped radix trees.

---

## 5. Phased Roadmap

| Phase | Milestone | Deliverables |
| :---: | :--- | :--- |
| **Phase 1** *(Current)* | **HttpArena World #1 Engine** | Maximize micro-benchmarks, zero-alloc routing, TLS/H2/H2C mastery. |
| **Phase 2** | **Upstream & Reverse Proxy Core** | Upstream client pool, `splice`/vectorized proxying, load balancing. |
| **Phase 3** | **Modular Pipeline Engine** | Dynamic plugin API, phase hooks, configuration parser (`apex.conf` / JSON). |
| **Phase 4** | **Edge Protection & NeoGate Rewrite** | Rate-limiting, JA4 fingerprinting, WAF filter, integration into NeoGate stack. |
