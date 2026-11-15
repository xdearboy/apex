# Apex High-Performance HTTP/1.1 & HTTP/2 Engine

This directory contains the full, production-grade tuned HTTP engine implementation powering Apex's top-tier standings in the [HttpArena](https://http-arena.com) worldwide benchmarks.

## Architecture & Features

- **Multi-Core Event Loop**: Linux `epoll` with `EPOLLET` (edge-triggered) and `SO_REUSEPORT` kernel load balancing across all CPU cores.
- **RFC 9113 HTTP/2 Engine**: Native multiplexed HTTP/2 support powered by `nghttp2`, supporting zero-allocation stream table mapping and batch frame output flushing.
- **TLS 1.3 Acceleration**: Powered by OpenSSL 3 with AEAD ciphers (`TLS_AES_128_GCM_SHA256`) and strict ALPN isolation between HTTP/1.1 and HTTP/2.
- **Asynchronous Timers**: Min-heap timer priority queue handling tens of thousands of concurrent delayed requests (`/delay/{ms}`) with sub-millisecond precision and zero CPU burn.
- **Streaming HTTP/1.1 Parser**: Resilient against arbitrary TCP fragmentation and chunked transfer encodings (`Transfer-Encoding: chunked`).
- **Static Asset Delivery**: Memory-efficient static file pipeline supporting Brotli and Gzip precompressed assets with dynamic MIME detection.
- **Zero-Allocation Hot Path**: Pre-allocated connection state pools, fast integer parsing, and lookup-table-based branchless string formatters.

## Port Topology

| Port | Protocol | Security | ALPN | Description |
| :--- | :--- | :--- | :--- | :--- |
| **8080** | HTTP/1.1 | Cleartext | — | Primary HTTP/1.1 baseline, pipelining, async delay, and dynamic query summing. |
| **8081** | HTTP/1.1 | TLS 1.3 | `http/1.1` | HTTPS endpoints (JSON serialization, 8Gbit echo, and static assets). |
| **8082** | HTTP/2 | Cleartext (`h2c`) | — | Direct prior-knowledge HTTP/2 cleartext multiplexing. |
| **8443** | HTTP/2 | TLS 1.3 (`h2`) | `h2` | Encrypted multiplexed HTTP/2 endpoints with stream isolation. |

## Building & Running

### Using Docker
```bash
# Build the container image
docker build -t apex-engine engine/

# Run the engine
docker run -p 8080:8080 -p 8081:8081 -p 8082:8082 -p 8443:8443 apex-engine
```

### Local Build (Linux)
Requires `gcc`, `make`, `libssl-dev`, `libcjson-dev`, `libbrotli-dev`, `zlib1g-dev`, and `libnghttp2-dev`:
```bash
cd engine
make -j$(nproc)
./server
```
