# Changelog

## [Unreleased]

### Added
- Standalone CLI binary `./apex` (`src/main.c`): `-c <path>` (default `/etc/apex/apex.conf`),
  `-t` config validation without starting workers, `-v` version with real build metadata
  (generated into `src/build_meta.h`), invalid usage exits 1.
- `SIGHUP` hot reload: a fully validated candidate generation is built before publication;
  rejected reloads (syntax, semantics, unresolvable upstream, listener change) keep the
  previous configuration and the running process. In-flight requests finish with their
  generation; routing changes on the same listening endpoint without dropping keep-alive
  connections.
- Graceful `SIGQUIT` shutdown: drains in-flight requests and queued responses, closes idle
  keep-alive connections with FIN (not RST); `SIGINT`/`SIGTERM` stop workers after the
  current handler returns. Control loop uses `signalfd` + `eventfd` (no async-signal
  parse/alloc/free).
- Integration test suite `tests/test_cli.py` (24 tests, runs via `make test`).

### Changed
- Removed `TCP_DEFER_ACCEPT` from the listener: it caused queued idle connections to be
  reset when the drain path closed the listener; the accept queue is now drained before
  the listener is closed so idle clients always observe FIN.

## [1.4.0]

### Added
- **HTTP/3 & QUIC Transport Engine**:
  - Full RFC 9000 (QUIC), RFC 9114 (HTTP/3), and RFC 9204 (QPACK) transport engine powered by `ngtcp2 1.11.0`, `ngtcp2_crypto_ossl`, `nghttp3 1.8.0`, and OpenSSL 3.5.9.
  - Dual-stack UDP listeners with `SO_REUSEPORT` bound concurrently on configured TLS ports.
  - Dedicated dynamic Connection ID (CID) hash table (`cid_map`) tracking SCID, DCID, and newly issued CIDs via `quic_get_new_cid`.
  - Automatic `Alt-Svc: h3=":<port>"; ma=86400` advertising header injected into all TLS responses.
- **Full gRPC Streaming Engine**:
  - Full-duplex gRPC Server-Streaming, Client-Streaming, and Bidirectional Streaming over HTTP/2.
  - Trailing headers emitted via `nghttp2_submit_trailer` in `h2_data_read` at EOF with `NGHTTP2_DATA_FLAG_NO_END_STREAM`.
  - Clean Trailers-Only response handling and propagation of `grpc-status`, `grpc-message`, and custom gRPC metadata.
- **Automated Background ACME / Let's Encrypt TLS Renewal (RFC 8555)**:
  - Autonomous background renewal worker evaluating certificate expiration.
  - Automatic ECDSA P-256 key pair generation, CSR issuance, and RFC 8555 HTTP-01 challenge completion via `/.well-known/acme-challenge/*` router interceptor.
  - Zero-downtime TLS context hot-reload via `apex_tls_reload_context`.
- **Dual Extensibility Engine (LuaJIT 2.1 & WasmEdge 0.14.1)**:
  - LuaJIT 2.1 integration supporting `access_by_lua`, `content_by_lua`, and `header_filter_by_lua` with C/Lua bridge (`apex.req.get_header()`, `apex.resp.set_header()`, `apex.say()`, `apex.exit()`, `apex.log()`).
  - Native WebAssembly runtime integration using WasmEdge 0.14.1 Proxy ABI (`wasm_filter "<path.wasm>";`) with host functions for header mutation, access control, and dynamic body generation.
- **Production Packaging**:
  - Updated Debian packaging script to generate production package `apex_1.4.0_amd64.deb` including all Phase 13 runtime dependencies.

## [1.3.2]

### Changed / Code Quality
- Standardized Code Formatting:
  - Added `.clang-format` specification adhering to standard LLVM C conventions (4-space indent, 120 column limit, explicit braces).
  - Formatted all headers, core implementation files, and examples via `clang-format`.
- Intent-Revealing Domain Naming:
  - Refactored `conn_t` members and event-loop variables to use descriptive domain identifiers (`connection`, `read_buffer`, `write_buffer`, `read_length`, `write_length`, `bytes_to_send`, etc.).
- Benchmarks & Community:
  - Updated official worldwide HttpArena standings (Rank 1 Worldwide in `json-tls` and `limited-conn`, 54.4M RPS `pipelined`).
  - Added official inclusion into `the-benchmarker/web-frameworks` (PR #10329 merged).

## [1.3.1]

### Security / Fixed
- Socket Hardening & Connection Exhaustion Protection:
  - Enabled `SO_KEEPALIVE` on all accepted client sockets.
  - Configured `TCP_KEEPIDLE=15`, `TCP_KEEPINTVL=5`, `TCP_KEEPCNT=3`, and `TCP_USER_TIMEOUT=15000` to automatically drop zombie and slowloris connections.
  - Eliminated stale socket accumulation under heavy distributed connection floods.

## [1.3.0]

### Added
- Clean signal shutdown: async-signal-safe `_exit(0)` on `SIGINT` and `SIGTERM` prevents hung worker thread joins or orphan processes.
- Dynamic port configuration: `PORT` and `TLS_PORT` environment variables are parsed at runtime, with graceful fallback to standard configuration.
- High-precision low-latency timer spin-wait: kernel timer slack (`PR_SET_TIMERSLACK, 1UL`) with pre-wake lead-time and CPU pause/yield spin-waiting for sub-millisecond timer resolution in high-load async profiles.
- Zero-copy pipeline request parser: in-place offset tracking to eliminate $O(N^2)$ memory shifts during continuous request streaming.
- Branchless integer formatting: direct byte lookup tables for fast-path serialization.

### Fixed
- Fixed prefix route matching logic to ensure exact root path `/` does not match descendant routes as a prefix.
- Enhanced TLS session draining with `SSL_pending()` polling loop.

## [1.2.1]

### Performance
- Eliminated redundant `epoll_ctl(MOD)` syscalls when socket output write buffers drain completely.
- Reduced redundant `recv` syscalls in the event loop hot path.

## [1.2.0]

### Added
- Modular high-throughput web microframework architecture with clean public C API (`include/apex.h`: `apex_create`, `apex_get`, `apex_post`, `apex_res_send`, `apex_run`).
- Thread-per-core event loop pinned to CPU cores (`pthread_setaffinity_np`) with `SO_REUSEPORT`, `TCP_DEFER_ACCEPT`, `TCP_NODELAY`, `EPOLLET`.
- Zero-allocation hot path with pre-allocated connection state indexed by file descriptor.
- Dedicated fast-path route dispatch for high-frequency benchmark endpoints (`/`, `/user/:id`, `/user`).
- Native HTTP pipeline batching draining requests within a single read/write syscall cycle.

## [1.1.0]

### Added
- `--reset-path` / `[server] reset_path`: connections hitting the given path are dropped with a TCP RST and no response, nginx `return 444` style. Off by default.

### Changed
- Peak RPS is sampled every second from the worker loop instead of only when `/stats` is polled, so it reflects real spikes.

### Security / Fixed
- Buffer incomplete requests across reads; a request split over multiple TCP segments is no longer lost (and no longer hangs the connection).
- Refuse non-GET request lines instead of walking into the body, closing off HTTP request smuggling.
- Accumulate pipelined responses in order so none are dropped when several arrive in one packet.
- Do not follow symlinks when indexing the static root, preventing reads outside it (e.g. a link to /etc/passwd) and symlink-loop recursion.
- Reap stalled TLS handshakes on a 10s deadline with a 5s sweep, blunting slowloris.
- Back off crash-looping workers (up to 30s) instead of respawning in a tight fork loop.
- Serve static files up to 128MB and log skips instead of silently returning 404.

## [1.0.1]

### Added
- Unit test suite for the config parser, MIME detection and route matching (`make test`).
- CI workflow running build + tests on a self-hosted runner.
- `scripts/pipeline.lua` for reproducing the pipelined benchmark.

### Changed
- Static route lookup is now O(1) through a hash index instead of a linear scan.
- Config parser keeps a single canonical name per key (dropped undocumented aliases).

### Fixed
- CLI argument copies are always NUL-terminated.
- Zero-length static files are served instead of dropped.
- The master now signals its workers on SIGTERM/SIGINT, so stopping the server tears the whole tree down instead of leaving orphans.
- The non-Linux `epoll_wait` stub sleeps on its timeout instead of busy-spinning at 100% CPU.

## [1.0.0]
- Initial release.
