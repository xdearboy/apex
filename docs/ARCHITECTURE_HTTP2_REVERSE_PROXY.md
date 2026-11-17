# APEX Task 2 — HTTP/2 Reverse Proxy (TLS + ALPN + nghttp2)

> Architect spec for roadmap task "HTTP/2 Support for Reverse Proxy".
> Scope: TLS termination with ALPN on the shared listener, HTTP/2 client
> sessions served by the existing router, and h2→h1.1 translation for
> `proxy_pass` upstreams. Upstreams stay HTTP/1.1 in this task.

---

## 1. Scope

### In scope
- TLS 1.2/1.3 termination via OpenSSL on a listener marked `ssl` (one
  plaintext endpoint per instance remains the rule; one TLS endpoint is now
  allowed as *the* endpoint — not both simultaneously).
- ALPN (`RFC 7301`): offer `h2` and `http/1.1`; selection decides the
  connection protocol. Plaintext listeners never speak h2.
- HTTP/2 server sessions (`RFC 9113`) powered by `nghttp2` (system lib,
  already present: 1.64.0 on the build host).
- h2 requests served through the **existing** router: handler routes,
  static files, and `proxy_pass`.
- h2→h1.1 request translation and h1.1→h2 response translation in the
  proxy path.

### Out of scope (later tasks)
- Upstream HTTP/2 (h2 pools), gRPC pass-through trailers, WebSocket/CONNECT,
  HTTP/3, custom vectorized HPACK (nghttp2's HPACK is used), prioritization
  beyond nghttp2 defaults, session resumption tuning, OCSP stapling.

---

## 2. Configuration (src/config.c, docs/CONFIG_SPEC.md)

```
http {
    server {
        listen "127.0.0.1:8443" tls;
        tls {
            certificate "conf/cert.pem";
            private_key  "conf/key.pem";
        }
        ...
    }
}
```

- Grammar (already in `docs/CONFIG_SPEC.md`): `listen <scalar> [tls];` plus a
  `tls { certificate; private_key; [ciphers]; [protocols]; [client_auth]; }`
  block in `server{}` scope. The parser enforces: `listen tls` requires a
  `tls` block; the block requires certificate and private_key.
- Added in 2a: OpenSSL-level validation — cert chain load, key load,
  `SSL_CTX_check_private_key` — in `-t` (`apex_tls_validate_config`) and in
  generation creation. Mixed `tls`/plaintext servers on one endpoint are
  rejected ("cannot mix tls and plaintext servers on one listen endpoint").
- Reload: changing any of {host, port, tls flag, certificate path, private
  key path} changes the endpoint → **rejected, requires restart** (existing
  rule, now TLS-aware).

### Generation ownership
`apex_generation_t` gains `SSL_CTX *tls_context` (NULL for plaintext).
Created in `apex_generation_create`; owned and freed with the generation
(`SSL_CTX_free`). Workers dereference via `worker->generation` — no separate
refcount needed. Reload semantics inherited for free: in-flight TLS
connections keep the old generation's SSL_CTX (live SSL objects up-ref the
CTX), new connections use the new one after worker adoption.

---

## 3. TLS transport layer (src/core.c + new src/tls.c)

### 3.1 Socket state machine
`conn_t` gains a transport union:

```c
typedef enum { APEX_TRANSPORT_PLAIN, APEX_TRANSPORT_TLS } transport_kind_t;
typedef enum { TLS_HANDSHAKE, TLS_READY, TLS_CLOSED } tls_phase_t;

/* inside conn_t */
transport_kind_t transport;
SSL *ssl;               /* NULL when transport == PLAIN */
tls_phase_t tls_phase;
uint8_t alpn_h2;        /* negotiated "h2" */
```

- Accept path: for a TLS endpoint, `SSL_new(worker->generation->tls_context)`,
  `SSL_set_fd(fd, 1)`, `SSL_set_accept_state`, phase = HANDSHAKE, register
  EPOLLIN (ET).
- Handshake: on EPOLLIN/EPOLLOUT during HANDSHAKE call
  `SSL_do_handshake`; map `SSL_ERROR_WANT_READ`→EPOLLIN,
  `WANT_WRITE`→EPOLLOUT|EPOLLIN; other errors → close (no alert spam: send
  `SSL_shutdown` once, best effort).
- Established: `SSL_get0_alpn_selected` → `alpn_h2` flag.
- Read: `SSL_read` into the existing `read_buffer` loop; `WANT_READ` →
  stop, `WANT_WRITE` → arm EPOLLOUT (renegotiation edge), `ZERO_RETURN` →
  clean FIN path (existing close logic).
- Write: flush path uses `SSL_write` instead of `send`; same WANT_* mapping
  with `epollout_active` bookkeeping that already exists.
- Close: `SSL_shutdown` once, then `SSL_free`, then socket close (existing
  `close_fd` path). No blocking waits.

### 3.2 ALPN selection
`SSL_CTX_set_alpn_select_cb` on the generation's CTX:
- Milestone 2a (landed): advertised list contains only `http/1.1`; clients
  offering it connect as plain h1-over-TLS (the existing parser consumes the
  byte stream unchanged); no overlap → alert fatal. HTTP/2 negotiation is
  therefore impossible until 2b flips the offered list — deliberate, so the
  served protocol never exceeds what the core implements.
- Milestone 2b: prepend `h2`; `alpn_h2` flag on the connection routes it to
  the nghttp2 session layer.
- Plaintext path is untouched — zero regression risk for the h1 hot path.

---

## 4. HTTP/2 session layer (new src/h2.c)

### 4.1 Lifecycle
- `alpn_h2` connection → `h2_conn_t` allocated on first use:

```c
typedef struct h2_conn {
    nghttp2_session *session;
    SSL *ssl;               /* borrow from conn_t */
    h2_stream_t *streams;   /* open streams needing response materialization */
    uint8_t *out_buffer;    /* nghttp2 send staging (growable, capped) */
    size_t out_len, out_cap;
    uint8_t out_armed;      /* EPOLLOUT pending */
} h2_conn_t;
```

  Stored on `conn_t` (union with nothing else — h2 conns never run the h1
  parser). Freed on connection close: all live streams RST'd, virtual conns
  destroyed, `nghttp2_session_del`.

- Read side: SSL_read bytes → `nghttp2_session_mem_recv` in a loop until
  EAGAIN/WANT_READ. After each call: drain `nghttp2_session_want_write` via
  `nghttp2_session_send` into the SSL socket (direct write in send callback
  with WANT_WRITE → arm EPOLLOUT, mirroring the engine's proven pattern).
- Settings: send our SETTINGS (MAX_CONCURRENT_STREAMS 128, initial window
  default), handle client SETTINGS ACK. WINDOW_UPDATE emitted by nghttp2.
- GOAWAY: on drain (SIGQUIT) submit GOAWAY graceful, stop accepting new
  streams, finish live streams, then close like other drained conns.

### 4.2 Request handling — the h1 bridge
Existing pipeline is synchronous: `apex_dispatch_runtime` fully
materializes the response before returning (proxy does blocking upstream
I/O with timeouts; handlers/static write synchronously). Therefore:

1. `on_begin_frame`/`on_header` collect pseudo-headers + regular headers
   for stream (denied duplicates → `PROTOCOL_ERROR` RST, per RFC).
2. On HEADERS with END_STREAM (or after DATA chunks complete with
   END_STREAM): **synthesize an h1.1 request** into a scratch buffer:

```
<m :> <path> HTTP/1.1\r\n
Host: < :authority >\r\n
<regular headers, minus connection-scoped: connection, keep-alive,
 proxy-connection, transfer-encoding, upgrade>\r\n
\r\n
<body bytes accumulated from DATA>
```

   - `:method`/`:path` validated (RFC: uppercase method token, path starts
     with `/` or `*`); violation → RST `PROTOCOL_ERROR`, no dispatch.
   - Missing `:authority` and no `host` header → RST (h1 needs Host).
   - Request body: streamed through `on_data_chunk_recv` into a per-stream
     body buffer capped at 8 MiB; overflow → RST `REFUSED_STREAM`... no —
     `ENHANCE_YOUR_CALM`-free choice: RST with `INTERNAL_ERROR` + 413
     semantics is not expressible pre-headers; use RST_STREAM
     `REFUSED_STREAM` (client may retry) and count it.
3. Create a **virtual conn_t** (heap, zero fd, own read/write/aux buffers,
   `active = 1`) and call the unchanged
   `apex_dispatch_runtime(app, runtime, req_buf, header_len, body,
   body_len, &res)` with `res.conn = virtual_conn`.
4. On return, the virtual conn holds the complete h1 response. Parse it
   back into structured form (we generated it, format is fixed):
   status line → `:status`; header lines → nv array (drop `Connection`,
   `Transfer-Encoding`, `Keep-Alive`; add nothing else); body = remainder.
5. `nghttp2_submit_response` with a data provider pulling from the body
   buffer; nghttp2 handles flow control/window updates.
6. Stream close callback → destroy the stream's virtual conn + buffers.

**Response size guard**: virtual conns buffer whole responses. Cap at
16 MiB (aux growth beyond cap → abort response, submit RST
`INTERNAL_ERROR`, log). Static files above the cap: 500 for h2 clients,
unchanged sendfile-style path for h1. Documented limitation.

**Bridging rules honored by construction**: router/proxy code sees a normal
`conn_t *` — no `if (h2)` branches in routing, static, or proxy logic.

---

## 5. Proxy translation (src/proxy.c)

Upstream side stays h1.1:
- h2→h1 translation happens **only** in the bridge (§4.2 step 2): by the
  time dispatch runs, `proxy_pass` receives a well-formed h1 request.
- `X-Forwarded-Proto: https` appended when transport == TLS (value
  `http` otherwise) — set from `conn->transport` at bridge time.
- Response path: unchanged (h1 upstream response → `router_write_proxy_response`
  → virtual conn → §4.2 step 5).
- h2 streams multiplexed on one downstream connection each acquire an
  upstream connection synchronously per request (existing pool semantics —
  no change, upstream pool remains thread-local).

---

## 6. Reload & shutdown interactions

- SIGHUP: unchanged. SSL_CTX travels with the generation; existing
  connections (SSL objects) keep the old CTX until they close; new accepts
  use the adopted generation. `apex_proxy_pool_reset` unchanged.
- SIGQUIT drain: TLS conns finish in-flight; h2 conns additionally submit
  graceful GOAWAY and finish open streams before close. Idle TLS conns get
  FIN via normal close (SSL_shutdown before close_fd) — the FIN-not-RST
  guarantee extends to TLS.
- SIGINT/SIGTERM: immediate orderly stop (existing behavior).

---

## 7. Error handling rules (guide Rule 2)

Every OpenSSL and nghttp2 call checked; failures produce:
- transport-level: perror-style log + connection close (never silent).
- config-level: validation error with file:line (like existing directives).
- stream-level: RST_STREAM with correct error code + log.
No allocation failure paths unwind silently: `malloc` failure on stream
setup → RST + log; on session setup → close connection.

---

## 8. Build & tests

### Makefile
- `pkg-config --exists libssl libcrypto libnghttp2` → add
  `-lssl -lcrypto -lnghttp2` via `$(shell pkg-config --libs ...)`, matching
  cflags. Hard failure with a clear message if missing (not silent).
- `tests/test_cli.py` remains hermetic stdlib-only; new TLS/h2 tests in
  `tests/test_h2.py` run the same `make test` entry and **skip cleanly**
  when the host lacks a capable client.

### Test client strategy
stdlib Python has no h2 client. Tests use `curl --http2` (present on the
build host; suite skips if `curl` lacks http2 support) plus Python's
`ssl` module for ALPN probe assertions (`ALPN protocols` set). Cases:
1. `listen ssl` endpoint: TLS handshake ok; ALPN selects `h2`; plaintext
   HTTP/1.1 over same TLS conn (`--http1.1`) also works.
2. h2 GET → handler route; h2 GET → static file; h2 GET → proxy_pass
   (local http.server backend, h1.1 upstream).
3. h2 with request body (POST) → proxy; body content preserved.
4. ALPN no-overlap client → handshake alert, process stays alive.
5. Cert/key mismatch or missing files → `-t` exits 1 with clear message.
6. Reload rejects endpoint/ssl changes; keeps serving (same-PID check).
7. SIGQUIT drain over TLS: in-flight h2 stream completes; idle TLS conn
   closed with FIN (observed via Python ssl socket EOF).
8. ASan+UBSan run of the full suite.

### Milestones (each lands green + tested on Linux)
- **2a** TLS+ALPN plumbing, h1-over-TLS, config/ssl directives, reload
  rejection, tests 1/4/5/6/7(h1-only)/8.
- **2b** nghttp2 sessions, bridge, handler+static routes, tests 1/2/8.
- **2c** proxy translation + POST bodies + GOAWAY drain, tests 3/7/8.
