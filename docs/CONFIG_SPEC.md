# Apex Configuration Specification

Status: draft for Phase 1. Language version `apex/1`.

Apex uses one canonical, human-readable configuration language. It is compiled
into an immutable runtime model before any worker accepts traffic. The syntax is
deliberately small: every construct is explicit, every block has a known owner,
and route selection is deterministic from source order.

The specification covers only the open core: listeners, HTTP routing, named
upstream pools, transport security, and module declarations. Vendor-specific
extensions never change the tokenizer or the evaluation order.

---

## 1. Design principles

1. **One surface syntax.** Braces for blocks, semicolons for leaf directives,
   whitespace-insensitive layout, `#` comments.
2. **Explicit ownership.** `http`, `upstream`, `server`, `location`, `tls`, and
   `modules` are the only container types. A container never becomes a site or a
   backend by accident.
3. **No hidden ordering.** Locations and routes are evaluated in source order.
   There is no implicit sort by directive name and no modifier-based precedence.
4. **No implicit side effects.** TLS, certificate acquisition, and module
   loading happen only when the configuration says so.
5. **Validate, then publish.** The full file is parsed, resolved, validated, and
   frozen before it can serve a request. A failed reload keeps the previous
   generation.
6. **Resolved at build time.** Defaults, inheritance, name references, and
   environment values are resolved into concrete values. Request handling never
   performs a configuration lookup by string.

---

## 2. Lexical structure

- Input is UTF-8. Directive and identifier names are ASCII.
- Tokens are: `word`, `string`, `{`, `}`, `;`.
- `word` is a run of characters other than whitespace, `{`, `}`, `;`, `#`,
  `"`, or `'`.
- `string` is either `"..."` or `'...'`, may contain whitespace and brace
  characters, and may not contain a raw newline.
- Escapes valid inside a double-quoted string: `\"`, `\\`, `\n`, `\r`, `\t`,
  `\xNN`. A single-quoted string has no escapes.
- `#` starts a comment when it appears where a token may start. The comment ends
  at the next line break. A `#` inside a token or string is literal.
- Newlines are whitespace. A statement ends with `;` or with a block closing
  brace followed by `;` for directives that accept a block.
- Unquoted values may not contain `{`, `}`, `;`, or `#`.

Scalar value kinds are distinguished by the directive schema, not by the
tokenizer:

| Kind | Examples | Notes |
| :--- | :--- | :--- |
| `identifier` | `api`, `round_robin` | ASCII letters, digits, `_`, `-`, `.` |
| `integer` | `0`, `8080`, `65535` | decimal, unsigned unless the directive allows negative |
| `duration` | `250ms`, `2s`, `30s`, `5m`, `1h` | integer plus unit; no fractional values |
| `size` | `64k`, `1m`, `16m` | binary multiples: `k`=1024, `m`=1024², `g`=1024³ |
| `string` | `"/srv/www"` | quoted when it contains separators or whitespace |

### 2.1 Environment expansion

`${NAME}` and `${NAME:-default}` are expanded only inside an already delimited
scalar token. Expansion cannot create new tokens, comments, braces, semicolons,
or line breaks. An unset variable without a default is a validation error.
Expanded values are snapshotted into the candidate configuration generation.

---

## 3. Grammar

```ebnf
config          = item* EOF ;
item            = include | http_block | modules_block ;
include         = "include" scalar ";" ;

http_block      = "http" "{" http_item* "}" ;
http_item       = upstream | server | http_directive ;
http_directive  = identifier scalar* ";" ;

upstream        = "upstream" identifier "{" upstream_item* "}" ;
upstream_item   = upstream_server | upstream_policy | upstream_option ;
upstream_server = "server" scalar [ "weight" "=" integer ]
                  [ "max_conns" "=" integer ] ";" ;
upstream_policy = "policy" ( "round_robin" | "p2c" ) ";" ;
upstream_option = ( "keepalive" integer
                  | "connect_timeout" duration
                  | "read_timeout" duration
                  | "idle_timeout" duration ) ";" ;

server          = "server" "{" server_item* "}" ;
server_item     = listen | server_name | tls_block | location | server_directive ;
listen          = "listen" scalar [ "tls" ] ";" ;
server_name     = "server_name" scalar+ ";" ;
server_directive = identifier scalar* ";" ;

tls_block       = "tls" "{" tls_item* "}" ;
tls_item        = ( "certificate" scalar
                  | "private_key" scalar
                  | "protocols" scalar+
                  | "ciphers" scalar
                  | "client_auth" ( "off" | "optional" | "required" ) ) ";" ;

location        = "location" location_match "{" location_item* "}" ;
location_match  = "=" scalar | scalar ;
location_item   = proxy_pass | location_directive ;
proxy_pass      = "proxy_pass" ( identifier | scalar ) ";" ;
location_directive = identifier scalar* ";" ;

modules_block   = "modules" "{" module_item* "}" ;
module_item     = "load" scalar ";" | "enable" identifier ";" ;
```

Every leaf directive ends with `;`. Every block is closed with `}`; a block
directive is followed by `;` only if its schema declares one (none of the core
blocks do).

---

## 4. Object model and scoping

| Object | Owner | Purpose |
| :--- | :--- | :--- |
| `config` | file | Root of one immutable generation. |
| `http` | `config` | Process-wide HTTP defaults and the parent of servers. |
| `upstream` | `http` | Named backend pool and its balancing policy. |
| `server` | `http` | A listener plus its virtual hosts and locations. |
| `tls` | `server` | Transport security policy for that server. |
| `location` | `server` | A request matcher and its action chain. |
| `modules` | `config` | Optional statically linked modules. |

Rules:

- Names are unique within their owner. Two `upstream api` blocks in one `http`
  block are a duplicate error.
- `server` blocks do not inherit from each other.
- A `location` inherits resolved defaults from its `server`. It does not merge
  collections: if a location declares its own header set, that set replaces the
  inherited set.
- `proxy_pass` references either a named upstream or a single endpoint written
  as a scalar. A scalar endpoint is `host:port` only; it may not contain a path,
  query, or fragment. Path changes use a separate rewrite action.
- All references are resolved into indexes during compilation. An unresolved
  upstream name is a hard error.

---

## 5. `http` block

The `http` block holds defaults for every server and every upstream.

```apex
http {
    keepalive_timeout 75s;
    client_header_timeout 15s;
    client_body_timeout 30s;
    server_tokens off;

    upstream api { ... }
    server { ... }
}
```

Recognized `http` directives (Phase 1):

| Directive | Type | Default | Meaning |
| :--- | :--- | :--- | :--- |
| `keepalive_timeout` | duration | `75s` | Idle downstream keep-alive lifetime. |
| `client_header_timeout` | duration | `15s` | Time allowed to receive request headers. |
| `client_body_timeout` | duration | `30s` | Time allowed between body reads. |
| `server_tokens` | `on`/`off` | `off` | Emit the full server identification header. |

Unknown directives are errors, not warnings.

---

## 6. `upstream` block

An upstream is the sole owner of a backend pool, its balancing policy, its
connection cache, and its counters.

```apex
upstream api {
    server 10.0.0.11:9000 weight=2;
    server 10.0.0.12:9000;
    server 10.0.0.13:9000 max_conns=512;

    policy p2c;
    keepalive 64;
    connect_timeout 2s;
    read_timeout 10s;
    idle_timeout 60s;
}
```

| Item | Type | Default | Meaning |
| :--- | :--- | :--- | :--- |
| `server <host:port>` | endpoint | required | Backend address. IPv6 uses `[addr]:port`. |
| `weight` | integer | `1` | Relative share for `round_robin`. Range 1..1000000. |
| `max_conns` | integer | `0` | Per-endpoint concurrency ceiling; `0` means unlimited. |
| `policy` | enum | `round_robin` | `round_robin` or `p2c`. |
| `keepalive` | integer | `32` | Maximum idle upstream connections cached per worker. |
| `connect_timeout` | duration | `2s` | TCP connect budget. |
| `read_timeout` | duration | `10s` | Per-read budget on the upstream socket. |
| `idle_timeout` | duration | `60s` | Maximum age of a cached idle connection. |

### 6.1 Balancing

- `round_robin` is weighted round-robin. The selection cursor is a per-pool
  atomic counter; total weight is derived from the endpoint list.
- `p2c` samples two distinct endpoints uniformly and selects the one with the
  lower weighted load, where load = `(active_conns + 1) / weight`. The random
  source is thread-local, so a selection has no shared mutable state beyond the
  endpoint counters.
- `active_conns` counts requests currently bound to an endpoint; idle cached
  connections do not count.
- Passive counters (`failed_requests`, `bytes_sent`, `bytes_received`) are
  telemetry in Phase 1. Active health probing is a later module.

### 6.2 Upstream connection reuse

Each worker owns a thread-local cache of idle keep-alive sockets. A cached socket
is reused only when all of these hold:

1. It belongs to the selected endpoint (same family, address, and port).
2. It is younger than `idle_timeout`.
3. A non-blocking peek reports no readable data and no peer close.

A response is returned to the cache only when its framing is complete, no bytes
remain unread, the upstream did not request `Connection: close`, and the request
allowed keep-alive. Otherwise the socket is closed. There is no cross-worker
socket handoff.

### 6.3 Request framing

The proxy sends HTTP/1.1. If the caller supplies no `Host`, Apex derives one from
the endpoint. If the caller supplies no `Connection`, Apex sends
`Connection: keep-alive` when reuse is allowed and `Connection: close`
otherwise. If a body is present and no `Content-Length` was supplied, Apex adds
one. Header names are matched case-insensitively. A header block that contains
both `Transfer-Encoding: chunked` and `Content-Length` is rejected and the
connection is closed.

Responses may use `Content-Length`, chunked transfer coding, or
connection-close framing. Informational `1xx` responses are skipped until a
final response arrives; `101` is returned as final with no body and the socket
is closed.

---

## 7. `server` block

```apex
server {
    listen ":443" tls;
    server_name example.com www.example.com;

    tls {
        certificate "/etc/apex/example.pem";
        private_key "/etc/apex/example.key";
        protocols TLSv1.2 TLSv1.3;
    }

    location "/api/" {
        proxy_pass api;
    }

    location "=" "/health" {
        proxy_pass api;
    }
}
```

| Directive | Type | Default | Meaning |
| :--- | :--- | :--- | :--- |
| `listen` | address | required | `":port"`, `"host:port"`, or `"[v6]:port"`. |
| `listen ... tls` | flag | `off` | Require the `tls` block for this listener. |
| `server_name` | name list | none | Host names served by this block. |

A server with `listen ... tls` must contain a `tls` block with both
`certificate` and `private_key`. A certificate file that cannot be opened is a
validation error. Certificate acquisition and renewal are not part of the core
language; they belong to an optional module.

Host selection is exact and case-insensitive. A server whose `server_name`
matches the request `Host` wins. If no name matches, the first server for the
listener is the default. A server with no `server_name` is a default server only.

---

## 8. `tls` block

```apex
tls {
    certificate "/etc/apex/example.pem";
    private_key "/etc/apex/example.key";
    protocols TLSv1.2 TLSv1.3;
    ciphers "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
    client_auth off;
}
```

| Directive | Type | Default | Meaning |
| :--- | :--- | :--- | :--- |
| `certificate` | path | required | PEM certificate chain. |
| `private_key` | path | required | PEM private key. |
| `protocols` | list | `TLSv1.2 TLSv1.3` | Allowed protocol versions. |
| `ciphers` | string | implementation default | TLS 1.2 cipher list. TLS 1.3 suites are configured separately by the runtime. |
| `client_auth` | enum | `off` | `off`, `optional`, or `required`. |

The `tls` block is server-scoped. Upstream transport security is a separate
upstream option and is never inferred from the port number.

---

## 9. `location` and `proxy_pass`

```apex
location "/" {
    proxy_pass api;
    proxy_set_header "X-Forwarded-Proto" "https";
    proxy_connect_timeout 2s;
}

location "=" "/health" {
    proxy_pass "127.0.0.1:9001";
}
```

Matching rules:

- `location "=" <path>` is an exact match. If it matches, selection stops.
- `location <path>` is a prefix match. The longest matching prefix wins.
- If two locations have the same length, the earlier one in source order wins.
- There is no regex matching in language version `apex/1`. The `~` and `@`
  prefixes are reserved and rejected.
- A location with an empty or non-rooted path is a validation error.

Location directives (Phase 1):

| Directive | Type | Default | Meaning |
| :--- | :--- | :---: | :--- |
| `proxy_pass` | upstream or endpoint | required | Terminal proxy action. |
| `proxy_set_header` | name, value | none | Adds or replaces one request header. |
| `proxy_connect_timeout` | duration | upstream value | Per-location override. |
| `proxy_read_timeout` | duration | upstream value | Per-location override. |
| `proxy_http_version` | `1.0`/`1.1` | `1.1` | Upstream request version. |

A location contains exactly one terminal action. Declaring both `proxy_pass` and
a static file action, or declaring `proxy_pass` twice, is an error.

---

## 10. `modules` block

Modules are optional, statically linked capabilities. The core tokenizer and the
core ordering rules are not extensible.

```apex
modules {
    load "edge_ratelimit";
    load "access_log";
}
```

A module name is resolved from the link-time registry. An unknown name is a hard
error. A module declares the phases it observes and the directives it owns; the
registry rejects a module directive in a scope the module did not declare.

Reserved core phases:

`pre_routing`, `tls_handshake`, `header_filter`, `access_control`,
`content_proxy`, `response_filter`, `logging`.

Module directives must not consume tokens across their own block boundary, must
not change the tokenizer, and must return diagnostics with the same source
provenance as core directives.

---

## 11. Includes and expansion

```apex
include "conf.d/proxy.conf";
```

- `include` performs literal textual inclusion in the current scope.
- A relative path is resolved against the including file.
- Paths are canonicalized. Cycles, missing files, and files larger than the
  configured limit are errors.
- `include` is allowed at file scope and inside `http`, `upstream`, `server`,
  `tls`, `location`, and `modules`. Including a block in a scope where that
  block is illegal is a validation error.
- Glob patterns are deliberately out of scope for `apex/1`.

---

## 12. Validation and diagnostics

Compilation is a single pipeline:

1. Read the root file and includes with bounded sizes.
2. Tokenize once; every token carries file, line, column, and byte span.
3. Parse forward into a candidate arena. Recover at `;` or a balanced `}`.
4. Resolve names, defaults, environment values, and include paths.
5. Validate types, ranges, duplicate names, illegal scopes, and cross-object
   invariants.
6. Freeze the result into one immutable generation.
7. Publish the generation at an event-loop boundary.

A diagnostic contains: severity, stable code, file, line, column, byte span,
include chain, enclosing object, actual token, expected form, and one hint.
Human-readable and machine-readable renderings come from the same structure.

`apex config check` performs steps 1-5 without publishing. `apex config dump`
prints the canonical resolved form with secret-bearing fields redacted.

Unknown directives, unknown modules, unresolved references, duplicate
listeners, ambiguous routes, and unsupported option values are errors, never
warnings. Warnings are reserved for deprecated but deterministic syntax.

---

## 13. Reload model

- A reload builds a complete candidate generation while the active generation
  keeps serving.
- Listener sockets, log files, and TLS contexts are prepared transactionally.
  If any preparation step fails, the candidate is discarded and the active
  generation is unchanged.
- Publication swaps one generation pointer per worker at an event-loop boundary.
  Requests keep the generation they started with.
- Runtime state that must survive a reload (upstream health identity, listener
  handles) is referenced by stable identity, never embedded in the syntax tree.
- Long-lived streams keep their generation until they close or reach their
  configured maximum age. The process reports retained generations so a reload
  cannot silently pin memory.

---

## 14. Complete example

```apex
include "conf.d/upstreams.conf";

http {
    keepalive_timeout 75s;
    client_header_timeout 15s;

    upstream api {
        server 10.0.0.11:9000 weight=2;
        server 10.0.0.12:9000;
        server 10.0.0.13:9000 max_conns=512;

        policy p2c;
        keepalive 64;
        connect_timeout 2s;
        read_timeout 10s;
        idle_timeout 60s;
    }

    server {
        listen ":443" tls;
        server_name example.com;

        tls {
            certificate "/etc/apex/example.pem";
            private_key "/etc/apex/example.key";
            protocols TLSv1.3;
            client_auth off;
        }

        location "=" "/health" {
            proxy_pass "127.0.0.1:9001";
        }

        location "/api/" {
            proxy_pass api;
            proxy_set_header "X-Forwarded-Proto" "https";
        }
    }

    server {
        listen ":80";
        server_name example.com;

        location "/" {
            proxy_pass api;
        }
    }
}

modules {
    load "access_log";
}
```

---

## 15. Reserved words

The following words are reserved in `apex/1` and cannot be used as upstream
names or module identifiers:

`http`, `upstream`, `server`, `listen`, `server_name`, `location`, `tls`,
`modules`, `include`, `policy`, `weight`, `max_conns`, `keepalive`,
`connect_timeout`, `read_timeout`, `idle_timeout`, `certificate`,
`private_key`, `protocols`, `ciphers`, `client_auth`, `proxy_pass`,
`proxy_set_header`, `proxy_connect_timeout`, `proxy_read_timeout`,
`proxy_http_version`, `round_robin`, `p2c`, `on`, `off`, `optional`,
`required`.

A future language version may add words; a word not listed here remains a valid
identifier.
