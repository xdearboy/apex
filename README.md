<div align="center">

# tachyon

**Static HTTP/HTTPS engine in C, built around Linux kernel TLS.**

[![ci](https://github.com/xdearboy/tachyon/actions/workflows/ci.yml/badge.svg)](https://github.com/xdearboy/tachyon/actions/workflows/ci.yml)
![C11](https://img.shields.io/badge/C-11-00599C)
![Linux](https://img.shields.io/badge/platform-Linux-333)
![TLS 1.3](https://img.shields.io/badge/TLS-1.3%20kTLS-3b7)
![license](https://img.shields.io/badge/license-MIT-blue)

English · [Русский](README.ru.md)

</div>

---

Sustains **1,000,000+ HTTPS requests/sec** (TLS 1.3) on a 28-core box at around **250µs** latency, with the symmetric crypto running inside the kernel instead of user space. Under pipelined load it pushes several million RPS before the kernel socket buffers saturate.

---

### Why it's fast

A normal HTTPS server burns most of its CPU shuffling bytes between user-space buffers and the TLS library. tachyon skips that work:

* **Kernel TLS.** OpenSSL only does the TLS 1.3 handshake. Once keys are set, `AES-128-GCM` is handed to the kernel (`TCP_ULP` / `SOL_TLS`) and encrypted with AES-NI, so response data never gets copied through user space.
* **Pre-rendered batches.** Static responses are built once into contiguous buffers and written back to back.
* **BPF CPU steering.** A `SO_ATTACH_REUSEPORT_CBPF` filter pins each connection to the worker already running on that core, so a request is handled where it landed.
* **Lock-free metrics.** Request counters live in shared memory (`mmap`) and move with plain atomics, no mutexes on the hot path.

Routes for a served directory are resolved through a hash index, so lookup cost does not grow with the number of files.

---

### Benchmark

2x Intel Xeon E5-2680 v4 (28 cores total), Linux 7.0 (Proxmox kernel), OpenSSL 3.5, loopback.

| Mode | Requests/sec | Latency (avg) |
| --- | ---: | ---: |
| Single request | **1,026,241** | 251µs |
| Pipelined, depth 8 | 5,892,826 | — |
| Pipelined, depth 16 | 11,451,411 | — |

Numbers drift with the host's turbo state and neighbours (it's a shared box), but single-request stays in the ~0.9-1.0M range. Pipelined figures use [`scripts/pipeline.lua`](scripts/pipeline.lua).

<details>
<summary>raw <code>wrk</code> output</summary>

```text
$ wrk -t28 -c600 -d10s https://127.0.0.1:8443/

Running 10s test @ https://127.0.0.1:8443/
  28 threads and 600 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   251.62us  205.78us  10.74ms   95.16%
    Req/Sec    37.19k     5.51k   52.48k    71.49%
  10,365,042 requests in 10.10s, 148.28MB read
Requests/sec: 1,026,241.78
Transfer/sec:     14.68MB
```

</details>

kTLS actually engaging is easy to verify at runtime:

```bash
$ curl -k -s https://127.0.0.1:8443/stats
{ "ktls_tx": true, "ktls_rx": true, "cipher": "TLS_AES_128_GCM_SHA256 (TLS 1.3)", ... }
```

---

### Building

Needs GCC or Clang and OpenSSL 3.0+:

```bash
git clone https://github.com/xdearboy/tachyon.git
cd tachyon
make          # build
make certs    # self-signed certs for local testing
make test     # unit tests
```

---

### Usage

```bash
# TOML config:
./tachyon -C tachyon.toml

# or plain flags:
./tachyon -p 443 -b 0.0.0.0 -c /path/to/cert.pem -k /path/to/key.pem

# serve a static directory:
./tachyon -p 8443 -c cert.pem -k key.pem -d /var/www/html
```

| Flag | Meaning |
| --- | --- |
| `-C, --config <file>` | TOML config file |
| `-p <port>` | listening port (default `8443`) |
| `-b <addr>` | bind address (default `0.0.0.0`) |
| `-c` / `-k` | TLS cert and key |
| `-d, --root <dir>` | serve static files from a directory |
| `-w <num>` | worker count (default: CPU cores) |
| `-s` | enable BPF CPU steering |
| `--status <204\|200>` | response code for the empty route (default `204`) |
| `--stats` / `--no-stats` | toggle the `/stats` endpoint |
| `--stats-path <path>` | custom stats path (default `/stats`) |

---

### Configuration (`tachyon.toml`)

```toml
[server]
port = 443
bind = "0.0.0.0"
# workers = 28
status = 204
# root = "/var/www/html"
cpu_steer = true

[tls]
cert = "/etc/letsencrypt/live/example.com/fullchain.pem"
key  = "/etc/letsencrypt/live/example.com/privkey.pem"

[stats]
enabled = true
path = "/stats"
```

---

### Kernel tuning

For maximum throughput under load:

```bash
sudo ./scripts/tune-os.sh
```

### License

MIT
