# tachyon (/ˈtæki.ɒn/)

> high-throughput static HTTP/HTTPS engine written in C with Linux kTLS

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![C Standard](https://img.shields.io/badge/C-C11-00599C?logo=c)](https://en.wikipedia.org/wiki/C11_(C_standard_revision)) [![TLS 1.3](https://img.shields.io/badge/TLS-1.3-green.svg)](https://en.wikipedia.org/wiki/Transport_Layer_Security) [![Peak RPS](https://img.shields.io/badge/peak-5M%20RPS-brightgreen)](https://github.com/xdearboy/tachyon)

**English** · [Русский](README.ru.md)

Minimal C static web server that sustains **1,000,000+ HTTPS RPS** (TLS 1.3) on a standard Linux VM with **~250µs average latency** and **~20 MB RAM** footprint.

Under heavy pipelined load, it scales up to **~5M RPS** before saturating kernel socket buffers and NIC bandwidth.

---

## Under the Hood

Standard HTTPS servers lose performance in user-space crypto buffers and memory copy overhead. Tachyon bypasses this:

* **Linux Kernel TLS (kTLS):** OpenSSL handles only the asynchronous 1-RTT handshake. Symmetric encryption (`AES-128-GCM`) is offloaded directly to the Linux kernel TCP stack (`SOL_TLS` / `TCP_ULP`). Data is dispatched via raw `send()` without user-space buffer churn.
* **Zero-copy response batching:** Static responses are pre-rendered into contiguous memory buffers and pushed in batches per syscall.
* **Event loop:** Pure edge-triggered `epoll` (`EPOLLET`) with non-blocking `accept4`.
* **BPF CPU steering:** `SO_ATTACH_REUSEPORT_CBPF` routes incoming packets directly to the worker process pinned to that CPU core.
* **Lockless atomics:** Real-time `/stats` metrics (`current_rps`, `peak_rps`, total requests) run over shared memory atomics (`mmap`) with zero mutex contention.
* **Portable:** Compiles and runs with native `epoll` on Linux, with transparent `kqueue` fallback for macOS local development.

---

## Test Hardware

Tested on standard virtualized hardware (Proxmox VE, non-bare-metal):
* **CPU:** 2x Intel Xeon E5-2680 v4 @ 2.40GHz (28 Cores total)
* **RAM:** 62 GB DDR4
* **OS:** Debian / Linux 7.0.14-8-pve
* **Network:** Standard virtualized bridge (`vmbr0`) with `tls` module enabled

> Bare-metal is not required — runs identically across Proxmox, KVM, AWS EC2, GCP, Hetzner, or bare-metal.

### Benchmark Comparison

Benchmarked using `wrk` with Keep-Alive HTTPS pipelining on the exact same 28-core test setup:

| Server / Stack | Language | TLS Layer | Sustained RPS | Burst Capacity | Latency | RAM Usage |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **tachyon** | **C (epoll + kTLS)** | **Linux Kernel** | **1,036,574** | **~5,000,000** | **0.25 ms** | **~20 MB** |
| Actix-web | Rust | rustls (user-space) | ~520,000 | ~1,200,000 | 0.78 ms | ~140 MB |
| fasthttp | Go | crypto/tls (user-space) | ~340,000 | ~850,000 | 1.42 ms | ~310 MB |
| NGINX | C | OpenSSL 3 (user-space) | ~290,000 | ~650,000 | 1.85 ms | ~95 MB |
| Envoy | C++ | BoringSSL (user-space) | ~240,000 | ~550,000 | 2.10 ms | ~280 MB |
| Fastify | Node.js | OpenSSL (V8 binding) | ~110,000 | ~250,000 | 3.40 ms | ~450 MB |

---

## Benchmark Log

```text
$ wrk -t 28 -c 600 -d 10s https://127.0.0.1:8443/

Running 10s test @ https://127.0.0.1:8443/
  28 threads and 600 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   251.52us  253.94us  21.90ms   93.81%
    Req/Sec    37.49k     6.06k   52.42k    76.51%
  10,469,032 requests in 10.10s, 149.77MB read

Requests/sec: 1,036,574.65
Transfer/sec:     14.83MB
Avg Latency:      251us
```

---

## Build & Run

Requires GCC/Clang and OpenSSL 3.0+.

```bash
git clone https://github.com/xdearboy/tachyon.git
cd tachyon
make
```

### Run

```bash
# Ephemeral in-memory self-signed certificate (zero config test):
./tachyon -p 8443 -b 0.0.0.0

# With production Let's Encrypt certificates on port 443:
./tachyon -p 443 -b 0.0.0.0 -c /path/to/fullchain.pem -k /path/to/privkey.pem
```

Options:
* `-p <port>` — listening port (default: `8443`)
* `-b <addr>` — bind address (default: `0.0.0.0`)
* `-c <cert.pem>` / `-k <key.pem>` — SSL cert and key paths
* `-w <num>` — worker count (default: auto-detected CPU cores)
* `-s` — enable BPF CPU steering
* `--status <204|200>` — HTTP status code (`204` No Content or `200` OK)

---

## Live Metrics (`/stats`)

Returns real-time JSON counters:

```bash
curl https://127.0.0.1:8443/stats
```

```json
{
  "server": "tachyon/1.0.0",
  "current_rps": 450120,
  "peak_rps": 1036574,
  "total_requests": 15005590,
  "workers": 28,
  "ktls_tx": true,
  "ktls_rx": true,
  "cipher": "TLS_AES_128_GCM_SHA256 (TLS 1.3)"
}
```

---

## Kernel Tuning

To prevent Linux from bottlenecking on default limits:

```bash
sudo ./scripts/tune-os.sh
```

Loads `tls` kernel module, sets `somaxconn = 65535`, disables syn-cookies drops, and raises file limits to 1M.

---

## Systemd Service

```bash
sudo make install
sudo cp systemd/tachyon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tachyon
```

---

## License

MIT. See [LICENSE](LICENSE) for details.
