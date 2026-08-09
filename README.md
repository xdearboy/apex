# tachyon

> **English** · [Русский](README.ru.md)

Ultra high-throughput static HTTP/HTTPS engine written in C with Linux kTLS.

Sustains **1,000,000+ HTTPS RPS** (TLS 1.3) on a standard 28-core Linux server with **~250µs latency** and minimal RAM usage. Under pipelined bursts it can push up to ~5M RPS before saturating kernel socket buffers.

---

### Why it's fast

Standard HTTPS servers spend most CPU cycles copying data between user-space buffers and OpenSSL crypto contexts. Tachyon avoids this:

1. **Linux Kernel TLS (kTLS):** OpenSSL handles only the TLS 1.3 handshake. Symmetric encryption (`AES-128-GCM`) is offloaded to the Linux kernel (`SOL_TLS` / `TCP_ULP`). Data is encrypted in kernel space via AES-NI without user-space buffer copying.
2. **Zero-Copy Batching:** Static responses are pre-rendered into contiguous memory buffers and pushed in batches.
3. **BPF CPU Steering:** `SO_ATTACH_REUSEPORT_CBPF` packet filter routes TCP connections directly to the worker running on that CPU core.
4. **Lockless Metrics:** Shared-memory atomics (`mmap`) track total requests and peak RPS without mutex contention.

---

### Benchmark

Tested on a 2x Intel Xeon E5-2680 v4 (28 cores, Debian Linux 7.0 Proxmox kernel):

```text
$ wrk -t 28 -c 600 -d 10s https://127.0.0.1:443/

Running 10s test @ https://127.0.0.1:443/
  28 threads and 600 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   251.62us  205.78us  10.74ms   95.16%
    Req/Sec    37.19k     5.51k   52.48k    71.49%
  10,365,042 requests in 10.10s, 148.28MB read
Requests/sec: 1,026,241.78
Transfer/sec:     14.68MB
```

---

### Building

Requires GCC or Clang and OpenSSL 3.0+:

```bash
git clone https://github.com/xdearboy/tachyon.git
cd tachyon
make
```

Generate local self-signed test certificates if needed:
```bash
make certs
```

---

### Usage

```bash
# Run with TOML configuration:
./tachyon -C tachyon.toml

# Or with CLI flags:
./tachyon -p 443 -b 0.0.0.0 -c /path/to/cert.pem -k /path/to/key.pem

# Serve static directory:
./tachyon -p 8443 -c cert.pem -k key.pem -d /var/www/html
```

#### CLI Options
* `-C, --config <file>` — path to TOML config file
* `-p <port>` — listening port (default: `8443`)
* `-b <addr>` — bind address (default: `0.0.0.0`)
* `-c <cert.pem>` / `-k <key.pem>` — SSL cert and key
* `-d, --root <dir>` — serve static directory (HTML, CSS, JS, etc.)
* `-w <num>` — number of workers (default: CPU cores)
* `-s` — enable BPF CPU affinity steering
* `--status <204|200>` — HTTP response code (default: `204`)
* `--stats` / `--no-stats` — enable/disable `/stats` endpoint
* `--stats-path <path>` — custom stats path (default: `/stats`)

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

### Kernel Tuning

For maximum throughput under heavy load:

```bash
sudo ./scripts/tune-os.sh
```

### License

MIT
