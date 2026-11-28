---
name: apex-proxy
description: Configure, operate, and benchmark Apex reverse proxy.
version: 1.5.0
author: xdearboy, Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [reverse-proxy, io-uring, web-server, performance, nginx-alternative, linux]
---

# Apex Reverse Proxy & Edge Router

Apex is an ultra-high-performance reverse proxy and edge router written in C23 with native `io_uring` and `epoll` event loops, HTTP/1.1, HTTP/2, HTTP/3 (QUIC), gRPC, LuaJIT 2.1 scripting, WasmEdge WebAssembly filters, and dynamic Coraza WAF.

## When to Use

Use this skill when you need to:
- Install or deploy Apex on Linux servers (Debian, Ubuntu, Fedora, RHEL, Rocky, Arch, Alpine).
- Author, validate, or reload Apex configurations (`apex.conf` and `conf.d/*.conf`).
- Configure reverse proxy routes, upstream pools (P2C, round-robin), TLS 1.3 / ACME, HTTP/3, and caching.
- Write or attach LuaJIT hooks or WasmEdge filters.
- Troubleshoot, inspect runtime logs, or benchmark Apex throughput and latency.

---

## Quick Reference

### Installation
```bash
# Universal 1-line installation (Debian, Ubuntu, Fedora, RHEL, Rocky, Arch, Alpine)
curl -fsSL https://raw.githubusercontent.com/xdearboy/apex/main/scripts/install.sh | sudo bash
```

### Essential CLI Commands
```bash
apex -t                       # Validate default configuration (/etc/apex/apex.conf)
apex -t -c /path/to/test.conf # Validate specific configuration file
apex -c /etc/apex/apex.conf   # Run in foreground
apex -v                       # Print version and compiled engine features
```

### Systemd Management
```bash
systemctl start apex          # Start service
systemctl stop apex           # Graceful stop (drains connections)
systemctl reload apex         # Zero-downtime hot reload via SIGHUP
systemctl status apex         # Inspect status & active worker threads
journalctl -u apex -f         # Live journal logs
```

---

## File System Layout & Standard Paths

| Component | Path | Description |
|---|---|---|
| **Binary** | `/usr/bin/apex` (or `/usr/local/bin/apex`) | Standalone C23 runtime executable |
| **Main Config** | `/etc/apex/apex.conf` | Core daemon, buffer, event, and default HTTP directives |
| **Modular VHosts**| `/etc/apex/conf.d/*.conf` | Included virtual host and upstream configs |
| **Example Host** | `/etc/apex/conf.d/example.conf` | Reference template for new services |
| **Logs** | `/var/log/apex/access.log`, `/var/log/apex/error.log` | Access & error logs (owned by `apex:apex`) |
| **Proxy Cache** | `/var/cache/apex/` | Disk cache zones |
| **Static Root** | `/var/www/static/` | Default document root for static assets |
| **Logrotate** | `/etc/logrotate.d/apex` | Daily rotation with zero-downtime USR1 re-opening |
| **Systemd Unit** | `/lib/systemd/system/apex.service` | Hardened service unit with `ExecStartPre` validation |

---

## Configuration Patterns

### 1. Basic Reverse Proxy Virtual Host (`/etc/apex/conf.d/app.conf`)
```nginx
upstream api_backend {
    policy p2c; # Power-of-Two-Choices latency-aware balancing
    server 127.0.0.1:9001 weight=2 max_conns=1024;
    server 127.0.0.1:9002 weight=1 max_conns=1024;
    keepalive 128;
    connect_timeout 2s;
    read_timeout 10s;
}

server {
    listen ":8080";
    server_name api.example.com;

    location "/api/" {
        proxy_pass api_backend;
        proxy_set_header "Host" "$host";
        proxy_set_header "X-Real-IP" "$remote_addr";
        proxy_set_header "X-Forwarded-For" "$proxy_add_x_forwarded_for";
        proxy_set_header "X-Forwarded-Proto" "$scheme";
        proxy_http_version 1.1;

        # Rate limiting (defined in apex.conf)
        limit_req zone=req_limit burst=50 nodelay;
    }

    location "=" "/health" {
        access_log off;
        return 200 "OK\n";
    }
}
```

### 2. HTTPS with Automatic ACME TLS (Let's Encrypt)
```nginx
server {
    listen ":8443" tls;
    server_name example.com;

    acme on;
    acme_email "admin@example.com";
    acme_provider "letsencrypt";

    location "/" {
        proxy_pass "127.0.0.1:3000";
    }
}
```

### 3. Static Assets with Memory/Disk Caching
```nginx
server {
    listen ":8080";
    server_name cdn.example.com;

    location "/static/" {
        root "/var/www/static";
        proxy_cache apex_cache;
        proxy_cache_valid 200 1h;
        proxy_cache_valid 404 1m;
        add_header "Cache-Control" "public, max-age=3600";
    }
}
```

### 4. LuaJIT 2.1 Request Hook
```nginx
location "/secure/" {
    access_by_lua '
        local auth = apex.req.get_headers()["authorization"]
        if not auth or auth ~= "Bearer secret" then
            apex.exit(403, "Forbidden")
        end
    ';
    proxy_pass "127.0.0.1:8000";
}
```

---

## Operating Guidelines for AI Agents

1. **Always Validate Before Reloading**:
   Before running `systemctl reload apex`, ALWAYS run `apex -t` or `apex -t -c /path/to/file`. Apex will reject syntax and semantic errors upfront without risking downtime.
2. **Never Drop Sockets on Reload**:
   `SIGHUP` creates a new generation of routes and upstreams in-memory. In-flight connections complete gracefully without dropping keep-alive sockets.
3. **High Concurrency Tuning**:
   Verify Linux kernel limits:
   ```bash
   sysctl -w net.core.somaxconn=65535
   sysctl -w fs.file-max=2097152
   ulimit -n 1048576
   ```
4. **io_uring Runtime Verification**:
   Apex automatically tries `io_uring_queue_init()`. If unprivileged in Docker containers or on older kernels, it gracefully falls back to `epoll`. Check the worker status in journal logs:
   ```bash
   journalctl -u apex -n 50 | grep -i "worker"
   ```
