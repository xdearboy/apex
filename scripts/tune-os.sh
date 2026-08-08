#!/usr/bin/env bash
# ==============================================================================
# tachyon OS & Network Kernel Tuning Script
# Optimizes Linux TCP/IP stack, file limits, and kTLS offload for >1M RPS
# ==============================================================================

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root." >&2
   exit 1
fi

echo "==> Loading Linux Kernel TLS (kTLS) module..."
modprobe tls || true
echo "tls" > /etc/modules-load.d/tls.conf

echo "==> Applying sysctl network stack tuning..."
cat << 'EOF' > /etc/sysctl.d/99-tachyon.conf
# File & Socket Limits
fs.file-max = 2097152
fs.nr_open = 2097152

# TCP Sockets & Listen Queue
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_syncookies = 0

# Ephemeral Port Range & Connection Recycling
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0

# Socket Buffers (Optimized for high-throughput small packets)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# TCP FastOpen
net.ipv4.tcp_fastopen = 3
EOF

sysctl --system

echo "==> Setting security limits (/etc/security/limits.d/99-tachyon.conf)..."
cat << 'EOF' > /etc/security/limits.d/99-tachyon.conf
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
tachyon soft nofile 1048576
tachyon hard nofile 1048576
www-data soft nofile 1048576
www-data hard nofile 1048576
EOF

echo "==> Successfully tuned Linux kernel for tachyon!"
