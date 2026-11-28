#!/usr/bin/env bash
set -euo pipefail

# Script to build Debian .deb package for Apex
VERSION="${1:-1.5.0}"
ARCH="amd64"
PKG_NAME="apex_${VERSION}_${ARCH}"
BUILD_DIR="$(mktemp -d -t apex-deb-XXXXXX)"

echo "==> Building Apex binary..."
make clean
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

echo "==> Preparing Debian package directory structure..."
INSTALL_ROOT="${BUILD_DIR}/${PKG_NAME}"
mkdir -p "${INSTALL_ROOT}/DEBIAN"
mkdir -p "${INSTALL_ROOT}/usr/bin"
mkdir -p "${INSTALL_ROOT}/etc/apex/conf.d"
mkdir -p "${INSTALL_ROOT}/etc/logrotate.d"
mkdir -p "${INSTALL_ROOT}/lib/systemd/system"
mkdir -p "${INSTALL_ROOT}/var/log/apex"
mkdir -p "${INSTALL_ROOT}/var/cache/apex"
mkdir -p "${INSTALL_ROOT}/var/www/static"

cp apex "${INSTALL_ROOT}/usr/bin/apex"
chmod 755 "${INSTALL_ROOT}/usr/bin/apex"

cp conf/apex.conf "${INSTALL_ROOT}/etc/apex/apex.conf"
chmod 644 "${INSTALL_ROOT}/etc/apex/apex.conf"

cp conf/conf.d/example.conf "${INSTALL_ROOT}/etc/apex/conf.d/example.conf"
chmod 644 "${INSTALL_ROOT}/etc/apex/conf.d/example.conf"

cp conf/apex.service "${INSTALL_ROOT}/lib/systemd/system/apex.service"
chmod 644 "${INSTALL_ROOT}/lib/systemd/system/apex.service"

cp conf/apex.logrotate "${INSTALL_ROOT}/etc/logrotate.d/apex"
chmod 644 "${INSTALL_ROOT}/etc/logrotate.d/apex"

cat <<EOF > "${INSTALL_ROOT}/DEBIAN/control"
Package: apex
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Apex Proxy Team <apex@cu3rd.ru>
Depends: libc6, libssl3t64 | libssl3, libnghttp2-14, libbrotli1 | libbrotlienc1, libzstd1, zlib1g, libluajit-5.1-2, libwasmedge0, libngtcp2-16, libngtcp2-crypto-ossl0, libnghttp3-9, liburing2 | liburing1 | libc6
Description: Apex ultra-high-performance HTTP reverse proxy and edge router
 Apex is an ultra-low latency, concurrent reverse proxy, load balancer,
 and edge router written in C23 with native io_uring / epoll event engines,
 HTTP/1.1, HTTP/2, HTTP/3 (QUIC), gRPC, automated ACME/TLS renewal,
 LuaJIT 2.1 scripting, WasmEdge WebAssembly filters, and dynamic WAF.
EOF

cat <<'EOF' > "${INSTALL_ROOT}/DEBIAN/postinst"
#!/bin/sh
set -e
if ! getent group apex >/dev/null 2>&1; then
    addgroup --system apex
fi
if ! getent passwd apex >/dev/null 2>&1; then
    adduser --system --ingroup apex --no-create-home --home /nonexistent --shell /usr/sbin/nologin apex
fi

mkdir -p /var/log/apex /var/cache/apex /var/www/static /etc/apex/conf.d
chown -R apex:apex /var/log/apex /var/cache/apex
chmod 750 /var/log/apex /var/cache/apex

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "${INSTALL_ROOT}/DEBIAN/postinst"

cat <<'EOF' > "${INSTALL_ROOT}/DEBIAN/prerm"
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl stop apex.service >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "${INSTALL_ROOT}/DEBIAN/prerm"

cat <<'EOF' > "${INSTALL_ROOT}/DEBIAN/postrm"
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
    rm -rf /var/log/apex /var/cache/apex
fi
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "${INSTALL_ROOT}/DEBIAN/postrm"

echo "==> Packaging deb..."
dpkg-deb --build --root-owner-group "${INSTALL_ROOT}" "${PKG_NAME}.deb"

echo "==> Cleaning up..."
rm -rf "${BUILD_DIR}"

echo "==> Done: ${PKG_NAME}.deb generated successfully."
