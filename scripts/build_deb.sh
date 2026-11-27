#!/usr/bin/env bash
set -euo pipefail

# Script to build Debian .deb package for Apex
VERSION="${1:-1.4.0}"
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
mkdir -p "${INSTALL_ROOT}/etc/apex"
mkdir -p "${INSTALL_ROOT}/lib/systemd/system"
mkdir -p "${INSTALL_ROOT}/var/log/apex"

cp apex "${INSTALL_ROOT}/usr/bin/apex"
chmod 755 "${INSTALL_ROOT}/usr/bin/apex"

cp conf/apex.conf "${INSTALL_ROOT}/etc/apex/apex.conf"
chmod 644 "${INSTALL_ROOT}/etc/apex/apex.conf"

cp conf/apex.service "${INSTALL_ROOT}/lib/systemd/system/apex.service"
chmod 644 "${INSTALL_ROOT}/lib/systemd/system/apex.service"

cat <<EOF > "${INSTALL_ROOT}/DEBIAN/control"
Package: apex
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Apex Proxy Team <apex@example.com>
Depends: libc6, libssl3, libnghttp2-14, libbrotlienc1, libzstd1, zlib1g, libluajit-5.1-2, libwasmedge0, libngtcp2-16, libngtcp2-crypto-ossl0, libnghttp3-9
Description: Apex high-performance HTTP reverse proxy and edge router
 Apex is an ultra-low latency, concurrent reverse proxy, load balancer,
 and edge router written in C23 with native HTTP/1.1, HTTP/2, HTTP/3 (QUIC),
 gRPC bidirectional streaming, automated ACME/TLS renewal, LuaJIT 2.1 scripting,
 WasmEdge WebAssembly filters, and dynamic WAF capabilities.
EOF

cat <<EOF > "${INSTALL_ROOT}/DEBIAN/postinst"
#!/bin/sh
set -e
if ! getent group apex >/dev/null 2>&1; then
    addgroup --system apex
fi
if ! getent passwd apex >/dev/null 2>&1; then
    adduser --system --ingroup apex --no-create-home --home /nonexistent --shell /usr/sbin/nologin apex
fi
mkdir -p /var/log/apex
chown -R apex:apex /var/log/apex
chmod 750 /var/log/apex

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "${INSTALL_ROOT}/DEBIAN/postinst"

cat <<EOF > "${INSTALL_ROOT}/DEBIAN/prerm"
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl stop apex.service >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "${INSTALL_ROOT}/DEBIAN/prerm"

cat <<EOF > "${INSTALL_ROOT}/DEBIAN/postrm"
#!/bin/sh
set -e
if [ "\$1" = "purge" ]; then
    rm -rf /var/log/apex
fi
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "${INSTALL_ROOT}/DEBIAN/postrm"

echo "==> Building .deb package..."
dpkg-deb --build --root-owner-group "${INSTALL_ROOT}" "${PKG_NAME}.deb"

echo "==> Successfully built ${PKG_NAME}.deb"
dpkg -c "${PKG_NAME}.deb"

rm -rf "${BUILD_DIR}"
