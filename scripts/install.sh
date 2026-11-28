#!/usr/bin/env bash
set -euo pipefail

# Apex Universal One-Line Installer
# Supported: Debian, Ubuntu, CentOS, RHEL, Fedora, Rocky, Alma, Arch, Alpine

REPO="xdearboy/apex"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/apex"
LOG_DIR="/var/log/apex"
CACHE_DIR="/var/cache/apex"
SERVICE_DIR="/etc/systemd/system"

RED='[0;31m'
GREEN='[0;32m'
BLUE='[0;34m'
BOLD='[1m'
NC='[0m'

log_info() { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} ${BOLD}$1${NC}"; }
log_err() { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }

echo -e "${BOLD}"
echo "    _    ____  _______  __ "
echo "   / \  |  _ \| ____\ \/ / "
echo "  / _ \ | |_) |  _|  \  /  "
echo " / ___ \|  __/| |___ /  \  "
echo "/_/   \_\_|   |_____/_/\_\ "
echo "Apex Reverse Proxy & Edge Router Installer"
echo -e "${NC}"

# 1. Check Root
if [ "$(id -u)" -ne 0 ]; then
    log_err "Please run this installer as root (e.g. sudo bash install.sh)"
fi

# 2. Detect Architecture
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64) TARGET_ARCH="amd64" ;;
    aarch64|arm64) TARGET_ARCH="arm64" ;;
    *) log_err "Unsupported architecture: ${ARCH}. Apex supports x86_64 and arm64." ;;
esac

# 3. Detect Package Manager / OS
OS="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS="${ID}"
fi

log_info "Detected OS: ${OS} (${ARCH})"

# 4. Install Runtime Dependencies if available
log_info "Checking and installing runtime dependencies..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq || true
    apt-get install -y --no-install-recommends curl ca-certificates libssl3 libssl3t64 libnghttp2-14 libbrotli1 libbrotlienc1 libzstd1 zlib1g libluajit-5.1-2 liburing2 liburing1 >/dev/null 2>&1 || true
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl ca-certificates openssl-libs libnghttp2 libbrotli libzstd zlib luajit liburing >/dev/null 2>&1 || true
elif command -v yum >/dev/null 2>&1; then
    yum install -y curl ca-certificates openssl-libs libnghttp2 libbrotli libzstd zlib luajit liburing >/dev/null 2>&1 || true
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm curl ca-certificates openssl libnghttp2 brotli zstd zlib luajit liburing >/dev/null 2>&1 || true
elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl ca-certificates openssl libnghttp2 brotli-libs zstd-libs zlib luajit liburing >/dev/null 2>&1 || true
fi

# 5. Fetch Latest Release Version
log_info "Fetching latest release metadata from GitHub..."
LATEST_TAG=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || echo "")
if [ -z "${LATEST_TAG}" ]; then
    LATEST_TAG="v1.5.0"
fi
VERSION="${LATEST_TAG#v}"
log_info "Installing Apex ${LATEST_TAG}..."

# 6. Try installing via native package manager if .deb available
INSTALLED_VIA_PKG=false
if command -v dpkg >/dev/null 2>&1 && [ "${TARGET_ARCH}" = "amd64" ]; then
    DEB_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/apex_${VERSION}_${TARGET_ARCH}.deb"
    TMP_DEB="/tmp/apex_${VERSION}_${TARGET_ARCH}.deb"
    log_info "Attempting native .deb package installation..."
    if curl -sSL -f -o "${TMP_DEB}" "${DEB_URL}"; then
        dpkg -i "${TMP_DEB}" || apt-get install -f -y
        rm -f "${TMP_DEB}"
        INSTALLED_VIA_PKG=true
        log_success "Apex ${LATEST_TAG} installed successfully via dpkg!"
    fi
fi

# 7. Fallback: Direct Binary & Systemd Installation
if [ "${INSTALLED_VIA_PKG}" = false ]; then
    TAR_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/apex_${VERSION}_linux_${TARGET_ARCH}.tar.gz"
    TMP_DIR="$(mktemp -d)"
    log_info "Downloading standalone release bundle..."
    if curl -sSL -f -o "${TMP_DIR}/apex.tar.gz" "${TAR_URL}"; then
        tar -xzf "${TMP_DIR}/apex.tar.gz" -C "${TMP_DIR}"
        mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}/conf.d" "${LOG_DIR}" "${CACHE_DIR}"
        cp "${TMP_DIR}/apex" "${INSTALL_DIR}/apex"
        chmod 755 "${INSTALL_DIR}/apex"
        if [ ! -f "${CONFIG_DIR}/apex.conf" ]; then
            cp "${TMP_DIR}/conf/apex.conf" "${CONFIG_DIR}/apex.conf"
            chmod 644 "${CONFIG_DIR}/apex.conf"
        fi
        if [ -d "${TMP_DIR}/conf/conf.d" ]; then
            cp -n "${TMP_DIR}/conf/conf.d/"* "${CONFIG_DIR}/conf.d/" 2>/dev/null || true
        fi
        # Create user if needed
        if ! id apex >/dev/null 2>&1; then
            useradd -r -s /usr/sbin/nologin apex 2>/dev/null || true
        fi
        chown -R apex:apex "${LOG_DIR}" "${CACHE_DIR}" 2>/dev/null || true
        
        # Install systemd service if available
        if [ -d "/etc/systemd/system" ] && [ -f "${TMP_DIR}/conf/apex.service" ]; then
            cp "${TMP_DIR}/conf/apex.service" "/etc/systemd/system/apex.service"
            sed -i "s|/usr/bin/apex|${INSTALL_DIR}/apex|g" "/etc/systemd/system/apex.service"
            systemctl daemon-reload || true
        fi
        rm -rf "${TMP_DIR}"
        log_success "Apex binary installed to ${INSTALL_DIR}/apex"
    else
        log_err "Failed to download release bundle from ${TAR_URL}"
    fi
fi

# 8. Service Status and Instructions
echo ""
echo -e "${GREEN}${BOLD}Apex is ready! ${NC}"
echo ""
echo "Quick Commands:"
echo "  - Test config:       apex -t"
echo "  - Run foreground:    apex -c /etc/apex/apex.conf"
if command -v systemctl >/dev/null 2>&1; then
    echo "  - Start service:     systemctl enable --now apex"
    echo "  - Check logs:        journalctl -u apex -f"
    echo "  - Live reload:       systemctl reload apex"
fi
echo "  - Config path:       /etc/apex/apex.conf"
echo "  - Virtual hosts:     /etc/apex/conf.d/*.conf"
echo "  - Access log:        /var/log/apex/access.log"
echo ""
