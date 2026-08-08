#!/usr/bin/env bash
# ==============================================================================
# tachyon wrk Benchmarking Automation Script
# ==============================================================================

set -euo pipefail

TARGET_URL="${1:-https://127.0.0.1:8443/}"
THREADS="${2:-28}"
CONNECTIONS="${3:-600}"
DURATION="${4:-10s}"

if ! command -v wrk &> /dev/null; then
    echo "Error: wrk is not installed. Install it with: apt install wrk" >&2
    exit 1
fi

echo "================================================================="
echo "  ⚡ Running tachyon Benchmark: $TARGET_URL"
echo "  Threads: $THREADS | Connections: $CONNECTIONS | Duration: $DURATION"
echo "================================================================="

wrk -t "$THREADS" -c "$CONNECTIONS" -d "$DURATION" --latency "$TARGET_URL"

echo ""
echo "==> Fetching server live statistics..."
curl -sk "${TARGET_URL%/}stats" || true
echo ""
