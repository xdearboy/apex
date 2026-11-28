# Multi-stage production build for Apex reverse proxy
# Ultra-fast C23 + native io_uring & HTTP/3 engine

# Stage 1: Build Coraza WAF bridge shared library
FROM golang:1.24-bookworm AS go-builder
WORKDIR /build/modules/mod_coraza
COPY modules/mod_coraza/go.mod modules/mod_coraza/go.sum* ./
RUN go mod download || true
COPY modules/mod_coraza/ ./
RUN go build -buildvcs=false -buildmode=c-shared -o libcoraza_bridge.so coraza_bridge.go

# Stage 2: Compile Apex C23 engine with io_uring and HTTP/3
FROM debian:trixie-slim AS c-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    libnghttp2-dev \
    libbrotli-dev \
    libzstd-dev \
    zlib1g-dev \
    libluajit-5.1-dev \
    liburing-dev \
    libngtcp2-dev \
    libngtcp2-crypto-ossl-dev \
    libnghttp3-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY include/ include/
COPY src/ src/
COPY examples/ examples/
COPY modules/ modules/
COPY Makefile ./

# Copy prebuilt coraza bridge from stage 1
COPY --from=go-builder /build/modules/mod_coraza/libcoraza_bridge.so modules/mod_coraza/
COPY --from=go-builder /build/modules/mod_coraza/libcoraza_bridge.h modules/mod_coraza/

RUN make clean && make -j$(nproc)

# Stage 3: Minimal secure runtime image (~30MB)
FROM debian:trixie-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3t64 \
    libnghttp2-14 \
    libbrotli1 \
    libzstd1 \
    zlib1g \
    libluajit-5.1-2 \
    liburing2 \
    libngtcp2-16 \
    libngtcp2-crypto-ossl0 \
    libnghttp3-9 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r apex --gid 10001 \
    && useradd -r -g apex --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin apex \
    && mkdir -p /etc/apex/conf.d /var/log/apex /var/cache/apex /var/www/static \
    && chown -R apex:apex /var/log/apex /var/cache/apex /var/www/static

# Install binary, configurations and examples
COPY --from=c-builder /build/apex /usr/bin/apex
COPY conf/apex.conf /etc/apex/apex.conf
COPY conf/conf.d/ /etc/apex/conf.d/

USER apex
EXPOSE 8080 8443
STOPSIGNAL SIGQUIT

ENTRYPOINT ["/usr/bin/apex"]
CMD ["-c", "/etc/apex/apex.conf"]
