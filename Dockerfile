# Multi-stage production build for Apex reverse proxy

# Stage 1: Build Coraza WAF bridge shared library
FROM golang:1.24-bookworm AS go-builder
WORKDIR /build/modules/mod_coraza
COPY modules/mod_coraza/go.mod modules/mod_coraza/go.sum* ./
RUN go mod download || true
COPY modules/mod_coraza/ ./
RUN go build -buildvcs=false -buildmode=c-shared -o libcoraza_bridge.so coraza_bridge.go

# Stage 2: Compile Apex C23 engine
FROM debian:bookworm AS c-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    libnghttp2-dev \
    libbrotli-dev \
    libzstd-dev \
    zlib1g-dev \
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

# Stage 3: Minimal secure runtime image
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libnghttp2-14 \
    libbrotlienc1 \
    libzstd1 \
    zlib1g \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r apex --gid 10001 \
    && useradd -r -g apex --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin apex \
    && mkdir -p /etc/apex /var/log/apex \
    && chown -R apex:apex /var/log/apex

# Install binaries and default config
COPY --from=c-builder /build/apex /usr/bin/apex
COPY conf/apex.conf /etc/apex/apex.conf

EXPOSE 80 443 8080
STOPSIGNAL SIGQUIT

ENTRYPOINT ["/usr/bin/apex"]
CMD ["-c", "/etc/apex/apex.conf"]
