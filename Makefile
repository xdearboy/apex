CC ?= cc
CSTD ?= -std=c2x
CFLAGS ?= $(CSTD) -O3 -flto -march=native -mtune=native -D_GNU_SOURCE -pthread -Wall -Wextra -Werror -Iinclude -Isrc -Isrc/core -Isrc/config -Isrc/http -Isrc/net -Isrc/storage -Isrc/security -Isrc/observability
AR ?= ar
LDFLAGS ?= -pthread -flto -rdynamic
VERSION ?= 1.5.0
PYTHON ?= python3

ifdef SANITIZE
CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer -g
LDFLAGS += -fsanitize=address,undefined
endif

ifdef TSAN
CFLAGS += -fsanitize=thread -fno-omit-frame-pointer -g
LDFLAGS += -fsanitize=thread
endif

LIB = libapex.a
BIN = apex

SRCS = src/core/core.c \
       src/core/runtime.c \
       src/core/pool.c \
       src/core/buf.c \
       src/core/module.c \
       src/core/lua_engine.c \
       src/core/wasm_engine.c \
       src/config/config.c \
       src/http/router.c \
       src/http/proxy.c \
       src/http/static.c \
       src/http/h2.c \
       src/http/fastcgi.c \
       src/http/websocket.c \
       src/http/http_util.c \
       src/http/sub_filter.c \
       src/http/auth_basic.c \
       src/http/http_api.c \
       src/http/compress.c \
       src/net/tls.c \
       src/net/resolver.c \
       src/net/realip.c \
       src/net/quic.c \
       src/storage/cache.c \
       src/storage/file_cache.c \
       src/security/ratelimit.c \
       src/security/filter.c \
       src/security/acme.c \
       src/observability/metrics.c \
       src/observability/log.c

OBJS = $(SRCS:.c=.o)
HEADERS = include/apex.h include/apex/pool.h include/apex/buf.h include/apex/filter.h include/apex/metrics.h include/apex/file_cache.h include/apex/http_util.h include/apex/acme.h include/apex/ratelimit.h include/apex/proxy.h include/apex/config.h include/apex/module.h include/apex/static.h include/apex/cache.h include/apex/realip.h include/apex/log.h include/apex/fastcgi.h include/apex/compress.h include/apex/http_api.h include/apex/websocket.h include/apex/auth_basic.h include/apex/sub_filter.h include/apex/resolver.h include/apex/lua_engine.h include/apex/wasm_engine.h include/apex/quic.h src/core/internal.h

TLS_CFLAGS := $(shell pkg-config --cflags libssl libcrypto 2>/dev/null)
TLS_LIBS := $(shell pkg-config --libs libssl libcrypto 2>/dev/null || printf '%s ' -lssl -lcrypto)
H2_CFLAGS := $(shell pkg-config --cflags libnghttp2 2>/dev/null)
H2_LIBS := $(shell pkg-config --libs libnghttp2 2>/dev/null || printf '%s ' -lnghttp2)
COMPRESS_CFLAGS := $(shell pkg-config --cflags libbrotlienc libzstd zlib 2>/dev/null)
COMPRESS_LIBS := $(shell pkg-config --libs libbrotlienc libzstd zlib 2>/dev/null || printf '%s ' -lbrotlienc -lzstd -lz)
LUA_CFLAGS := $(shell pkg-config --cflags luajit 2>/dev/null || printf '%s ' -I/usr/include/luajit-2.1)
LUA_LIBS := $(shell pkg-config --libs luajit 2>/dev/null || printf '%s ' -lluajit-5.1)
WASM_CFLAGS := $(shell pkg-config --cflags wasmedge 2>/dev/null || printf '')
WASM_LIBS := $(shell pkg-config --libs wasmedge 2>/dev/null || printf '%s ' -lwasmedge)
QUIC_CFLAGS := $(shell pkg-config --cflags libngtcp2 libngtcp2_crypto_ossl libnghttp3 2>/dev/null || printf '')
QUIC_LIBS := $(shell pkg-config --libs libngtcp2 libngtcp2_crypto_ossl libnghttp3 2>/dev/null || printf '%s ' -lngtcp2 -lngtcp2_crypto_ossl -lnghttp3)
URING_CFLAGS := $(shell pkg-config --cflags liburing 2>/dev/null && printf '%s ' -DAPEX_HAVE_URING)
URING_LIBS := $(shell pkg-config --libs liburing 2>/dev/null)
CFLAGS += $(TLS_CFLAGS) $(H2_CFLAGS) $(COMPRESS_CFLAGS) $(LUA_CFLAGS) $(WASM_CFLAGS) $(QUIC_CFLAGS) $(URING_CFLAGS)
LDLIBS = $(TLS_LIBS) $(H2_LIBS) $(COMPRESS_LIBS) $(LUA_LIBS) $(WASM_LIBS) $(QUIC_LIBS) $(URING_LIBS) -ldl -lm

EXAMPLES = examples/web_frameworks examples/hello_world examples/proxy_demo \
           examples/config_demo examples/mod_security_headers.so

MODULES = modules/mod_coraza/mod_coraza.so

OBJDIRS = $(sort $(dir $(OBJS) src/core/main.o))

all: $(LIB) $(BIN) $(EXAMPLES) $(MODULES)

$(OBJDIRS):
	mkdir -p $@

$(OBJS): | $(OBJDIRS)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

BUILD_META_H = src/core/build_meta.h

# Regenerated whenever the Makefile changes. If you override CC/CFLAGS/LDFLAGS
# or SANITIZE on the command line, run `make clean` once so -v stays truthful.
$(BUILD_META_H): Makefile | $(OBJDIRS)
	@{ printf '#define APEX_VERSION "%s"\n' "$(VERSION)"; \
	   printf '#define APEX_BUILD_CC "%s"\n' "$(CC)"; \
	   printf '#define APEX_BUILD_CFLAGS "%s"\n' "$(CFLAGS)"; \
	   printf '#define APEX_BUILD_LDFLAGS "%s"\n' "$(LDFLAGS)"; } > $@.tmp \
	&& mv -f $@.tmp $@

$(BIN): src/core/main.o $(BUILD_META_H) $(LIB)
	$(CC) $(CFLAGS) -o $@ src/core/main.o $(LIB) $(LDFLAGS) $(LDLIBS)

src/core/main.o: src/core/main.c $(HEADERS) $(BUILD_META_H) Makefile | $(OBJDIRS)
	$(CC) $(CFLAGS) -c $< -o $@

examples/web_frameworks: examples/web_frameworks.o $(LIB)
	$(CC) $(CFLAGS) -o $@ examples/web_frameworks.o $(LIB) $(LDFLAGS) $(LDLIBS)

examples/hello_world: examples/hello_world.o $(LIB)
	$(CC) $(CFLAGS) -o $@ examples/hello_world.o $(LIB) $(LDFLAGS) $(LDLIBS)

examples/proxy_demo: examples/proxy_demo.o $(LIB)
	$(CC) $(CFLAGS) -o $@ examples/proxy_demo.o $(LIB) $(LDFLAGS) $(LDLIBS)

examples/config_demo: examples/config_demo.o $(LIB)
	$(CC) $(CFLAGS) -o $@ examples/config_demo.o $(LIB) $(LDFLAGS) $(LDLIBS)

examples/mod_security_headers.so: examples/mod_security_headers.c include/apex/module.h
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

modules/mod_coraza/libcoraza_bridge.so: modules/mod_coraza/coraza_bridge.go modules/mod_coraza/go.mod
	cd modules/mod_coraza && go build -buildvcs=false -buildmode=c-shared -o libcoraza_bridge.so coraza_bridge.go

modules/mod_coraza/mod_coraza.so: modules/mod_coraza/mod_coraza.c include/apex/module.h modules/mod_coraza/libcoraza_bridge.so
	$(CC) $(CFLAGS) -shared -fPIC -o $@ modules/mod_coraza/mod_coraza.c -Lmodules/mod_coraza -lcoraza_bridge -Wl,-rpath,'$$ORIGIN'

tests/test_pool: tests/test_pool.o $(LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_pool.o $(LIB) $(LDFLAGS) $(LDLIBS)

tests/test_filter: tests/test_filter.o $(LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_filter.o $(LIB) $(LDFLAGS) $(LDLIBS)

test: all tests/test_pool tests/test_filter
	./tests/test_pool
	./tests/test_filter
	$(PYTHON) tests/test_cli.py ./$(BIN)
	$(PYTHON) tests/test_tls.py ./$(BIN)
	$(PYTHON) tests/test_websocket.py ./$(BIN)
	$(PYTHON) tests/test_h2.py ./$(BIN)
	$(PYTHON) tests/test_waf.py ./$(BIN)
	$(PYTHON) tests/test_redirect.py ./$(BIN)
	$(PYTHON) tests/test_file_cache.py ./$(BIN)
	$(PYTHON) tests/test_security_defenses.py ./$(BIN)
	$(PYTHON) tests/test_proxy_headers.py ./$(BIN)
	$(PYTHON) tests/test_acl.py ./$(BIN)
	$(PYTHON) tests/test_include_glob.py ./$(BIN)
	$(PYTHON) tests/test_upstream_policies.py ./$(BIN)
	$(PYTHON) tests/test_ratelimit.py ./$(BIN)
	$(PYTHON) tests/test_stub_status.py ./$(BIN)
	$(PYTHON) tests/test_cache.py ./$(BIN)
	$(PYTHON) tests/test_realip.py ./$(BIN)
	$(PYTHON) tests/test_access_log.py ./$(BIN)
	$(PYTHON) tests/test_fastcgi.py ./$(BIN)
	$(PYTHON) tests/test_healthcheck.py ./$(BIN)
	$(PYTHON) tests/test_add_header.py ./$(BIN)
	$(PYTHON) tests/test_server_tokens.py ./$(BIN)
	$(PYTHON) tests/test_map.py ./$(BIN)
	$(PYTHON) tests/test_https_proxy.py ./$(BIN)
	$(PYTHON) tests/test_compression.py ./$(BIN)
	$(PYTHON) tests/test_failover.py ./$(BIN)
	$(PYTHON) tests/test_cookie_rewrite.py ./$(BIN)
	$(PYTHON) tests/test_sub_filter.py ./$(BIN)
	$(PYTHON) tests/test_resolver.py ./$(BIN)
	$(PYTHON) tests/test_otel.py ./$(BIN)
	$(PYTHON) tests/test_upstream_api.py ./$(BIN)
	$(PYTHON) tests/test_multi_listener.py ./$(BIN)
	$(PYTHON) tests/test_zero_downtime.py ./$(BIN)
	$(PYTHON) tests/test_grpc.py ./$(BIN)
	$(PYTHON) tests/test_h3.py ./$(BIN)
	$(PYTHON) tests/test_lua_hooks.py ./$(BIN)
	$(PYTHON) tests/test_wasm_filter.py ./$(BIN)
	$(PYTHON) tests/test_acme_live.py ./$(BIN)

check: test
asan:
	$(MAKE) clean
	$(MAKE) SANITIZE=1 test

tsan:
	$(MAKE) clean
	$(MAKE) TSAN=1 test

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) src/core/main.o src/main.o $(LIB) $(BIN) examples/*.o examples/*.so $(EXAMPLES) $(MODULES) modules/mod_coraza/*.so modules/mod_coraza/*.h $(BUILD_META_H) src/build_meta.h tests/test_pool.o tests/test_pool tests/test_filter.o tests/test_filter $(FUZZ_TARGETS) $(FUZZ_OBJS)

FUZZ_CC ?= clang
FUZZ_CFLAGS ?= -std=c2x -O1 -g -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer -D_GNU_SOURCE -pthread -Wall -Wextra -Iinclude -Isrc -Isrc/core -Isrc/config -Isrc/http -Isrc/net -Isrc/storage -Isrc/security -Isrc/observability $(TLS_CFLAGS) $(H2_CFLAGS) $(COMPRESS_CFLAGS)
FUZZ_LDFLAGS ?= -pthread -rdynamic -fsanitize=fuzzer,address,undefined
FUZZ_LIBS = $(TLS_LIBS) $(H2_LIBS) $(COMPRESS_LIBS) -ldl -lm

FUZZ_SRCS = $(filter-out src/core/main.c, $(SRCS))
FUZZ_OBJS = $(FUZZ_SRCS:.c=.fuzz.o)

%.fuzz.o: %.c $(HEADERS)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -c $< -o $@

FUZZ_TARGETS = fuzz/fuzz_http1 fuzz/fuzz_uri fuzz/fuzz_config fuzz/fuzz_h2_frame

fuzz/fuzz_http1: fuzz/fuzz_http1.c $(FUZZ_OBJS)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $< $(FUZZ_OBJS) $(FUZZ_LDFLAGS) $(FUZZ_LIBS)

fuzz/fuzz_uri: fuzz/fuzz_uri.c $(FUZZ_OBJS)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $< $(FUZZ_OBJS) $(FUZZ_LDFLAGS) $(FUZZ_LIBS)

fuzz/fuzz_config: fuzz/fuzz_config.c $(FUZZ_OBJS)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $< $(FUZZ_OBJS) $(FUZZ_LDFLAGS) $(FUZZ_LIBS)

fuzz/fuzz_h2_frame: fuzz/fuzz_h2_frame.c $(FUZZ_OBJS)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $< $(FUZZ_OBJS) $(FUZZ_LDFLAGS) $(FUZZ_LIBS)

fuzz: $(FUZZ_TARGETS)

lint:
	clang-tidy $(SRCS) -- $(CSTD) -D_GNU_SOURCE -Iinclude -Isrc -Isrc/core -Isrc/config -Isrc/http -Isrc/net -Isrc/storage -Isrc/security -Isrc/observability $(TLS_CFLAGS) $(H2_CFLAGS) $(COMPRESS_CFLAGS)

.PHONY: all clean proxy test check asan tsan fuzz lint
