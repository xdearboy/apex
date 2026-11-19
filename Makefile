CC ?= cc
CSTD ?= -std=c2x
CFLAGS ?= $(CSTD) -O3 -flto -D_GNU_SOURCE -pthread -Wall -Wextra -Werror -Iinclude -Isrc
AR ?= ar
LDFLAGS ?= -pthread -flto
VERSION ?= 1.3.2
PYTHON ?= python3

ifdef SANITIZE
CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer -g
LDFLAGS += -fsanitize=address,undefined
endif

LIB = libapex.a
BIN = apex
SRCS = src/core.c src/router.c src/proxy.c src/config.c src/tls.c src/h2.c
OBJS = $(SRCS:.c=.o)
HEADERS = include/apex.h include/apex/proxy.h include/apex/config.h src/internal.h

TLS_CFLAGS := $(shell pkg-config --cflags libssl libcrypto 2>/dev/null)
TLS_LIBS := $(shell pkg-config --libs libssl libcrypto 2>/dev/null || printf '%s ' -lssl -lcrypto)
H2_CFLAGS := $(shell pkg-config --cflags libnghttp2 2>/dev/null)
H2_LIBS := $(shell pkg-config --libs libnghttp2 2>/dev/null || printf '%s ' -lnghttp2)
CFLAGS += $(TLS_CFLAGS) $(H2_CFLAGS)
LDLIBS = $(TLS_LIBS) $(H2_LIBS)

EXAMPLES = examples/web_frameworks examples/hello_world examples/proxy_demo \
           examples/config_demo

all: $(LIB) $(BIN) $(EXAMPLES)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

BUILD_META_H = src/build_meta.h

# Regenerated whenever the Makefile changes. If you override CC/CFLAGS/LDFLAGS
# or SANITIZE on the command line, run `make clean` once so -v stays truthful.
$(BUILD_META_H): Makefile
	@{ printf '#define APEX_VERSION "%s"\n' "$(VERSION)"; \
	   printf '#define APEX_BUILD_CC "%s"\n' "$(CC)"; \
	   printf '#define APEX_BUILD_CFLAGS "%s"\n' "$(CFLAGS)"; \
	   printf '#define APEX_BUILD_LDFLAGS "%s"\n' "$(LDFLAGS)"; } > $@.tmp \
	&& mv -f $@.tmp $@

$(BIN): src/main.o $(BUILD_META_H) $(LIB)
	$(CC) $(CFLAGS) -o $@ src/main.o $(LIB) $(LDFLAGS) $(LDLIBS)

src/main.o: src/main.c $(HEADERS) $(BUILD_META_H) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

examples/web_frameworks: examples/web_frameworks.o $(LIB)
	$(CC) $(CFLAGS) -o $@ examples/web_frameworks.o $(LIB) $(LDFLAGS) $(LDLIBS)

examples/hello_world: examples/hello_world.o $(LIB)
	$(CC) $(CFLAGS) -o $@ examples/hello_world.o $(LIB) $(LDFLAGS) $(LDLIBS)

examples/proxy_demo: examples/proxy_demo.o src/proxy.o
	$(CC) $(CFLAGS) -o $@ examples/proxy_demo.o src/proxy.o $(LDFLAGS)

examples/config_demo: examples/config_demo.o $(LIB)
	$(CC) $(CFLAGS) -o $@ examples/config_demo.o $(LIB) $(LDFLAGS) $(LDLIBS)

proxy: examples/proxy_demo

test: all
	./examples/config_demo --selftest
	./examples/proxy_demo
	$(PYTHON) tests/test_cli.py ./$(BIN)
	$(PYTHON) tests/test_tls.py ./$(BIN)
	$(PYTHON) tests/test_h2.py ./$(BIN)

check: test

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) src/main.o $(LIB) $(BIN) examples/*.o $(EXAMPLES) $(BUILD_META_H)

.PHONY: all clean proxy test check
