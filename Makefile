CC ?= cc
CSTD ?= -std=c2x
CFLAGS ?= $(CSTD) -O3 -flto -D_GNU_SOURCE -pthread -Wall -Wextra -Werror -Iinclude -Isrc
AR ?= ar
LDFLAGS ?= -pthread -flto

ifdef SANITIZE
CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer -g
LDFLAGS += -fsanitize=address,undefined
endif

LIB = libapex.a
SRCS = src/core.c src/router.c src/proxy.c src/config.c
OBJS = $(SRCS:.c=.o)
HEADERS = include/apex.h include/apex/proxy.h include/apex/config.h src/internal.h

EXAMPLES = examples/web_frameworks examples/hello_world examples/proxy_demo \
           examples/config_demo

all: $(LIB) $(EXAMPLES)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

examples/web_frameworks: examples/web_frameworks.o $(LIB)
	$(CC) $(CFLAGS) -o $@ examples/web_frameworks.o $(LIB) $(LDFLAGS)

examples/hello_world: examples/hello_world.o $(LIB)
	$(CC) $(CFLAGS) -o $@ examples/hello_world.o $(LIB) $(LDFLAGS)

examples/proxy_demo: examples/proxy_demo.o src/proxy.o
	$(CC) $(CFLAGS) -o $@ examples/proxy_demo.o src/proxy.o $(LDFLAGS)

examples/config_demo: examples/config_demo.o $(LIB)
	$(CC) $(CFLAGS) -o $@ examples/config_demo.o $(LIB) $(LDFLAGS)

proxy: examples/proxy_demo

test: all
	./examples/config_demo --selftest
	./examples/proxy_demo

check: test

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(LIB) examples/*.o $(EXAMPLES)

.PHONY: all clean proxy test check
