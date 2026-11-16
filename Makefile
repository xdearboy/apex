CC ?= cc
CFLAGS ?= -std=gnu2x -O3 -flto -D_GNU_SOURCE -pthread -Wall -Wextra -Werror -Iinclude -Isrc
AR ?= ar
LDFLAGS ?= -pthread -flto

LIB = libapex.a
SRCS = src/core.c src/router.c src/proxy.c
OBJS = $(SRCS:.c=.o)

EXAMPLES = examples/web_frameworks examples/hello_world examples/proxy_demo

all: $(LIB) $(EXAMPLES)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

examples/web_frameworks: examples/web_frameworks.o $(LIB)
	$(CC) $(CFLAGS) -o $@ examples/web_frameworks.o $(LIB) $(LDFLAGS)

examples/hello_world: examples/hello_world.o $(LIB)
	$(CC) $(CFLAGS) -o $@ examples/hello_world.o $(LIB) $(LDFLAGS)

examples/proxy_demo: examples/proxy_demo.o src/proxy.o
	$(CC) $(CFLAGS) -o $@ examples/proxy_demo.o src/proxy.o $(LDFLAGS)

proxy: examples/proxy_demo

%.o: %.c include/apex.h
	$(CC) $(CFLAGS) -c $< -o $@

src/proxy.o: src/proxy.c include/apex/proxy.h
	$(CC) $(CFLAGS) -c $< -o $@

examples/proxy_demo.o: examples/proxy_demo.c include/apex/proxy.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(LIB) examples/*.o $(EXAMPLES)

.PHONY: all clean proxy
