CC ?= gcc
CFLAGS ?= -std=gnu11 -O3 -flto -D_GNU_SOURCE -pthread -Wall -Wextra -Iinclude -Isrc
AR ?= ar
LDFLAGS ?= -pthread

LIB = libapex.a
SRCS = src/core.c src/router.c
OBJS = $(SRCS:.c=.o)

EXAMPLES = examples/web_frameworks examples/hello_world

all: $(LIB) $(EXAMPLES)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

examples/web_frameworks: examples/web_frameworks.o $(LIB)
	$(CC) $(CFLAGS) -o $@ examples/web_frameworks.o $(LIB) $(LDFLAGS)

examples/hello_world: examples/hello_world.o $(LIB)
	$(CC) $(CFLAGS) -o $@ examples/hello_world.o $(LIB) $(LDFLAGS)

%.o: %.c include/apex.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(LIB) examples/*.o $(EXAMPLES)

.PHONY: all clean
