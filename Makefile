CC ?= cc
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

CFLAGS ?= -O3 -march=native -flto -fomit-frame-pointer -Wall -Wextra -Wpedantic
CFLAGS += -Iinclude $(shell pkg-config --cflags openssl 2>/dev/null)
LDFLAGS ?= -flto $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

ifneq ($(shell $(CC) -ljemalloc -x c /dev/null -o /dev/null 2>/dev/null && echo 1),)
    LDFLAGS += -ljemalloc
endif

SRCS = src/main.c src/net.c src/tls.c src/worker.c src/metrics.c src/http.c
OBJS = $(SRCS:.c=.o)
TARGET = tachyon

.PHONY: all clean install uninstall test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) hello-server

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

test: $(TARGET)
	mkdir -p /tmp/tachyon-test-www && echo "<h1>Tachyon Static OK</h1>" > /tmp/tachyon-test-www/index.html; \
	./$(TARGET) -p 9443 -b 127.0.0.1 -d /tmp/tachyon-test-www & PID=$$!; \
	sleep 1; \
	curl -k -s https://127.0.0.1:9443/ && echo "" && \
	curl -k -s https://127.0.0.1:9443/stats && echo "" && \
	curl -k -s https://127.0.0.1:9443/nonexistent && echo "" && \
	kill $$PID && rm -rf /tmp/tachyon-test-www
