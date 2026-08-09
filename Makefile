CC ?= cc
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

CFLAGS ?= -O3 -march=native -flto -fomit-frame-pointer -Wall -Wextra -Wpedantic
CFLAGS += -Iinclude $(shell pkg-config --cflags openssl 2>/dev/null)
LDFLAGS ?= -flto $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

ifneq ($(shell $(CC) -ljemalloc -x c /dev/null -o /dev/null 2>/dev/null && echo 1),)
    LDFLAGS += -ljemalloc
endif

SRCS = src/main.c src/net.c src/tls.c src/worker.c src/metrics.c src/http.c src/config.c
OBJS = $(SRCS:.c=.o)
HDRS = $(wildcard include/*.h)
TARGET = tachyon

TEST_CFLAGS = -Iinclude $(shell pkg-config --cflags openssl 2>/dev/null) -Wall -Wextra -g
TEST_LDFLAGS = $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")
TEST_BINS = tests/test_config tests/test_http

.PHONY: all clean install uninstall test test-integration certs

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

tests/test_%: tests/test_%.c $(SRCS) $(HDRS)
	$(CC) $(TEST_CFLAGS) $< -o $@ $(TEST_LDFLAGS)

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do ./$$t || exit 1; done

certs:
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost" 2>/dev/null

clean:
	rm -f $(OBJS) $(TARGET) $(TEST_BINS) hello-server cert.pem key.pem

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

test-integration: $(TARGET) certs
	mkdir -p /tmp/tachyon-test-www && echo "<h1>Tachyon Static OK</h1>" > /tmp/tachyon-test-www/index.html; \
	printf '[server]\nport = 9443\nbind = "127.0.0.1"\nroot = "/tmp/tachyon-test-www"\nstatus = 200\n\n[tls]\ncert = "cert.pem"\nkey = "key.pem"\n\n[stats]\nenabled = true\npath = "/stats"\n' > /tmp/test-tachyon.toml; \
	./$(TARGET) -C /tmp/test-tachyon.toml & PID=$$!; \
	sleep 1; \
	curl -k -s https://127.0.0.1:9443/ && echo "" && \
	curl -k -s https://127.0.0.1:9443/stats && echo "" && \
	curl -k -s https://127.0.0.1:9443/nonexistent && echo "" && \
	kill $$PID && rm -rf /tmp/tachyon-test-www /tmp/test-tachyon.toml cert.pem key.pem
