#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "apex/proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DEMO_BACKENDS 2
#define DEMO_BACKEND_ACCEPTORS 8
#define DEMO_SEQUENTIAL_REQUESTS 12
#define DEMO_WORKERS 4
#define DEMO_WORKER_REQUESTS 50

typedef enum {
    EDGE_SLOW = 0,
    EDGE_TRICKLE,
    EDGE_BIG_HEADER,
    EDGE_BIG_CHUNK,
} edge_mode_t;

typedef struct {
    int listen_fd;
    uint16_t port;
    edge_mode_t mode;
    pthread_t thread;
} edge_backend_t;

typedef struct {
    int listen_fd;
    int id;
    int thread_count;
    _Atomic bool *stop;
    pthread_t threads[DEMO_BACKEND_ACCEPTORS];
} backend_t;

typedef struct {
    upstream_group_t *group;
    int requests;
    _Atomic int *succeeded;
    _Atomic int *failed;
    int worker_id;
} worker_arg_t;

static int send_all(int fd, const void *data, size_t len) {
    const char *cursor = data;
    while (len > 0) {
        ssize_t sent;
#ifdef MSG_NOSIGNAL
        sent = send(fd, cursor, len, MSG_NOSIGNAL);
#else
        sent = send(fd, cursor, len, 0);
#endif
        if (sent > 0) {
            cursor += sent;
            len -= (size_t)sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

static void serve_client(int fd, int backend_id, _Atomic bool *stop, unsigned long long *sequence) {
    char buffer[16384];
    size_t used = 0;

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 200000;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    while (!atomic_load_explicit(stop, memory_order_relaxed)) {
        size_t header_length = 0;
        for (size_t index = 0; index + 3u < used; index++) {
            if (memcmp(buffer + index, "\r\n\r\n", 4) == 0) {
                header_length = index + 4u;
                break;
            }
        }

        if (header_length > 0) {
            char body[96];
            int body_length =
                snprintf(body, sizeof(body), "backend=%d seq=%llu\n", backend_id, *sequence);
            (*sequence)++;
            if (body_length < 0 || (size_t)body_length >= sizeof(body)) {
                return;
            }

            char response[256];
            int response_length =
                snprintf(response, sizeof(response),
                         "HTTP/1.1 200 OK\r\n"
                         "Content-Type: text/plain\r\n"
                         "Content-Length: %d\r\n"
                         "Connection: keep-alive\r\n"
                         "\r\n"
                         "%s",
                         body_length, body);
            if (response_length < 0 || (size_t)response_length >= sizeof(response)) {
                return;
            }
            if (send_all(fd, response, (size_t)response_length) < 0) {
                return;
            }

            memmove(buffer, buffer + header_length, used - header_length);
            used -= header_length;
            continue;
        }

        if (used == sizeof(buffer)) {
            return;
        }

        ssize_t received = recv(fd, buffer + used, sizeof(buffer) - used, 0);
        if (received > 0) {
            used += (size_t)received;
            continue;
        }
        if (received == 0) {
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
        }
        return;
    }
}

static void *backend_main(void *argument) {
    backend_t *backend = argument;
    unsigned long long sequence = 0;

    while (!atomic_load_explicit(backend->stop, memory_order_relaxed)) {
        struct pollfd descriptor = {.fd = backend->listen_fd, .events = POLLIN, .revents = 0};
        int ready = poll(&descriptor, 1, 100);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (ready == 0) {
            continue;
        }

        int client = accept(backend->listen_fd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            break;
        }

#ifdef SO_NOSIGPIPE
        int enabled = 1;
        (void)setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
#endif
        serve_client(client, backend->id, backend->stop, &sequence);
        close(client);
    }

    return NULL;
}

static int start_backend(backend_t *backend, int id, _Atomic bool *stop) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    int enabled = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;

    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0 || listen(fd, 128) < 0) {
        close(fd);
        return -1;
    }

    socklen_t address_length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &address_length) < 0) {
        close(fd);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }

    backend->listen_fd = fd;
    backend->id = id;
    backend->stop = stop;
    backend->thread_count = 0;
    for (int index = 0; index < DEMO_BACKEND_ACCEPTORS; index++) {
        if (pthread_create(&backend->threads[index], NULL, backend_main, backend) != 0) {
            break;
        }
        backend->thread_count++;
    }

    if (backend->thread_count == 0) {
        close(fd);
        return -1;
    }

    return (int)ntohs(address.sin_port);
}

static int parse_backend_id(const apex_proxy_response_t *response) {
    if (response->body == NULL || response->body_len < 9u) {
        return -1;
    }
    const char *body = response->body;
    if (memcmp(body, "backend=", 8) != 0) {
        return -1;
    }
    char digit = body[8];
    if (digit < '0' || digit > '9') {
        return -1;
    }
    return digit - '0';
}

static void *proxy_worker(void *argument) {
    worker_arg_t *worker = argument;
    for (int index = 0; index < worker->requests; index++) {
        apex_proxy_request_t request = {0};
        request.method = "GET";
        request.target = "/";
        request.keep_alive = true;

        apex_proxy_response_t response;
        int result = apex_proxy_forward(worker->group, &request, &response);
        if (result == APEX_PROXY_OK && response.status == 200 && response.body_len > 0) {
            atomic_fetch_add_explicit(worker->succeeded, 1, memory_order_relaxed);
        } else {
            if (result != APEX_PROXY_OK) {
                fprintf(stderr, "worker %d: %s\n", worker->worker_id, apex_proxy_strerror(result));
            }
            atomic_fetch_add_explicit(worker->failed, 1, memory_order_relaxed);
        }
        apex_proxy_response_free(&response);
    }

    apex_proxy_pool_stats_t stats;
    apex_proxy_pool_get_stats(&stats);
    printf("worker %d: created=%zu reused=%zu idle=%zu\n", worker->worker_id, stats.total_created,
           stats.total_reused, stats.idle_connections);
    apex_proxy_pool_reset();
    return NULL;
}

static void edge_sleep_ms(int milliseconds) {
    struct timespec remaining = {.tv_sec = milliseconds / 1000, .tv_nsec = (long)(milliseconds % 1000) * 1000000L};
    while (nanosleep(&remaining, &remaining) != 0 && errno == EINTR) {
    }
}

static int send_big_header(int fd) {
    static const char prefix[] = "HTTP/1.1 200 OK\r\nX-Fill: ";
    static const char suffix[] = "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    char filler[2048];
    memset(filler, 'a', sizeof(filler));
    if (send_all(fd, prefix, sizeof(prefix) - 1u) < 0) {
        return -1;
    }
    if (send_all(fd, filler, sizeof(filler)) < 0) {
        return -1;
    }
    if (send_all(fd, suffix, sizeof(suffix) - 1u) < 0) {
        return -1;
    }
    return 0;
}

static int send_big_chunk(int fd) {
    static const char head[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n100000\r\n";
    return send_all(fd, head, sizeof(head) - 1u);
}

static void *edge_main(void *argument) {
    edge_backend_t *backend = argument;
    struct pollfd descriptor = {.fd = backend->listen_fd, .events = POLLIN, .revents = 0};
    int ready;
    do {
        ready = poll(&descriptor, 1, 3000);
    } while (ready < 0 && errno == EINTR);
    if (ready <= 0) {
        return NULL;
    }

    int client = accept(backend->listen_fd, NULL, NULL);
    if (client < 0) {
        return NULL;
    }

    struct timeval timeout = {.tv_sec = 0, .tv_usec = 100000};
    (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    char scratch[1024];
    (void)recv(client, scratch, sizeof(scratch), 0);

    switch (backend->mode) {
    case EDGE_SLOW:
        edge_sleep_ms(500);
        break;
    case EDGE_TRICKLE: {
        static const char head[] = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n";
        (void)send_all(client, head, sizeof(head) - 1u);
        for (int index = 0; index < 8; index++) {
            edge_sleep_ms(60);
            (void)send_all(client, "x", 1);
        }
        break;
    }
    case EDGE_BIG_HEADER:
        (void)send_big_header(client);
        break;
    case EDGE_BIG_CHUNK:
        (void)send_big_chunk(client);
        break;
    }

    close(client);
    return NULL;
}

static int start_edge_backend(edge_backend_t *backend, edge_mode_t mode) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    int enabled = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;

    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0 || listen(fd, 8) < 0) {
        close(fd);
        return -1;
    }

    socklen_t address_length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &address_length) < 0) {
        close(fd);
        return -1;
    }

    backend->listen_fd = fd;
    backend->mode = mode;
    backend->port = ntohs(address.sin_port);
    if (pthread_create(&backend->thread, NULL, edge_main, backend) != 0) {
        close(fd);
        return -1;
    }
    return 0;
}

static int run_edge_case(const char *name, edge_mode_t mode, uint32_t max_header, uint32_t max_body,
                         uint64_t io_timeout_ms, int expected) {
    edge_backend_t backend = {0};
    if (start_edge_backend(&backend, mode) < 0) {
        fprintf(stderr, "edge %s: failed to start backend\n", name);
        return 1;
    }

    upstream_group_t group;
    apex_upstream_group_init(&group);
    if (max_header != 0) {
        group.max_header_bytes = max_header;
    }
    if (max_body != 0) {
        group.max_body_bytes = max_body;
    }
    if (io_timeout_ms != 0) {
        group.io_timeout_ms = io_timeout_ms;
    }
    group.connect_timeout_ms = 1000;
    if (apex_upstream_add_server(&group, "127.0.0.1", backend.port, 1) < 0) {
        fprintf(stderr, "edge %s: failed to add server\n", name);
        close(backend.listen_fd);
        (void)pthread_join(backend.thread, NULL);
        return 1;
    }

    apex_proxy_request_t request = {0};
    request.method = "GET";
    request.target = "/";

    apex_proxy_response_t response;
    int result = apex_proxy_forward(&group, &request, &response);
    int failures = 0;
    if (result != expected) {
        fprintf(stderr, "edge %s: got %d (%s), expected %d (%s)\n", name, result, apex_proxy_strerror(result),
                expected, apex_proxy_strerror(expected));
        failures++;
    } else {
        printf("edge %s: %s\n", name, apex_proxy_strerror(result));
    }

    apex_proxy_response_free(&response);
    apex_proxy_pool_reset();
    (void)pthread_join(backend.thread, NULL);
    close(backend.listen_fd);
    return failures;
}

static int run_validation_case(void) {
    upstream_group_t group;
    apex_upstream_group_init(&group);

    int failures = 0;
    apex_proxy_request_t request = {0};
    request.method = "GET";
    request.target = "/";

    apex_proxy_response_t response;
    memset(&response, 0xa5, sizeof(response));
    int result = apex_proxy_forward(&group, &request, &response);
    if (result != APEX_PROXY_ERR_NO_UPSTREAM) {
        fprintf(stderr, "edge validation: no-upstream got %d\n", result);
        failures++;
    }
    if (response.headers != NULL || response.body != NULL || response.headers_len != 0 ||
        response.body_len != 0 || response.status != 0) {
        fprintf(stderr, "edge validation: response not cleared on early error\n");
        failures++;
    }
    apex_proxy_response_free(&response);

    if (apex_upstream_add_server(&group, "127.0.0.1", 1, 0) < 0) {
        fprintf(stderr, "edge validation: failed to add server\n");
        return 1;
    }

    memset(&response, 0xa5, sizeof(response));
    request.method = NULL;
    result = apex_proxy_forward(&group, &request, &response);
    if (result != APEX_PROXY_ERR_INVALID) {
        fprintf(stderr, "edge validation: invalid method got %d\n", result);
        failures++;
    }
    if (response.headers != NULL || response.body != NULL) {
        fprintf(stderr, "edge validation: response not cleared on invalid method\n");
        failures++;
    }
    apex_proxy_response_free(&response);

    printf("edge validation: %s\n", failures ? "failed" : "ok");
    return failures ? 1 : 0;
}

static int run_zero_weight_case(void) {
    upstream_group_t group;
    apex_upstream_group_init(&group);
    if (apex_upstream_add_server(&group, "127.0.0.1", 9, 0) < 0 ||
        apex_upstream_add_server(&group, "127.0.0.1", 9, 0) < 0) {
        fprintf(stderr, "edge zero weight: failed to configure group\n");
        return 1;
    }

    int failures = 0;
    for (int policy = 0; policy < 2; policy++) {
        apex_upstream_set_policy(&group, policy == 0 ? APEX_BALANCE_ROUND_ROBIN : APEX_BALANCE_P2C);
        for (int index = 0; index < 1000; index++) {
            ssize_t chosen = apex_upstream_select(&group);
            if (chosen < 0 || chosen >= 2) {
                fprintf(stderr, "edge zero weight: invalid selection %zd\n", chosen);
                failures++;
                break;
            }
        }
    }

    printf("edge zero weight: %s\n", failures ? "failed" : "ok");
    return failures ? 1 : 0;
}

static int run_failover_case(void) {
    _Atomic bool stop = false;
    backend_t live_backend = {0};
    int live_port = start_backend(&live_backend, 0, &stop);
    if (live_port < 0) {
        fprintf(stderr, "edge failover: failed to start live backend\n");
        return 1;
    }

    int dead_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in dead_addr = {0};
    dead_addr.sin_family = AF_INET;
    dead_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dead_addr.sin_port = 0;
    (void)bind(dead_fd, (struct sockaddr *)&dead_addr, sizeof(dead_addr));
    socklen_t addr_len = sizeof(dead_addr);
    (void)getsockname(dead_fd, (struct sockaddr *)&dead_addr, &addr_len);
    int dead_port = ntohs(dead_addr.sin_port);
    close(dead_fd);

    upstream_group_t group;
    apex_upstream_group_init(&group);
    group.connect_timeout_ms = 200;
    group.max_retries = 2;
    group.max_fails = 2;
    group.health_check_enabled = true;
    group.health_check_interval_ms = 1000;
    group.health_check_timeout_ms = 200;

    if (apex_upstream_add_server(&group, "127.0.0.1", (uint16_t)dead_port, 1) < 0 ||
        apex_upstream_add_server(&group, "127.0.0.1", (uint16_t)live_port, 1) < 0) {
        fprintf(stderr, "edge failover: failed to add servers\n");
        atomic_store_explicit(&stop, true, memory_order_relaxed);
        close(live_backend.listen_fd);
        for (int i = 0; i < live_backend.thread_count; i++) {
            (void)pthread_join(live_backend.threads[i], NULL);
        }
        return 1;
    }

    int failures = 0;
    apex_proxy_request_t request = {0};
    request.method = "GET";
    request.target = "/";
    request.keep_alive = true;

    apex_proxy_response_t response;
    int result = apex_proxy_forward(&group, &request, &response);
    if (result != APEX_PROXY_OK || response.status != 200) {
        fprintf(stderr, "edge failover: forward failed (%d: %s, status=%d)\n", result, apex_proxy_strerror(result),
                response.status);
        failures++;
    } else if (response.server_index != 1) {
        fprintf(stderr, "edge failover: expected response from server 1, got %zu\n", response.server_index);
        failures++;
    }
    apex_proxy_response_free(&response);

    result = apex_proxy_forward(&group, &request, &response);
    if (result != APEX_PROXY_OK || response.status != 200) {
        fprintf(stderr, "edge failover: second forward failed (%d: %s)\n", result, apex_proxy_strerror(result));
        failures++;
    }
    apex_proxy_response_free(&response);

    if (apex_health_prober_start(&group, 1) != 0) {
        fprintf(stderr, "edge failover: prober start failed\n");
        failures++;
    }
    apex_health_prober_stop();

    atomic_store_explicit(&stop, true, memory_order_relaxed);
    close(live_backend.listen_fd);
    for (int i = 0; i < live_backend.thread_count; i++) {
        (void)pthread_join(live_backend.threads[i], NULL);
    }
    apex_proxy_pool_reset();

    printf("edge failover: %s\n", failures ? "failed" : "ok");
    return failures ? 1 : 0;
}

int main(void) {
    (void)signal(SIGPIPE, SIG_IGN);

    _Atomic bool stop = false;
    backend_t backends[DEMO_BACKENDS];
    int ports[DEMO_BACKENDS];
    memset(backends, 0, sizeof(backends));

    for (int index = 0; index < DEMO_BACKENDS; index++) {
        ports[index] = start_backend(&backends[index], index, &stop);
        if (ports[index] < 0) {
            fprintf(stderr, "failed to start backend %d\n", index);
            return 1;
        }
        printf("backend %d listening on 127.0.0.1:%d\n", index, ports[index]);
    }

    upstream_group_t group;
    apex_upstream_group_init(&group);
    if (apex_upstream_add_server(&group, "127.0.0.1", (uint16_t)ports[0], 1) < 0 ||
        apex_upstream_add_server(&group, "127.0.0.1", (uint16_t)ports[1], 3) < 0) {
        fprintf(stderr, "failed to configure upstream group\n");
        return 1;
    }
    apex_upstream_set_policy(&group, APEX_BALANCE_ROUND_ROBIN);

    int backend_hits[DEMO_BACKENDS] = {0, 0};
    int sequential_failures = 0;
    int sequential_succeeded = 0;

    for (int index = 0; index < DEMO_SEQUENTIAL_REQUESTS; index++) {
        apex_proxy_request_t request = {0};
        request.method = "GET";
        request.target = "/";
        request.keep_alive = true;

        apex_proxy_response_t response;
        int result = apex_proxy_forward(&group, &request, &response);
        if (result != APEX_PROXY_OK || response.status != 200) {
            fprintf(stderr, "sequential request %d: %s\n", index,
                    result == APEX_PROXY_OK ? "unexpected status" : apex_proxy_strerror(result));
            sequential_failures++;
        } else {
            int backend_id = parse_backend_id(&response);
            if (backend_id >= 0 && backend_id < DEMO_BACKENDS) {
                backend_hits[backend_id]++;
            }
            sequential_succeeded++;
        }
        apex_proxy_response_free(&response);
    }

    apex_proxy_pool_stats_t main_stats;
    apex_proxy_pool_get_stats(&main_stats);
    printf("round_robin hits: backend0=%d backend1=%d\n", backend_hits[0], backend_hits[1]);
    printf("main thread pool: created=%zu reused=%zu closed=%zu idle=%zu\n", main_stats.total_created,
           main_stats.total_reused, main_stats.total_closed, main_stats.idle_connections);

    apex_proxy_pool_reset();
    apex_upstream_set_policy(&group, APEX_BALANCE_P2C);

    _Atomic int succeeded = 0;
    _Atomic int failed = 0;
    pthread_t workers[DEMO_WORKERS];
    worker_arg_t worker_args[DEMO_WORKERS];
    int started_workers = 0;

    for (int index = 0; index < DEMO_WORKERS; index++) {
        worker_args[index].group = &group;
        worker_args[index].requests = DEMO_WORKER_REQUESTS;
        worker_args[index].succeeded = &succeeded;
        worker_args[index].failed = &failed;
        worker_args[index].worker_id = index;
        if (pthread_create(&workers[index], NULL, proxy_worker, &worker_args[index]) != 0) {
            fprintf(stderr, "failed to start worker %d\n", index);
            break;
        }
        started_workers++;
    }

    for (int index = 0; index < started_workers; index++) {
        (void)pthread_join(workers[index], NULL);
    }

    int total_failures = sequential_failures + atomic_load_explicit(&failed, memory_order_relaxed);
    int total_succeeded = sequential_succeeded + atomic_load_explicit(&succeeded, memory_order_relaxed);
    int expected = started_workers * DEMO_WORKER_REQUESTS + DEMO_SEQUENTIAL_REQUESTS;

    printf("p2c workers: succeeded=%d failed=%d\n", total_succeeded, total_failures);
    printf("requests=%d expected=%d\n", total_succeeded, expected);

    atomic_store_explicit(&stop, true, memory_order_relaxed);
    for (int index = 0; index < DEMO_BACKENDS; index++) {
        for (int thread = 0; thread < backends[index].thread_count; thread++) {
            (void)pthread_join(backends[index].threads[thread], NULL);
        }
        close(backends[index].listen_fd);
    }

    int edge_failures = 0;
    edge_failures += run_validation_case();
    edge_failures += run_zero_weight_case();
    edge_failures += run_failover_case();
    edge_failures += run_edge_case("slow upstream timeout", EDGE_SLOW, 0, 0, 150, APEX_PROXY_ERR_TIMEOUT);
    edge_failures += run_edge_case("trickle deadline", EDGE_TRICKLE, 0, 0, 200, APEX_PROXY_ERR_TIMEOUT);
    edge_failures += run_edge_case("oversized header", EDGE_BIG_HEADER, 512, 0, 0, APEX_PROXY_ERR_TOO_LARGE);
    edge_failures += run_edge_case("oversized chunk", EDGE_BIG_CHUNK, 0, 1024, 0, APEX_PROXY_ERR_TOO_LARGE);

    if (total_failures != 0 || total_succeeded != expected || edge_failures != 0) {
        return 1;
    }

    printf("proxy demo ok\n");
    return 0;
}
