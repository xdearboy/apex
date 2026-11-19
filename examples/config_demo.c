#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "internal.h"

#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

static int test_failures;

static void check(bool condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "  FAIL: %s\n", message);
        test_failures++;
    }
}

static void print_config_error(const apex_config_error_t *error) {
    if (error == NULL) {
        return;
    }
    if (error->line > 0) {
        fprintf(stderr, "%s:%d:%d: %s: %s\n", error->file, error->line, error->column,
                apex_config_strerror(error->code), error->message);
    } else {
        fprintf(stderr, "%s: %s: %s\n", error->file, apex_config_strerror(error->code), error->message);
    }
    if (error->hint[0] != '\0') {
        fprintf(stderr, "  hint: %s\n", error->hint);
    }
}

static const char *valid_config_text =
    "http {\n"
    "    worker_connections 2048;\n"
    "    keepalive_timeout 70s;\n"
    "    client_header_timeout 12s;\n"
    "    client_body_timeout 20s;\n"
    "    server_tokens on;\n"
    "\n"
    "    upstream api {\n"
    "        server 127.0.0.1:9001 weight=2 max_conns=128;\n"
    "        server 127.0.0.1:9002;\n"
    "        policy p2c;\n"
    "        keepalive 48;\n"
    "        connect_timeout 3s;\n"
    "        read_timeout 9s;\n"
    "        idle_timeout 30s;\n"
    "    }\n"
    "\n"
    "    upstream web {\n"
    "        server 127.0.0.1:9100;\n"
    "        algorithm round_robin;\n"
    "    }\n"
    "\n"
    "    server {\n"
    "        listen 127.0.0.1:8081;\n"
    "        server_name \"example.com\" \"www.example.com\";\n"
    "\n"
    "        location \"=\" \"/health\" {\n"
    "            proxy_pass \"http://127.0.0.1:9003\";\n"
    "        }\n"
    "\n"
    "        location \"/api/\" {\n"
    "            proxy_pass api;\n"
    "            proxy_set_header \"X-Forwarded-Proto\" \"https\";\n"
    "            proxy_connect_timeout 1500ms;\n"
    "            proxy_http_version 1.1;\n"
    "        }\n"
    "\n"
    "        location \"/\" {\n"
    "            proxy_pass web;\n"
    "        }\n"
    "    }\n"
    "}\n";

static int test_parse_valid(void) {
    apex_config_error_t error;
    apex_config_t *config = NULL;
    int status = apex_config_parse_string("valid.conf", valid_config_text, strlen(valid_config_text), &config,
                                          &error);
    if (status != APEX_CONFIG_OK) {
        print_config_error(&error);
        check(false, "valid configuration did not parse");
        return 1;
    }

    check(config->http.worker_connections == 2048u, "worker_connections default/override");
    check(config->http.keepalive_timeout_ms == 70000u, "keepalive_timeout duration");
    check(config->http.client_header_timeout_ms == 12000u, "client_header_timeout duration");
    check(config->http.client_body_timeout_ms == 20000u, "client_body_timeout duration");
    check(config->http.server_tokens, "server_tokens on");
    check(config->upstream_count == 2u, "upstream count");
    check(config->server_count == 1u, "server count");

    const apex_upstream_config_t *api = apex_config_find_upstream(config, "api");
    check(api != NULL, "api upstream exists");
    if (api != NULL) {
        check(api->policy == APEX_BALANCE_P2C, "api policy p2c");
        check(api->keepalive == 48u, "api keepalive");
        check(api->connect_timeout_ms == 3000u, "api connect_timeout");
        check(api->read_timeout_ms == 9000u, "api read_timeout");
        check(api->idle_timeout_ms == 30000u, "api idle_timeout");
        check(api->server_count == 2u, "api server count");
        check(api->servers[0].weight == 2u, "api weight");
        check(api->servers[0].max_conns == 128u, "api max_conns");
        check(api->servers[0].port == 9001u, "api port");
    }

    const apex_server_config_t *server = &config->servers[0];
    check(server->listen_port == 8081u, "listen port");
    check(strcmp(server->listen_host, "127.0.0.1") == 0, "listen host");
    check(server->server_name_count == 2u, "server_name count");
    check(server->location_count == 3u, "location count");

    check(server->locations[0].exact, "exact location flag");
    check(strcmp(server->locations[0].path, "/health") == 0, "exact location path");
    check(server->locations[0].target == APEX_PROXY_TARGET_ENDPOINT, "endpoint proxy target");
    check(server->locations[0].endpoint_port == 9003u, "endpoint port");
    check(strcmp(server->locations[0].endpoint_host, "127.0.0.1") == 0, "endpoint host");

    check(server->locations[1].target == APEX_PROXY_TARGET_UPSTREAM, "named proxy target");
    check(server->locations[1].upstream_index == 0u, "named upstream index");
    check(server->locations[1].header_count == 1u, "proxy_set_header count");
    check(server->locations[1].has_connect_timeout, "proxy connect timeout override");
    check(server->locations[1].connect_timeout_ms == 1500u, "proxy connect timeout value");
    check(server->locations[1].http_version == 11, "proxy_http_version 1.1");

    apex_runtime_t *runtime = apex_runtime_create(config, &error);
    check(runtime != NULL, "runtime creation");
    if (runtime != NULL) {
        check(runtime->group_count == 2u, "runtime upstream groups");
        check(runtime->endpoint_group_count == 1u, "runtime endpoint groups");

        apex_config_route_t route;
        memset(&route, 0, sizeof(route));
        check(apex_runtime_match(runtime, "EXAMPLE.COM", 11u, "/api/users", 10u, &route), "host/prefix match");
        check(route.location == &server->locations[1], "prefix location selected");
        check(route.group == apex_runtime_upstream(runtime, 0u), "named upstream group selected");

        memset(&route, 0, sizeof(route));
        check(apex_runtime_match(runtime, "example.com", 11u, "/health", 7u, &route), "exact match");
        check(route.location == &server->locations[0], "exact location selected");
        check(route.group == apex_runtime_endpoint_group(runtime, &server->locations[0]),
              "endpoint group selected");

        memset(&route, 0, sizeof(route));
        check(apex_runtime_match(runtime, "unknown.test", 12u, "/", 1u, &route), "default server fallback");
        check(route.location == &server->locations[2], "root location selected");

        memset(&route, 0, sizeof(route));
        check(!apex_runtime_match(runtime, "example.com", 11u, "not-a-path", 10u, &route),
              "non-rooted path does not match");
    }

    apex_runtime_destroy(runtime);
    apex_config_free(config);
    return 0;
}

static int test_environment(void) {
    apex_config_error_t error;

    setenv("APEX_TEST_PORT", "9123", 1);
    const char *text = "http { upstream api { server 127.0.0.1:${APEX_TEST_PORT}; } "
                       "server { listen \":8082\"; location \"/\" { proxy_pass api; } } }";
    apex_config_t *config = NULL;
    int status = apex_config_parse_string("env.conf", text, strlen(text), &config, &error);
    check(status == APEX_CONFIG_OK, "environment expansion parses");
    if (status == APEX_CONFIG_OK) {
        check(config->upstreams[0].servers[0].port == 9123u, "environment value expanded");
        apex_config_free(config);
    } else {
        print_config_error(&error);
    }

    const char *default_text = "http { upstream api { server 127.0.0.1:${APEX_TEST_DEFAULT:-9001}; } "
                               "server { listen \":8082\"; location \"/\" { proxy_pass api; } } }";
    config = NULL;
    status = apex_config_parse_string("env-default.conf", default_text, strlen(default_text), &config, &error);
    check(status == APEX_CONFIG_OK, "environment default parses");
    if (status == APEX_CONFIG_OK) {
        check(config->upstreams[0].servers[0].port == 9001u, "environment default used");
        apex_config_free(config);
    } else {
        print_config_error(&error);
    }

    const char *missing_text = "http { upstream api { server 127.0.0.1:${APEX_TEST_MISSING}; } "
                               "server { listen \":8082\"; location \"/\" { proxy_pass api; } } }";
    config = NULL;
    status = apex_config_parse_string("env-missing.conf", missing_text, strlen(missing_text), &config, &error);
    check(status != APEX_CONFIG_OK, "unset environment variable rejected");
    check(error.code != APEX_CONFIG_OK && error.message[0] != '\0', "unset environment diagnostic");
    apex_config_free(config);

    unsetenv("APEX_TEST_PORT");
    return 0;
}

static void expect_parse_failure(const char *name, const char *text) {
    apex_config_error_t error;
    apex_config_t *config = NULL;
    int status = apex_config_parse_string(name, text, strlen(text), &config, &error);
    if (status == APEX_CONFIG_OK) {
        fprintf(stderr, "  FAIL: %s should not parse\n", name);
        test_failures++;
        apex_config_free(config);
        return;
    }
    if (error.message[0] == '\0') {
        fprintf(stderr, "  FAIL: %s produced an empty diagnostic\n", name);
        test_failures++;
    }
}

static int test_parse_errors(void) {
    expect_parse_failure("unknown-directive.conf",
                         "http { mystery on; server { listen \":1\"; location \"/\" { proxy_pass \"127.0.0.1:2\"; } } }");
    expect_parse_failure("missing-semicolon.conf",
                         "http { keepalive_timeout 75s server { listen \":1\"; "
                         "location \"/\" { proxy_pass \"127.0.0.1:2\"; } } }");
    expect_parse_failure("bad-duration.conf",
                         "http { keepalive_timeout 5x; server { listen \":1\"; "
                         "location \"/\" { proxy_pass \"127.0.0.1:2\"; } } }");
    expect_parse_failure("unresolved-upstream.conf",
                         "http { server { listen \":1\"; location \"/\" { proxy_pass missing; } } }");
    expect_parse_failure("duplicate-upstream.conf",
                         "http { upstream api { server 127.0.0.1:1; } "
                         "upstream api { server 127.0.0.1:2; } "
                         "server { listen \":1\"; location \"/\" { proxy_pass api; } } }");
    expect_parse_failure("empty-location.conf", "http { server { listen \":1\"; location \"/\" { } } }");
    expect_parse_failure("bad-endpoint.conf",
                         "http { server { listen \":1\"; location \"/\" { proxy_pass \"127.0.0.1\"; } } }");
    expect_parse_failure("bad-escape.conf",
                         "http { server { listen \":1\"; server_name \"bad\\q\"; "
                         "location \"/\" { proxy_pass \"127.0.0.1:2\"; } } }");
    expect_parse_failure("unterminated-block.conf",
                         "http { server { listen \":1\"; location \"/\" { proxy_pass \"127.0.0.1:2\"; ");
    return 0;
}

static int write_temp_file(const char *template, const char *contents, char *path, size_t path_capacity) {
    snprintf(path, path_capacity, "%s", template);
    int fd = mkstemp(path);
    if (fd < 0) {
        return -1;
    }

    size_t length = strlen(contents);
    size_t written = 0;
    while (written < length) {
        ssize_t result = write(fd, contents + written, length - written);
        if (result <= 0) {
            close(fd);
            unlink(path);
            return -1;
        }
        written += (size_t)result;
    }
    close(fd);
    return 0;
}

static int test_include(void) {
    char included_path[256];
    char root_path[256];
    const char *included = "http { upstream api { server 127.0.0.1:9009; } "
                           "server { listen \":8083\"; location \"/\" { proxy_pass api; } } }\n";

    if (write_temp_file("/tmp/apex-include-XXXXXX", included, included_path, sizeof(included_path)) != 0) {
        check(false, "cannot create include fixture");
        return 1;
    }

    char root[512];
    snprintf(root, sizeof(root), "include \"%s\";\n", included_path);
    if (write_temp_file("/tmp/apex-root-XXXXXX", root, root_path, sizeof(root_path)) != 0) {
        unlink(included_path);
        check(false, "cannot create root fixture");
        return 1;
    }

    apex_config_error_t error;
    apex_config_t *config = NULL;
    int status = apex_config_parse_file(root_path, &config, &error);
    check(status == APEX_CONFIG_OK, "include configuration parses");
    if (status == APEX_CONFIG_OK) {
        check(config->upstream_count == 1u, "include loaded upstream");
        check(config->server_count == 1u, "include loaded server");
        apex_config_free(config);
    } else {
        print_config_error(&error);
    }

    unlink(root_path);
    unlink(included_path);
    return 0;
}

typedef struct {
    int listen_fd;
    uint16_t port;
    char request[4096];
    size_t request_length;
    int status;
    const char *response;
    size_t response_length;
} demo_backend_t;

static int send_all_fd(int fd, const void *data, size_t length) {
    const char *cursor = data;
    while (length > 0) {
#ifdef MSG_NOSIGNAL
        ssize_t sent = send(fd, cursor, length, MSG_NOSIGNAL);
#else
        ssize_t sent = send(fd, cursor, length, 0);
#endif
        if (sent > 0) {
            cursor += sent;
            length -= (size_t)sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

static void *demo_backend_main(void *argument) {
    demo_backend_t *backend = argument;
    int client = accept(backend->listen_fd, NULL, NULL);
    if (client < 0) {
        return NULL;
    }

    while (backend->request_length < sizeof(backend->request) - 1u) {
        ssize_t received = recv(client, backend->request + backend->request_length,
                                sizeof(backend->request) - 1u - backend->request_length, 0);
        if (received <= 0) {
            break;
        }
        backend->request_length += (size_t)received;
        if (memmem(backend->request, backend->request_length, "\r\n\r\n", 4u) != NULL) {
            break;
        }
    }
    backend->request[backend->request_length] = '\0';

    static const char default_response[] = "HTTP/1.1 200 OK\r\n"
                                           "Content-Type: text/plain\r\n"
                                           "Transfer-Encoding: chunked\r\n"
                                           "Connection: close\r\n"
                                           "\r\n"
                                           "5\r\nhello\r\n"
                                           "0\r\n\r\n";
    const char *response = backend->response != NULL ? backend->response : default_response;
    size_t response_length = backend->response != NULL ? backend->response_length
                                                       : sizeof(default_response) - 1u;
    if (send_all_fd(client, response, response_length) == 0) {
        backend->status = 200;
    }
    close(client);
    return NULL;
}

static int start_demo_backend(demo_backend_t *backend) {
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
    backend->port = ntohs(address.sin_port);
    backend->status = 0;
    backend->request_length = 0;
    backend->response = NULL;
    backend->response_length = 0;
    return 0;
}

static int test_router_integration(void) {
    demo_backend_t backend;
    memset(&backend, 0, sizeof(backend));
    if (start_demo_backend(&backend) != 0) {
        check(false, "cannot start integration backend");
        return 1;
    }

    pthread_t thread;
    if (pthread_create(&thread, NULL, demo_backend_main, &backend) != 0) {
        close(backend.listen_fd);
        check(false, "cannot start integration backend thread");
        return 1;
    }

    char text[1024];
    snprintf(text, sizeof(text),
             "http {\n"
             "    upstream edge { server 127.0.0.1:%u; keepalive 4; }\n"
             "    server {\n"
             "        listen 127.0.0.1:18080;\n"
             "        server_name example.com;\n"
             "        location \"/\" {\n"
             "            proxy_pass edge;\n"
             "            proxy_set_header \"X-Forwarded-Proto\" \"https\";\n"
             "        }\n"
             "    }\n"
             "}\n",
             (unsigned)backend.port);

    apex_config_error_t error;
    apex_config_t *config = NULL;
    int status = apex_config_parse_string("integration.conf", text, strlen(text), &config, &error);
    check(status == APEX_CONFIG_OK, "integration configuration parses");
    if (status != APEX_CONFIG_OK) {
        print_config_error(&error);
        close(backend.listen_fd);
        (void)pthread_join(thread, NULL);
        return 1;
    }

    apex_app_t *app = apex_create();
    check(app != NULL, "app creation");
    if (app == NULL) {
        apex_config_free(config);
        close(backend.listen_fd);
        (void)pthread_join(thread, NULL);
        return 1;
    }

    status = apex_app_attach_config(app, config, &error);
    check(status == 0, "configuration attachment");
    if (status != 0) {
        print_config_error(&error);
        apex_config_free(config);
        apex_destroy(app);
        close(backend.listen_fd);
        (void)pthread_join(thread, NULL);
        return 1;
    }

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        check(false, "cannot create socket pair");
        apex_destroy(app);
        close(backend.listen_fd);
        (void)pthread_join(thread, NULL);
        return 1;
    }

    static const char request[] = "GET /integration HTTP/1.1\r\n"
                                  "Host: example.com\r\n"
                                  "X-Original: yes\r\n"
                                  "X-Forwarded-Proto: http\r\n"
                                  "Connection: keep-alive\r\n"
                                  "\r\n";

    conn_t connection;
    memset(&connection, 0, sizeof(connection));
    connection.fd = sockets[0];
    apex_res_t response = {.conn = &connection};

    apex_dispatch(app, request, sizeof(request) - 1u, NULL, 0, &response);

    char output[4096];
    size_t output_length = 0;
    if (connection.write_length > 0) {
        output_length = connection.write_length;
        memcpy(output, connection.write_buffer, connection.write_length);
    }
    if (connection.aux_length > 0 && output_length + connection.aux_length < sizeof(output)) {
        memcpy(output + output_length, connection.aux_buffer, connection.aux_length);
        output_length += connection.aux_length;
    }
    if (output_length >= sizeof(output)) {
        output_length = sizeof(output) - 1u;
    }
    output[output_length] = '\0';

    check(strstr(output, "HTTP/1.1 200 OK") != NULL, "proxied response status");
    check(strstr(output, "Content-Length: 5\r\n") != NULL, "proxied response content length");
    check(strstr(output, "Transfer-Encoding") == NULL, "chunked framing removed downstream");
    check(strstr(output, "\r\n\r\nhello") != NULL, "proxied response body");

    (void)pthread_join(thread, NULL);

    check(backend.status == 200, "backend handled one request");
    check(strstr(backend.request, "GET /integration HTTP/1.1") != NULL, "backend received request line");
    check(strstr(backend.request, "X-Original: yes") != NULL, "backend received original header");
    check(strstr(backend.request, "X-Forwarded-Proto: https\r\n") != NULL,
          "backend received proxy_set_header");
    check(strstr(backend.request, "X-Forwarded-Proto: http\r\n") == NULL,
          "original overridden header removed");

    apex_proxy_pool_reset();
    close(sockets[0]);
    close(sockets[1]);
    close(backend.listen_fd);
    apex_destroy(app);
    return 0;
}

static int test_large_response(void) {
    const size_t body_length = 12000u;
    size_t response_capacity = body_length + 256u;
    char *backend_response = malloc(response_capacity);
    if (backend_response == NULL) {
        check(false, "cannot allocate large response fixture");
        return 1;
    }

    int header_length = snprintf(backend_response, response_capacity,
                                 "HTTP/1.1 200 OK\r\n"
                                 "Content-Type: text/plain\r\n"
                                 "Transfer-Encoding: chunked\r\n"
                                 "Connection: close\r\n"
                                 "\r\n"
                                 "%zx\r\n",
                                 body_length);
    if (header_length < 0) {
        free(backend_response);
        check(false, "cannot build large response fixture");
        return 1;
    }
    memset(backend_response + header_length, 'A', body_length);
    size_t total_length = (size_t)header_length + body_length;
    memcpy(backend_response + total_length, "\r\n0\r\n\r\n", 7u);
    total_length += 7u;

    demo_backend_t backend;
    memset(&backend, 0, sizeof(backend));
    if (start_demo_backend(&backend) != 0) {
        free(backend_response);
        check(false, "cannot start large-response backend");
        return 1;
    }
    backend.response = backend_response;
    backend.response_length = total_length;

    pthread_t thread;
    if (pthread_create(&thread, NULL, demo_backend_main, &backend) != 0) {
        close(backend.listen_fd);
        free(backend_response);
        check(false, "cannot start large-response backend thread");
        return 1;
    }

    char text[1024];
    snprintf(text, sizeof(text),
             "http { upstream edge { server 127.0.0.1:%u; } "
             "server { listen \":8084\"; location \"/\" { proxy_pass edge; } } }",
             (unsigned)backend.port);

    apex_config_error_t error;
    apex_config_t *config = NULL;
    int status = apex_config_parse_string("large.conf", text, strlen(text), &config, &error);
    check(status == APEX_CONFIG_OK, "large-response configuration parses");
    if (status != APEX_CONFIG_OK) {
        print_config_error(&error);
        close(backend.listen_fd);
        free(backend_response);
        (void)pthread_join(thread, NULL);
        return 1;
    }

    apex_app_t *app = apex_create();
    check(app != NULL, "large-response app creation");
    if (app == NULL || apex_app_attach_config(app, config, &error) != 0) {
        apex_config_free(config);
        apex_destroy(app);
        close(backend.listen_fd);
        free(backend_response);
        (void)pthread_join(thread, NULL);
        return 1;
    }

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        check(false, "cannot create large-response socket pair");
        apex_destroy(app);
        close(backend.listen_fd);
        free(backend_response);
        (void)pthread_join(thread, NULL);
        return 1;
    }

    static const char request[] = "GET /large HTTP/1.1\r\nHost: example.com\r\n\r\n";
    conn_t connection;
    memset(&connection, 0, sizeof(connection));
    connection.fd = sockets[0];
    apex_res_t response = {.conn = &connection};

    apex_dispatch(app, request, sizeof(request) - 1u, NULL, 0, &response);

    size_t output_length = (size_t)connection.write_length + connection.aux_length;
    char *output = malloc(output_length + 1u);
    check(output != NULL, "large-response output allocation");
    if (output != NULL) {
        size_t position = 0;
        if (connection.write_length > 0) {
            memcpy(output, connection.write_buffer, connection.write_length);
            position += connection.write_length;
        }
        if (connection.aux_length > 0) {
            memcpy(output + position, connection.aux_buffer, connection.aux_length);
            position += connection.aux_length;
        }
        output[position] = '\0';

        check(strstr(output, "HTTP/1.1 200 OK") != NULL, "large-response status");
        check(strstr(output, "Content-Length: 12000\r\n") != NULL, "large-response content length");
        check(strstr(output, "Transfer-Encoding") == NULL, "large-response framing removed");
        check(position == output_length && output_length > body_length, "large-response fully queued");
        const char *body = strstr(output, "\r\n\r\n");
        check(body != NULL && strlen(body + 4) == body_length && body[4] == 'A' &&
                  body[4 + body_length - 1u] == 'A',
              "large-response body intact");
        free(output);
    }

    free(connection.aux_buffer);
    connection.aux_buffer = NULL;
    (void)pthread_join(thread, NULL);

    apex_proxy_pool_reset();
    close(sockets[0]);
    close(sockets[1]);
    close(backend.listen_fd);
    free(backend_response);
    apex_destroy(app);
    return 0;
}

static int run_selftest(void) {
    test_failures = 0;
    printf("config parser: parser, environment, include, router integration\n");
    test_parse_valid();
    test_environment();
    test_parse_errors();
    test_include();
    test_router_integration();
    test_large_response();

    if (test_failures != 0) {
        fprintf(stderr, "config self-test failed with %d error(s)\n", test_failures);
        return 1;
    }
    printf("config self-test ok\n");
    return 0;
}

static int print_config_summary(const apex_config_t *config) {
    printf("configuration: %s\n", config->source);
    printf("  servers=%zu upstreams=%zu modules=%zu\n", config->server_count, config->upstream_count,
           config->module_count);
    for (size_t index = 0; index < config->upstream_count; index++) {
        const char *policy_str = "round_robin";
        if (config->upstreams[index].policy == APEX_BALANCE_P2C) {
            policy_str = "p2c";
        } else if (config->upstreams[index].policy == APEX_BALANCE_LEAST_CONN) {
            policy_str = "least_conn";
        } else if (config->upstreams[index].policy == APEX_BALANCE_IP_HASH) {
            policy_str = "ip_hash";
        }
        printf("  upstream %s: servers=%zu policy=%s\n", config->upstreams[index].name,
               config->upstreams[index].server_count, policy_str);
    }
    for (size_t index = 0; index < config->server_count; index++) {
        const apex_server_config_t *server = &config->servers[index];
        printf("  server %s:%u: names=%zu locations=%zu\n",
               server->listen_host[0] != '\0' ? server->listen_host : "*", (unsigned)server->listen_port,
               server->server_name_count, server->location_count);
        for (size_t location_index = 0; location_index < server->location_count; location_index++) {
            const apex_location_config_t *location = &server->locations[location_index];
            char target[192];
            if (location->target == APEX_PROXY_TARGET_UPSTREAM) {
                snprintf(target, sizeof(target), "upstream:%s", location->upstream_name);
            } else if (location->target == APEX_PROXY_TARGET_ENDPOINT) {
                snprintf(target, sizeof(target), "endpoint:%s:%u", location->endpoint_host,
                         (unsigned)location->endpoint_port);
            } else {
                snprintf(target, sizeof(target), "root:%s", location->root);
            }
            printf("    location %s%s -> %s\n", location->exact ? "= " : "", location->path, target);
        }
    }
    return 0;
}

static void usage(const char *program) {
    fprintf(stderr,
            "usage:\n"
            "  %s -t <file>       validate configuration\n"
            "  %s --check <file>  validate configuration\n"
            "  %s --selftest      run parser and router tests\n"
            "  %s <file>          load configuration and serve on its first listen port\n",
            program, program, program, program);
}

int main(int argc, char **argv) {
    (void)signal(SIGPIPE, SIG_IGN);

    if (argc == 2 && strcmp(argv[1], "--selftest") == 0) {
        return run_selftest();
    }

    if (argc == 3 && (strcmp(argv[1], "-t") == 0 || strcmp(argv[1], "--check") == 0)) {
        apex_config_error_t error;
        int status = apex_config_check_file(argv[2], &error);
        if (status != APEX_CONFIG_OK) {
            print_config_error(&error);
            return 1;
        }
        printf("configuration OK: %s\n", argv[2]);
        return 0;
    }

    if (argc == 2 && argv[1][0] != '-') {
        apex_config_error_t error;
        apex_config_t *config = NULL;
        int status = apex_config_parse_file(argv[1], &config, &error);
        if (status != APEX_CONFIG_OK) {
            print_config_error(&error);
            return 1;
        }

        print_config_summary(config);

        apex_app_t *app = apex_create();
        if (app == NULL) {
            apex_config_free(config);
            fprintf(stderr, "cannot allocate app\n");
            return 1;
        }

        status = apex_app_attach_config(app, config, &error);
        if (status != 0) {
            print_config_error(&error);
            apex_config_free(config);
            apex_destroy(app);
            return 1;
        }

        status = apex_run(app, 0);
        apex_destroy(app);
        return status == 0 ? 0 : 1;
    }

    usage(argv[0]);
    return 1;
}
