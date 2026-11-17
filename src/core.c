#include "internal.h"

typedef struct {
    int thread_id;
    int port;
    int nprocs;
    apex_app_t *app;
} worker_arg_t;

static inline void close_conn(int epoll_fd, conn_t *connection) {
    free(connection->aux_buffer);
    connection->aux_buffer = NULL;
    connection->aux_length = 0;
    connection->aux_offset = 0;

    if (connection->fd >= 0) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, connection->fd, NULL);
        close(connection->fd);
        connection->fd = -1;
        connection->read_length = 0;
        connection->write_length = 0;
        connection->write_offset = 0;
        connection->close_after_write = 0;
        connection->epollout_active = 0;
    }
}

void apex_conn_write(conn_t *connection, const void *data, size_t length) {
    if (connection == NULL || data == NULL || length == 0) {
        return;
    }

    bool aux_pending = connection->aux_length > connection->aux_offset;

    if (!aux_pending && length <= sizeof(connection->write_buffer) - connection->write_length) {
        memcpy(connection->write_buffer + connection->write_length, data, length);
        connection->write_length += (uint32_t)length;
        return;
    }

    if (length > SIZE_MAX - connection->aux_length) {
        connection->close_after_write = 1;
        return;
    }

    char *grown = realloc(connection->aux_buffer, connection->aux_length + length);
    if (grown == NULL) {
        connection->close_after_write = 1;
        return;
    }
    connection->aux_buffer = grown;
    memcpy(connection->aux_buffer + connection->aux_length, data, length);
    connection->aux_length += length;
}

static inline void flush_write(int epoll_fd, conn_t *connection) {
    while (connection->fd >= 0) {
        ssize_t bytes_sent = 0;

        if (connection->write_length > connection->write_offset) {
            size_t bytes_to_send = connection->write_length - connection->write_offset;
            bytes_sent = send(connection->fd, connection->write_buffer + connection->write_offset, bytes_to_send,
                              MSG_NOSIGNAL);
            if (bytes_sent > 0) {
                connection->write_offset += (uint32_t)bytes_sent;
                if (connection->write_offset == connection->write_length) {
                    connection->write_offset = 0;
                    connection->write_length = 0;
                }
            }
        } else if (connection->aux_length > connection->aux_offset) {
            size_t bytes_to_send = connection->aux_length - connection->aux_offset;
            bytes_sent = send(connection->fd, connection->aux_buffer + connection->aux_offset, bytes_to_send,
                              MSG_NOSIGNAL);
            if (bytes_sent > 0) {
                connection->aux_offset += (size_t)bytes_sent;
                if (connection->aux_offset == connection->aux_length) {
                    free(connection->aux_buffer);
                    connection->aux_buffer = NULL;
                    connection->aux_length = 0;
                    connection->aux_offset = 0;
                }
            }
        } else {
            break;
        }

        if (bytes_sent > 0 || (bytes_sent < 0 && errno == EINTR)) {
            continue;
        }
        if (bytes_sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        close_conn(epoll_fd, connection);
        return;
    }

    if (connection->fd < 0) {
        return;
    }

    bool pending = connection->write_length > connection->write_offset ||
                   connection->aux_length > connection->aux_offset;

    if (!pending && connection->close_after_write) {
        close_conn(epoll_fd, connection);
        return;
    }

    if (pending && !connection->epollout_active) {
        struct epoll_event event_config;
        event_config.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;
        event_config.data.fd = connection->fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, connection->fd, &event_config);
        connection->epollout_active = 1;
    } else if (!pending && connection->epollout_active) {
        struct epoll_event event_config;
        event_config.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
        event_config.data.fd = connection->fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, connection->fd, &event_config);
        connection->epollout_active = 0;
    }
}

static void *worker_main(void *arg) {
    worker_arg_t *worker_arg = (worker_arg_t *)arg;
    int thread_id = worker_arg->thread_id;
    int port = worker_arg->port;
    apex_app_t *app = worker_arg->app;
    int process_count = worker_arg->nprocs;

    if (process_count > 0) {
        cpu_set_t cpu_affinity_set;
        CPU_ZERO(&cpu_affinity_set);
        CPU_SET(thread_id % process_count, &cpu_affinity_set);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_affinity_set), &cpu_affinity_set);
    }

    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        return NULL;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listen_fd < 0) {
        perror("socket");
        close(epoll_fd);
        return NULL;
    }

    int socket_option_enable = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &socket_option_enable, sizeof(socket_option_enable));
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &socket_option_enable, sizeof(socket_option_enable));
    setsockopt(listen_fd, IPPROTO_TCP, TCP_NODELAY, &socket_option_enable, sizeof(socket_option_enable));
    setsockopt(listen_fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &socket_option_enable, sizeof(socket_option_enable));

    struct sockaddr_in socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sin_family = AF_INET;
    socket_address.sin_port = htons((uint16_t)port);
    socket_address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_fd, (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0) {
        perror("bind");
        close(listen_fd);
        close(epoll_fd);
        return NULL;
    }

    if (listen(listen_fd, 65535) < 0) {
        perror("listen");
        close(listen_fd);
        close(epoll_fd);
        return NULL;
    }

    struct epoll_event listen_event;
    listen_event.events = EPOLLIN | EPOLLET;
    listen_event.data.fd = listen_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &listen_event) < 0) {
        perror("epoll_ctl listen_fd");
        close(listen_fd);
        close(epoll_fd);
        return NULL;
    }

    conn_t *connections =
        (conn_t *)mmap(NULL, sizeof(conn_t) * MAX_FDS, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (connections == MAP_FAILED) {
        perror("mmap");
        close(listen_fd);
        close(epoll_fd);
        return NULL;
    }

    for (int fd_index = 0; fd_index < MAX_FDS; fd_index++) {
        connections[fd_index].fd = -1;
    }

    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int ready_events_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (ready_events_count < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        for (int event_index = 0; event_index < ready_events_count; event_index++) {
            int active_fd = events[event_index].data.fd;
            uint32_t active_event_flags = events[event_index].events;

            if (active_fd == listen_fd) {
                while (1) {
                    int client_socket_fd = accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
                    if (client_socket_fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        break;
                    }

                    if (client_socket_fd >= MAX_FDS) {
                        close(client_socket_fd);
                        continue;
                    }

                    int tcp_flag = 1;
                    setsockopt(client_socket_fd, IPPROTO_TCP, TCP_NODELAY, &tcp_flag, sizeof(tcp_flag));
                    setsockopt(client_socket_fd, IPPROTO_TCP, TCP_QUICKACK, &tcp_flag, sizeof(tcp_flag));
                    setsockopt(client_socket_fd, SOL_SOCKET, SO_KEEPALIVE, &tcp_flag, sizeof(tcp_flag));
#if defined(TCP_KEEPIDLE)
                    int keepalive_idle_seconds = 15;
                    setsockopt(client_socket_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_idle_seconds,
                               sizeof(keepalive_idle_seconds));
#endif
#if defined(TCP_KEEPINTVL)
                    int keepalive_interval_seconds = 5;
                    setsockopt(client_socket_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_interval_seconds,
                               sizeof(keepalive_interval_seconds));
#endif
#if defined(TCP_KEEPCNT)
                    int keepalive_probes_count = 3;
                    setsockopt(client_socket_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_probes_count,
                               sizeof(keepalive_probes_count));
#endif
#if defined(TCP_USER_TIMEOUT)
                    unsigned int user_timeout_milliseconds = 15000;
                    setsockopt(client_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_milliseconds,
                               sizeof(user_timeout_milliseconds));
#endif

                    conn_t *client_connection = &connections[client_socket_fd];
                    client_connection->fd = client_socket_fd;
                    client_connection->read_length = 0;
                    client_connection->write_length = 0;
                    client_connection->write_offset = 0;
                    client_connection->close_after_write = 0;
                    client_connection->epollout_active = 0;
                    client_connection->aux_buffer = NULL;
                    client_connection->aux_length = 0;
                    client_connection->aux_offset = 0;

                    struct epoll_event client_event;
                    client_event.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
                    client_event.data.fd = client_socket_fd;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_socket_fd, &client_event);
                }
                continue;
            }

            conn_t *connection = &connections[active_fd];
            if (connection->fd < 0) {
                continue;
            }

            if (active_event_flags & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
                close_conn(epoll_fd, connection);
                continue;
            }

            if (active_event_flags & EPOLLIN) {
                while (1) {
                    ssize_t bytes_received = recv(connection->fd, connection->read_buffer + connection->read_length,
                                                  sizeof(connection->read_buffer) - connection->read_length, 0);
                    if (bytes_received > 0) {
                        connection->read_length += (uint32_t)bytes_received;
                        if (memmem(connection->read_buffer, connection->read_length, "\r\n\r\n", 4)) {
                            break;
                        }
                    } else if (bytes_received == 0) {
                        close_conn(epoll_fd, connection);
                        goto next_event;
                    } else {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        close_conn(epoll_fd, connection);
                        goto next_event;
                    }

                    if (connection->read_length == sizeof(connection->read_buffer)) {
                        break;
                    }
                }

                char *buffer_cursor = connection->read_buffer;
                size_t remaining_bytes = connection->read_length;

                while (remaining_bytes >= 4) {
                    char *crlf_delimiter = (char *)memmem(buffer_cursor, remaining_bytes, "\r\n\r\n", 4);
                    if (!crlf_delimiter) {
                        break;
                    }

                    size_t header_length = (size_t)((crlf_delimiter + 4) - buffer_cursor);
                    size_t content_length = 0;

                    if (buffer_cursor[0] == 'P' && buffer_cursor[1] == 'O' && buffer_cursor[2] == 'S' &&
                        buffer_cursor[3] == 'T') {
                        char *content_length_header =
                            (char *)memmem(buffer_cursor, header_length, "Content-Length:", 15);
                        if (!content_length_header) {
                            content_length_header = (char *)memmem(buffer_cursor, header_length, "content-length:", 15);
                        }
                        if (content_length_header) {
                            content_length = strtoul(content_length_header + 15, NULL, 10);
                        }
                    }

                    if (remaining_bytes < header_length + content_length) {
                        break;
                    }

                    if (memmem(buffer_cursor, header_length, "close", 5)) {
                        connection->close_after_write = 1;
                    }

                    apex_res_t response = {.conn = connection};
                    apex_dispatch(app, buffer_cursor, header_length, buffer_cursor + header_length, content_length,
                                  &response);

                    size_t total_request_length = header_length + content_length;
                    buffer_cursor += total_request_length;
                    remaining_bytes -= total_request_length;
                }

                if (remaining_bytes > 0 && buffer_cursor != connection->read_buffer) {
                    memmove(connection->read_buffer, buffer_cursor, remaining_bytes);
                }
                connection->read_length = (uint32_t)remaining_bytes;

                flush_write(epoll_fd, connection);
            }

            if ((active_event_flags & EPOLLOUT) && connection->fd >= 0) {
                flush_write(epoll_fd, connection);
            }

        next_event:;
        }
    }

    munmap(connections, sizeof(conn_t) * MAX_FDS);
    close(listen_fd);
    close(epoll_fd);
    return NULL;
}

static void apex_handle_sig(int sig) {
    (void)sig;
    _exit(0);
}

int apex_run(apex_app_t *app, int port) {
    signal(SIGINT, apex_handle_sig);
    signal(SIGTERM, apex_handle_sig);
    signal(SIGPIPE, SIG_IGN);

    if (port <= 0 && app != NULL && app->owned_config != NULL) {
        int configured_port = apex_config_first_listen_port(app->owned_config);
        if (configured_port > 0) {
            port = configured_port;
        }
    }
    if (port <= 0) {
        port = 8080;
    }

    const char *port_env = getenv("PORT");
    if (port_env) {
        int p = atoi(port_env);
        if (p > 0)
            port = p;
    }

    int nprocs = get_nprocs();
    if (nprocs <= 0) {
        nprocs = 1;
    }

    pthread_t *threads = (pthread_t *)calloc((size_t)nprocs, sizeof(pthread_t));
    worker_arg_t *args = (worker_arg_t *)calloc((size_t)nprocs, sizeof(worker_arg_t));
    if (!threads || !args) {
        fprintf(stderr, "Memory allocation error\n");
        return 1;
    }

    for (int i = 0; i < nprocs; i++) {
        args[i].thread_id = i;
        args[i].port = port;
        args[i].nprocs = nprocs;
        args[i].app = app;
        if (pthread_create(&threads[i], NULL, worker_main, &args[i]) != 0) {
            fprintf(stderr, "Failed to create worker thread %d\n", i);
            return 1;
        }
    }

    for (int i = 0; i < nprocs; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    free(args);
    return 0;
}
