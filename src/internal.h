#ifndef APEX_INTERNAL_H
#define APEX_INTERNAL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "apex.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>

#define MAX_FDS 65536
#define MAX_EVENTS 512
#define BUF_SIZE 4096
#define MAX_ROUTES 128

typedef struct conn {
    int fd;
    uint8_t active;
    uint32_t read_length;
    uint32_t write_length;
    uint32_t write_offset;
    uint8_t close_after_write;
    uint8_t epollout_active;
    char read_buffer[BUF_SIZE];
    char write_buffer[BUF_SIZE];
    char *aux_buffer;
    size_t aux_length;
    size_t aux_offset;
} conn_t;

void apex_conn_write(conn_t *connection, const void *data, size_t length);

struct apex_res {
    conn_t *conn;
};

typedef struct {
    char method[8];
    char pattern[128];
    size_t pattern_len;
    int is_param;
    size_t prefix_len;
    apex_handler_t handler;
} apex_route_t;

typedef struct {
    _Atomic unsigned references;
    apex_config_t *config;
    apex_runtime_t *runtime;
} apex_generation_t;

apex_generation_t *apex_generation_create(apex_config_t *config, apex_config_error_t *error);
void apex_generation_retain(apex_generation_t *generation);
void apex_generation_release(apex_generation_t *generation);

struct apex_app {
    apex_route_t routes[MAX_ROUTES];
    size_t route_count;
    apex_handler_t fast_get_root;
    apex_handler_t fast_get_user_id;
    apex_handler_t fast_post_user;
    apex_generation_t *generation;
    _Atomic bool running;
};

void apex_dispatch(apex_app_t *app, const char *req_buf, size_t header_len, const char *body, size_t body_len,
                   apex_res_t *res);
void apex_dispatch_runtime(apex_app_t *app, const apex_runtime_t *runtime, const char *req_buf, size_t header_len,
                           const char *body, size_t body_len, apex_res_t *res);

#endif /* APEX_INTERNAL_H */
