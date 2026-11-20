#ifndef APEX_FASTCGI_H
#define APEX_FASTCGI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FCGI_VERSION_1 1

#define FCGI_BEGIN_REQUEST 1
#define FCGI_ABORT_REQUEST 2
#define FCGI_END_REQUEST 3
#define FCGI_PARAMS 4
#define FCGI_STDIN 5
#define FCGI_STDOUT 6
#define FCGI_STDERR 7
#define FCGI_DATA 8
#define FCGI_GET_VALUES 9
#define FCGI_GET_VALUES_RESULT 10
#define FCGI_UNKNOWN_TYPE 11

#define FCGI_RESPONDER 1
#define FCGI_AUTHORIZER 2
#define FCGI_FILTER 3

#define FCGI_KEEP_CONN 1

#define FCGI_REQUEST_COMPLETE 0
#define FCGI_CANT_MPX_CONN 1
#define FCGI_OVERLOADED 2
#define FCGI_UNKNOWN_ROLE 3

#define FCGI_HEADER_LEN 8

typedef struct {
    uint8_t version;
    uint8_t type;
    uint8_t request_id_b1;
    uint8_t request_id_b0;
    uint8_t content_length_b1;
    uint8_t content_length_b0;
    uint8_t padding_length;
    uint8_t reserved;
} __attribute__((packed)) fcgi_header_t;

typedef struct {
    uint8_t role_b1;
    uint8_t role_b0;
    uint8_t flags;
    uint8_t reserved[5];
} __attribute__((packed)) fcgi_begin_request_body_t;

typedef struct {
    uint8_t app_status_b3;
    uint8_t app_status_b2;
    uint8_t app_status_b1;
    uint8_t app_status_b0;
    uint8_t protocol_status;
    uint8_t reserved[3];
} __attribute__((packed)) fcgi_end_request_body_t;

typedef struct {
    const char *target;         /* "127.0.0.1:9000" or "unix:/path/to/sock" */
    const char *method;
    const char *uri;
    const char *script_filename;
    const char *script_name;
    const char *query_string;
    const char *document_root;
    const char *client_ip;
    uint16_t client_port;
    const char *server_addr;
    uint16_t server_port;
    const char *server_name;
    const char *raw_request;
    size_t raw_request_len;
    const char *body;
    size_t body_len;
    uint64_t connect_timeout_ms;
    uint64_t read_timeout_ms;
} apex_fastcgi_request_t;

typedef struct {
    int status;
    char status_text[64];
    char *headers;
    size_t headers_len;
    char *body;
    size_t body_len;
    uint64_t elapsed_us;
} apex_fastcgi_response_t;

void apex_fastcgi_response_free(apex_fastcgi_response_t *resp);

/*
 * Forwards request to FastCGI backend (TCP or Unix socket).
 * Returns 0 on success, negative error code on failure.
 */
int apex_fastcgi_forward(const apex_fastcgi_request_t *req, apex_fastcgi_response_t *resp);

#ifdef __cplusplus
}
#endif

#endif /* APEX_FASTCGI_H */
