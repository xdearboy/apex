#ifndef APEX_QUIC_H
#define APEX_QUIC_H

#include "apex/config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct worker_arg worker_arg_t;
typedef struct apex_listener_endpoint apex_listener_endpoint_t;
typedef struct apex_quic_server apex_quic_server_t;

/**
 * Initialize global QUIC crypto subsystems (OpenSSL QUIC TLS backend).
 * Safe to call multiple times.
 */
int apex_quic_init(void);

/**
 * Create a QUIC/HTTP/3 server instance bound to the provided non-blocking UDP socket.
 */
apex_quic_server_t *apex_quic_server_create(worker_arg_t *worker, int udp_fd,
                                           const apex_listener_endpoint_t *ep);

/**
 * Destroy a QUIC/HTTP/3 server instance and all active connections/streams.
 */
void apex_quic_server_destroy(apex_quic_server_t *server);

/**
 * Process readable datagrams on the UDP listener socket.
 */
void apex_quic_process_read(apex_quic_server_t *server);

#ifdef __cplusplus
}
#endif

#endif /* APEX_QUIC_H */
