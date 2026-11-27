#ifndef APEX_WEBSOCKET_H
#define APEX_WEBSOCKET_H

#include "internal.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Bidirectional proxy tunnel for WebSocket connections.
 */
void apex_proxy_ws_tunnel(conn_t *client_conn, int upstream_fd, void *upstream_ssl,
                          void *upstream_server, uint64_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* APEX_WEBSOCKET_H */
