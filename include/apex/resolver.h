#ifndef APEX_RESOLVER_H
#define APEX_RESOLVER_H

#include "apex/config.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Flush all entries in the DNS cache.
 */
void apex_dns_cache_flush(void);

/**
 * Check if a host string is a numeric IPv4 or IPv6 address.
 */
bool apex_dns_is_numeric_ip(const char *host);

/**
 * Resolve a host and port to a sockaddr_storage address and textual IP representation.
 * Queries in-memory DNS cache first, then configured custom DNS resolvers via UDP RFC 1035,
 * falling back to getaddrinfo.
 *
 * Returns 0 on success, -1 on resolution failure.
 */
int apex_dns_resolve(const char *host, uint16_t port,
                     const apex_resolver_config_t *resolver,
                     struct sockaddr_storage *out_addr, socklen_t *out_len,
                     char *out_ip, size_t out_ip_cap);

#ifdef __cplusplus
}
#endif

#endif /* APEX_RESOLVER_H */
