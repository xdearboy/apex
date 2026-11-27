#include "apex/resolver.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <openssl/rand.h>

#define APEX_DNS_CACHE_MAX_ENTRIES 256

typedef struct {
    char host[256];
    struct sockaddr_storage address;
    socklen_t address_len;
    char ip[64];
    uint64_t expires_at_ms;
    bool in_use;
} apex_dns_cache_entry_t;

typedef struct {
    pthread_mutex_t lock;
    apex_dns_cache_entry_t entries[APEX_DNS_CACHE_MAX_ENTRIES];
} apex_dns_cache_t;

static apex_dns_cache_t g_dns_cache = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

static inline uint64_t resolver_monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static inline uint64_t resolver_monotonic_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

void apex_dns_cache_flush(void) {
    pthread_mutex_lock(&g_dns_cache.lock);
    memset(g_dns_cache.entries, 0, sizeof(g_dns_cache.entries));
    pthread_mutex_unlock(&g_dns_cache.lock);
}

bool apex_dns_is_numeric_ip(const char *host) {
    if (host == NULL || host[0] == '\0') {
        return false;
    }
    struct in_addr addr4;
    if (inet_pton(AF_INET, host, &addr4) == 1) return true;
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, host, &addr6) == 1) return true;
    return false;
}

static bool dns_cache_lookup(const char *host, struct sockaddr_storage *out_addr,
                             socklen_t *out_len, char *out_ip, size_t out_ip_cap) {
    uint64_t now = resolver_monotonic_ms();
    pthread_mutex_lock(&g_dns_cache.lock);
    for (size_t i = 0; i < APEX_DNS_CACHE_MAX_ENTRIES; i++) {
        if (g_dns_cache.entries[i].in_use && strcmp(g_dns_cache.entries[i].host, host) == 0) {
            if (now < g_dns_cache.entries[i].expires_at_ms) {
                *out_addr = g_dns_cache.entries[i].address;
                *out_len = g_dns_cache.entries[i].address_len;
                if (out_ip != NULL && out_ip_cap > 0) {
                    snprintf(out_ip, out_ip_cap, "%s", g_dns_cache.entries[i].ip);
                }
                pthread_mutex_unlock(&g_dns_cache.lock);
                return true;
            } else {
                g_dns_cache.entries[i].in_use = false;
                break;
            }
        }
    }
    pthread_mutex_unlock(&g_dns_cache.lock);
    return false;
}

static void dns_cache_insert(const char *host, const struct sockaddr_storage *addr,
                             socklen_t addr_len, const char *ip, uint32_t ttl_ms) {
    uint64_t now = resolver_monotonic_ms();
    if (ttl_ms == 0) ttl_ms = 30000;
    pthread_mutex_lock(&g_dns_cache.lock);
    size_t target_idx = APEX_DNS_CACHE_MAX_ENTRIES;
    uint64_t oldest_expiry = UINT64_MAX;
    size_t oldest_idx = 0;

    for (size_t i = 0; i < APEX_DNS_CACHE_MAX_ENTRIES; i++) {
        if (g_dns_cache.entries[i].in_use && strcmp(g_dns_cache.entries[i].host, host) == 0) {
            target_idx = i;
            break;
        }
        if (!g_dns_cache.entries[i].in_use && target_idx == APEX_DNS_CACHE_MAX_ENTRIES) {
            target_idx = i;
        }
        if (g_dns_cache.entries[i].expires_at_ms < oldest_expiry) {
            oldest_expiry = g_dns_cache.entries[i].expires_at_ms;
            oldest_idx = i;
        }
    }
    if (target_idx == APEX_DNS_CACHE_MAX_ENTRIES) {
        target_idx = oldest_idx;
    }

    apex_dns_cache_entry_t *entry = &g_dns_cache.entries[target_idx];
    snprintf(entry->host, sizeof(entry->host), "%s", host);
    entry->address = *addr;
    entry->address_len = addr_len;
    snprintf(entry->ip, sizeof(entry->ip), "%s", ip);
    entry->expires_at_ms = now + (uint64_t)ttl_ms;
    entry->in_use = true;
    pthread_mutex_unlock(&g_dns_cache.lock);
}

static bool dns_query_udp(const char *dns_server, const char *host, uint32_t timeout_ms,
                          struct sockaddr_storage *out_addr, socklen_t *out_len,
                          char *out_ip, size_t out_ip_cap, uint32_t *out_ttl_ms) {
    if (dns_server == NULL || dns_server[0] == '\0' || host == NULL || host[0] == '\0') {
        return false;
    }

    char srv_host[128];
    uint16_t srv_port = 53;
    const char *colon = strchr(dns_server, ':');
    if (colon != NULL) {
        size_t hlen = (size_t)(colon - dns_server);
        if (hlen >= sizeof(srv_host)) hlen = sizeof(srv_host) - 1;
        memcpy(srv_host, dns_server, hlen);
        srv_host[hlen] = '\0';
        srv_port = (uint16_t)atoi(colon + 1);
        if (srv_port == 0) srv_port = 53;
    } else {
        snprintf(srv_host, sizeof(srv_host), "%s", dns_server);
    }

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(srv_port);
    if (inet_pton(AF_INET, srv_host, &srv_addr.sin_addr) != 1) {
        return false;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    struct timeval tv;
    tv.tv_sec = (time_t)(timeout_ms / 1000u);
    tv.tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u);
    if (tv.tv_sec == 0 && tv.tv_usec == 0) {
        tv.tv_sec = 2;
    }
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Build RFC 1035 DNS query packet */
    uint8_t packet[512];
    memset(packet, 0, sizeof(packet));

    uint16_t qid = 0;
    if (RAND_bytes((unsigned char *)&qid, sizeof(qid)) != 1) {
        qid = (uint16_t)(resolver_monotonic_us() & 0xFFFF);
    }
    packet[0] = (uint8_t)(qid >> 8);
    packet[1] = (uint8_t)(qid & 0xFF);
    packet[2] = 0x01; /* RD = 1 (recursion desired) */
    packet[3] = 0x00;
    packet[4] = 0x00; packet[5] = 0x01; /* QDCOUNT = 1 */

    size_t offset = 12;
    const char *p = host;
    while (*p != '\0') {
        const char *dot = strchr(p, '.');
        size_t label_len = dot ? (size_t)(dot - p) : strlen(p);
        if (label_len == 0 || label_len > 63 || offset + 1 + label_len + 4 >= sizeof(packet)) {
            close(fd);
            return false;
        }
        packet[offset++] = (uint8_t)label_len;
        memcpy(packet + offset, p, label_len);
        offset += label_len;
        if (!dot) break;
        p = dot + 1;
    }
    packet[offset++] = 0x00; /* End of name */
    packet[offset++] = 0x00; packet[offset++] = 0x01; /* QTYPE = A (1) */
    packet[offset++] = 0x00; packet[offset++] = 0x01; /* QCLASS = IN (1) */

    if (sendto(fd, packet, offset, 0, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        close(fd);
        return false;
    }

    uint8_t resp[512];
    ssize_t nrecv = recvfrom(fd, resp, sizeof(resp), 0, NULL, NULL);
    close(fd);

    if (nrecv < 12) return false;

    uint16_t rid = (uint16_t)((resp[0] << 8) | resp[1]);
    if (rid != qid) return false;

    uint16_t flags = (uint16_t)((resp[2] << 8) | resp[3]);
    if ((flags & 0x8000) == 0) return false; /* Not a response */
    if ((flags & 0x000F) != 0) return false; /* Error RCODE */

    uint16_t ancount = (uint16_t)((resp[6] << 8) | resp[7]);
    if (ancount == 0) return false;

    /* Skip Question section */
    size_t roff = 12;
    while (roff < (size_t)nrecv && resp[roff] != 0) {
        if ((resp[roff] & 0xC0) == 0xC0) {
            if (roff + 2 > (size_t)nrecv) return false;
            roff += 2;
            break;
        }
        size_t llen = (size_t)resp[roff];
        if (roff + 1 + llen > (size_t)nrecv) return false;
        roff += 1 + llen;
    }
    if (roff < (size_t)nrecv && resp[roff] == 0) {
        roff++;
    }
    if (roff + 4 > (size_t)nrecv) return false;
    roff += 4; /* QTYPE + QCLASS */

    /* Parse Answers */
    for (uint16_t a = 0; a < ancount && roff + 10 <= (size_t)nrecv; a++) {
        if ((resp[roff] & 0xC0) == 0xC0) {
            if (roff + 2 > (size_t)nrecv) break;
            roff += 2;
        } else {
            while (roff < (size_t)nrecv && resp[roff] != 0) {
                size_t llen = (size_t)resp[roff];
                if (roff + 1 + llen > (size_t)nrecv) break;
                roff += 1 + llen;
            }
            if (roff < (size_t)nrecv && resp[roff] == 0) roff++;
        }
        if (roff + 10 > (size_t)nrecv) break;

        uint16_t atype = (uint16_t)((resp[roff] << 8) | resp[roff + 1]);
        uint16_t aclass = (uint16_t)((resp[roff + 2] << 8) | resp[roff + 3]);
        uint32_t attl = (uint32_t)((resp[roff + 4] << 24) | (resp[roff + 5] << 16) | (resp[roff + 6] << 8) | resp[roff + 7]);
        uint16_t rdlen = (uint16_t)((resp[roff + 8] << 8) | resp[roff + 9]);
        roff += 10;

        if (atype == 1 && aclass == 1 && rdlen == 4 && roff + 4 <= (size_t)nrecv) {
            struct sockaddr_in *sin = (struct sockaddr_in *)out_addr;
            memset(sin, 0, sizeof(*sin));
            sin->sin_family = AF_INET;
            memcpy(&sin->sin_addr, resp + roff, 4);
            *out_len = sizeof(struct sockaddr_in);
            if (out_ip != NULL && out_ip_cap > 0) {
                inet_ntop(AF_INET, &sin->sin_addr, out_ip, (socklen_t)out_ip_cap);
            }
            uint32_t capped_ttl = attl > 86400u ? 86400u : attl;
            *out_ttl_ms = capped_ttl > 0 ? capped_ttl * 1000u : 30000u;
            return true;
        }
        if (roff + rdlen > (size_t)nrecv) break;
        roff += rdlen;
    }
    return false;
}

int apex_dns_resolve(const char *host, uint16_t port,
                     const apex_resolver_config_t *resolver,
                     struct sockaddr_storage *out_addr, socklen_t *out_len,
                     char *out_ip, size_t out_ip_cap) {
    if (host == NULL || host[0] == '\0' || out_addr == NULL || out_len == NULL) {
        return -1;
    }

    if (apex_dns_is_numeric_ip(host)) {
        struct in_addr addr4;
        struct in6_addr addr6;
        if (inet_pton(AF_INET, host, &addr4) == 1) {
            struct sockaddr_in *sin = (struct sockaddr_in *)out_addr;
            sin->sin_family = AF_INET;
            sin->sin_port = htons(port);
            sin->sin_addr = addr4;
            *out_len = sizeof(*sin);
            if (out_ip != NULL && out_ip_cap > 0) {
                snprintf(out_ip, out_ip_cap, "%s", host);
            }
            return 0;
        } else if (inet_pton(AF_INET6, host, &addr6) == 1) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out_addr;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = htons(port);
            sin6->sin6_addr = addr6;
            *out_len = sizeof(*sin6);
            if (out_ip != NULL && out_ip_cap > 0) {
                snprintf(out_ip, out_ip_cap, "%s", host);
            }
            return 0;
        } else {
            return -1;
        }
    }

    bool cached = dns_cache_lookup(host, out_addr, out_len, out_ip, out_ip_cap);
    if (cached) {
        if (out_addr->ss_family == AF_INET) {
            ((struct sockaddr_in *)out_addr)->sin_port = htons(port);
        } else if (out_addr->ss_family == AF_INET6) {
            ((struct sockaddr_in6 *)out_addr)->sin6_port = htons(port);
        }
        return 0;
    }

    bool resolved = false;
    uint32_t ttl_ms = 30000;
    if (resolver != NULL && resolver->is_set && resolver->server_count > 0) {
        uint32_t to = resolver->timeout_ms ? resolver->timeout_ms : 2000;
        for (size_t s = 0; s < resolver->server_count; s++) {
            if (dns_query_udp(resolver->servers[s], host, to, out_addr, out_len, out_ip, out_ip_cap, &ttl_ms)) {
                ((struct sockaddr_in *)out_addr)->sin_port = htons(port);
                resolved = true;
                break;
            }
        }
    }

    if (!resolved) {
        char service[8];
        int written = snprintf(service, sizeof(service), "%u", (unsigned int)port);
        if (written < 0 || (size_t)written >= sizeof(service)) {
            return -1;
        }

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICSERV;

        struct addrinfo *gai_res = NULL;
        if (getaddrinfo(host, service, &hints, &gai_res) != 0 || gai_res == NULL) {
            return -1;
        }

        struct addrinfo *selected = NULL;
        for (struct addrinfo *cand = gai_res; cand != NULL; cand = cand->ai_next) {
            if (cand->ai_family == AF_INET || cand->ai_family == AF_INET6) {
                selected = cand;
                break;
            }
        }

        if (selected == NULL || selected->ai_addrlen > sizeof(struct sockaddr_storage)) {
            freeaddrinfo(gai_res);
            return -1;
        }

        memcpy(out_addr, selected->ai_addr, selected->ai_addrlen);
        *out_len = (socklen_t)selected->ai_addrlen;

        if (out_ip != NULL && out_ip_cap > 0) {
            if (getnameinfo(selected->ai_addr, selected->ai_addrlen, out_ip, (socklen_t)out_ip_cap, NULL, 0, NI_NUMERICHOST) != 0) {
                snprintf(out_ip, out_ip_cap, "%s", host);
            }
        }
        freeaddrinfo(gai_res);
    }

    uint32_t final_ttl = (resolver != NULL && resolver->valid_ms > 0) ? resolver->valid_ms : ttl_ms;
    dns_cache_insert(host, out_addr, *out_len, (out_ip && out_ip[0]) ? out_ip : host, final_ttl);
    return 0;
}
