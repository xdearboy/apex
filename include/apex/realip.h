#ifndef APEX_REALIP_H
#define APEX_REALIP_H

#include "apex/config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

bool apex_real_ip_parse_rule(const char *text, size_t len, apex_real_ip_rule_t *rule);
bool apex_real_ip_matches(const apex_real_ip_rule_t *rule, const char *ip_str);
bool apex_real_ip_matches_any(const apex_real_ip_rule_t *rules, size_t count, const char *ip_str);

/*
 * Resolves the real client IP based on trusted proxy rules and configured header.
 * If peer_ip does not match any rule, peer_ip is copied into out_ip.
 * If recursive is true, traverses comma-separated lists (e.g. in X-Forwarded-For)
 * from right to left, stopping at the first untrusted IP.
 */
void apex_real_ip_resolve(const apex_real_ip_rule_t *rules, size_t rule_count,
                          const char *header_name, bool recursive,
                          const char *peer_ip,
                          const char *raw_request, size_t raw_len,
                          char *out_ip, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* APEX_REALIP_H */
