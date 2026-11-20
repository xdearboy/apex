#include "apex/realip.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

bool apex_real_ip_parse_rule(const char *text, size_t len, apex_real_ip_rule_t *rule) {
    if (text == NULL || len == 0 || rule == NULL) {
        return false;
    }
    memset(rule, 0, sizeof(*rule));

    if (len == 3 && strncmp(text, "all", 3) == 0) {
        rule->is_all = true;
        return true;
    }

    if (len >= 5 && strncmp(text, "unix:", 5) == 0) {
        /* Treat unix socket peer as localhost IPv4 */
        rule->is_ipv6 = false;
        rule->mask4.s_addr = htonl(0xFFFFFFFFU);
        rule->addr4.s_addr = htonl(0x7F000001U);
        return true;
    }

    char buf[128];
    if (len >= sizeof(buf)) {
        return false;
    }
    memcpy(buf, text, len);
    buf[len] = '\0';

    char *slash = strchr(buf, '/');
    int prefix = -1;
    if (slash != NULL) {
        *slash = '\0';
        char *endptr = NULL;
        long p = strtol(slash + 1, &endptr, 10);
        if (*endptr != '\0' || p < 0) {
            return false;
        }
        prefix = (int)p;
    }

    /* Try IPv4 */
    struct in_addr addr4;
    if (inet_pton(AF_INET, buf, &addr4) == 1) {
        rule->is_ipv6 = false;
        if (prefix < 0) {
            prefix = 32;
        }
        if (prefix > 32) {
            return false;
        }
        uint32_t mask_val = (prefix == 0) ? 0 : (uint32_t)(~0ULL << (32 - prefix));
        rule->mask4.s_addr = htonl(mask_val);
        rule->addr4.s_addr = addr4.s_addr & rule->mask4.s_addr;
        return true;
    }

    /* Try IPv6 */
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, buf, &addr6) == 1) {
        rule->is_ipv6 = true;
        if (prefix < 0) {
            prefix = 128;
        }
        if (prefix > 128) {
            return false;
        }
        memset(&rule->mask6, 0, sizeof(rule->mask6));
        int full_bytes = prefix / 8;
        int rem_bits = prefix % 8;
        for (int i = 0; i < full_bytes; i++) {
            rule->mask6.s6_addr[i] = 0xFF;
        }
        if (rem_bits > 0 && full_bytes < 16) {
            rule->mask6.s6_addr[full_bytes] = (uint8_t)(0xFF << (8 - rem_bits));
        }
        for (int i = 0; i < 16; i++) {
            rule->addr6.s6_addr[i] = addr6.s6_addr[i] & rule->mask6.s6_addr[i];
        }
        return true;
    }

    return false;
}

bool apex_real_ip_matches(const apex_real_ip_rule_t *rule, const char *ip_str) {
    if (rule == NULL || ip_str == NULL) {
        return false;
    }
    if (rule->is_all) {
        return true;
    }

    /* Handle IPv4-mapped IPv6 string e.g. ::ffff:127.0.0.1 */
    const char *eval_ip = ip_str;
    if (strncasecmp(eval_ip, "::ffff:", 7) == 0) {
        eval_ip += 7;
    }

    struct in_addr addr4;
    if (inet_pton(AF_INET, eval_ip, &addr4) == 1) {
        if (!rule->is_ipv6) {
            return (addr4.s_addr & rule->mask4.s_addr) == rule->addr4.s_addr;
        }
        return false;
    }

    struct in6_addr addr6;
    if (inet_pton(AF_INET6, eval_ip, &addr6) == 1) {
        if (rule->is_ipv6) {
            for (int i = 0; i < 16; i++) {
                if ((addr6.s6_addr[i] & rule->mask6.s6_addr[i]) != rule->addr6.s6_addr[i]) {
                    return false;
                }
            }
            return true;
        }
        /* Check if IPv4-mapped in IPv6 binary representation */
        if (IN6_IS_ADDR_V4MAPPED(&addr6)) {
            uint32_t ip4 = *(const uint32_t *)&addr6.s6_addr[12];
            return (ip4 & rule->mask4.s_addr) == rule->addr4.s_addr;
        }
        return false;
    }

    return false;
}

bool apex_real_ip_matches_any(const apex_real_ip_rule_t *rules, size_t count, const char *ip_str) {
    if (rules == NULL || count == 0 || ip_str == NULL) {
        return false;
    }
    for (size_t i = 0; i < count; i++) {
        if (apex_real_ip_matches(&rules[i], ip_str)) {
            return true;
        }
    }
    return false;
}

static bool extract_header_value(const char *raw_request, size_t raw_len,
                                 const char *header_name, char *out_val, size_t out_val_len) {
    if (raw_request == NULL || raw_len == 0 || header_name == NULL || out_val == NULL || out_val_len == 0) {
        return false;
    }
    size_t name_len = strlen(header_name);
    const char *cur = raw_request;
    const char *end = raw_request + raw_len;

    /* Skip request line */
    const char *line_end = memmem(cur, (size_t)(end - cur), "\r\n", 2);
    if (line_end == NULL) {
        return false;
    }
    cur = line_end + 2;

    while (cur < end) {
        if (cur + 2 <= end && cur[0] == '\r' && cur[1] == '\n') {
            break; /* End of headers */
        }
        const char *next_line = memmem(cur, (size_t)(end - cur), "\r\n", 2);
        size_t line_len = next_line ? (size_t)(next_line - cur) : (size_t)(end - cur);

        const char *colon = memchr(cur, ':', line_len);
        if (colon != NULL) {
            size_t hname_len = (size_t)(colon - cur);
            if (hname_len == name_len && strncasecmp(cur, header_name, name_len) == 0) {
                const char *val_start = colon + 1;
                while (val_start < cur + line_len && (*val_start == ' ' || *val_start == '\t')) {
                    val_start++;
                }
                const char *val_end = cur + line_len;
                while (val_end > val_start && (val_end[-1] == ' ' || val_end[-1] == '\t')) {
                    val_end--;
                }
                size_t val_len = (size_t)(val_end - val_start);
                if (val_len >= out_val_len) {
                    val_len = out_val_len - 1;
                }
                memcpy(out_val, val_start, val_len);
                out_val[val_len] = '\0';
                return true;
            }
        }

        if (next_line == NULL) {
            break;
        }
        cur = next_line + 2;
    }
    return false;
}

static void trim_ip_token(char *str) {
    if (str == NULL) {
        return;
    }
    char *p = str;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        p++;
    }
    if (p != str) {
        memmove(str, p, strlen(p) + 1);
    }
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\t' || str[len - 1] == '\r' || str[len - 1] == '\n')) {
        str[--len] = '\0';
    }
}

static bool is_valid_ip_string(const char *ip_str) {
    if (ip_str == NULL || ip_str[0] == '\0') {
        return false;
    }
    struct in_addr addr4;
    if (inet_pton(AF_INET, ip_str, &addr4) == 1) {
        return true;
    }
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, ip_str, &addr6) == 1) {
        return true;
    }
    return false;
}

void apex_real_ip_resolve(const apex_real_ip_rule_t *rules, size_t rule_count,
                          const char *header_name, bool recursive,
                          const char *peer_ip,
                          const char *raw_request, size_t raw_len,
                          char *out_ip, size_t out_len) {
    if (out_ip == NULL || out_len == 0) {
        return;
    }
    if (peer_ip == NULL || peer_ip[0] == '\0') {
        peer_ip = "127.0.0.1";
    }

    /* Default fallback is the direct peer IP */
    snprintf(out_ip, out_len, "%s", peer_ip);

    if (rules == NULL || rule_count == 0) {
        return;
    }

    /* Only proceed if connecting peer is in trusted proxies list */
    if (!apex_real_ip_matches_any(rules, rule_count, peer_ip)) {
        return;
    }

    const char *hdr = (header_name != NULL && header_name[0] != '\0') ? header_name : "X-Forwarded-For";

    char header_val[1024];
    if (!extract_header_value(raw_request, raw_len, hdr, header_val, sizeof(header_val))) {
        return;
    }

    if (!recursive) {
        /*
         * Non-recursive: replace client address with the last (rightmost) address
         * sent in the request header.
         */
        char *last_comma = strrchr(header_val, ',');
        char *target = last_comma ? (last_comma + 1) : header_val;
        trim_ip_token(target);
        if (is_valid_ip_string(target)) {
            snprintf(out_ip, out_len, "%s", target);
        }
        return;
    }

    /*
     * Recursive: split by comma into token array and traverse from right to left.
     * The first IP that is NOT in the trusted list is the untrusted client.
     */
    char *tokens[32];
    size_t num_tokens = 0;
    char *saveptr = NULL;
    char *tok = strtok_r(header_val, ",", &saveptr);
    while (tok != NULL && num_tokens < 32) {
        trim_ip_token(tok);
        if (is_valid_ip_string(tok)) {
            tokens[num_tokens++] = tok;
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }

    if (num_tokens == 0) {
        return;
    }

    /* Walk backwards from right to left */
    for (size_t i = num_tokens; i > 0; i--) {
        const char *cand = tokens[i - 1];
        if (!apex_real_ip_matches_any(rules, rule_count, cand)) {
            /* Found untrusted client IP! */
            snprintf(out_ip, out_len, "%s", cand);
            return;
        }
    }

    /* If all IPs in X-Forwarded-For were trusted proxies, use the leftmost one */
    snprintf(out_ip, out_len, "%s", tokens[0]);
}
