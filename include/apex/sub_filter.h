#ifndef APEX_SUB_FILTER_H
#define APEX_SUB_FILTER_H

#include "apex/config.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Resolve effective cookie domain and path rewrite rules for the given location/server/http.
 */
void apex_cookie_rules_get(const apex_server_config_t *server,
                           const apex_location_config_t *location,
                           const apex_http_config_t *http,
                           const apex_cookie_domain_rule_t **out_domains, size_t *out_domain_count,
                           const apex_cookie_path_rule_t **out_paths, size_t *out_path_count);

/**
 * Rewrite a single Set-Cookie header line according to configured domain and path rules.
 * Returns true if modified; false if unchanged or error.
 */
bool apex_cookie_rewrite_line(const char *line, size_t line_length,
                              const apex_cookie_domain_rule_t *domains, size_t domain_count,
                              const apex_cookie_path_rule_t *paths, size_t path_count,
                              char *out_buf, size_t out_capacity, size_t *out_len);

/**
 * Resolve effective sub_filter configuration across location, server, and http blocks.
 */
const apex_sub_filter_config_t *apex_sub_filter_get(const apex_server_config_t *server,
                                                    const apex_location_config_t *location,
                                                    const apex_http_config_t *http);

/**
 * Apply sub_filter replacements to response body.
 * If replacements occurred, *out_body will point to a newly malloc'd buffer and *out_len to its size, returning true.
 * Returns false if no replacements made (or not eligible).
 */
bool apex_sub_filter_apply(const apex_sub_filter_config_t *sub,
                           const char *response_headers, size_t response_headers_len,
                           int status,
                           const void *in_body, size_t in_len,
                           void **out_body, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* APEX_SUB_FILTER_H */
