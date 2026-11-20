#ifndef APEX_CACHE_H
#define APEX_CACHE_H

#include "apex/config.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct apex_cache_manager apex_cache_manager_t;

typedef struct {
    int status;
    char *headers;
    size_t headers_len;
    char *body;
    size_t body_len;
    uint64_t expires_at_ms;
} apex_cached_response_t;

apex_cache_manager_t *apex_cache_manager_create(const apex_config_t *config);
void apex_cache_manager_destroy(apex_cache_manager_t *manager);

bool apex_cache_lookup(apex_cache_manager_t *manager, const char *zone_name,
                       const char *key, apex_cached_response_t *cached);

void apex_cached_response_free(apex_cached_response_t *cached);

bool apex_cache_store(apex_cache_manager_t *manager, const char *zone_name,
                      const char *key, int status, const char *headers, size_t headers_len,
                      const char *body, size_t body_len, uint64_t valid_ms);

bool apex_cache_purge(apex_cache_manager_t *manager, const char *zone_name, const char *key);

uint64_t apex_cache_evaluate_validity(const char *headers, size_t headers_len, int status,
                                      const apex_cache_valid_rule_t *rules, size_t rule_count);

#ifdef __cplusplus
}
#endif

#endif /* APEX_CACHE_H */
