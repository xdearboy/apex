#ifndef APEX_RATELIMIT_H
#define APEX_RATELIMIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "apex/config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define APEX_RATELIMIT_SHARDS 1024u
#define APEX_RATELIMIT_MAX_ENTRIES_PER_SHARD 2048u
#define APEX_RATELIMIT_IDLE_TTL_US 60000000ULL       /* 60 seconds */
#define APEX_RATELIMIT_EMERGENCY_TTL_US 5000000ULL   /* 5 seconds under pressure */

/**
 * Allocate and initialize a thread-safe sharded rate and connection limiter.
 * Returns opaque pointer or NULL if no zones configured or on allocation error.
 */
void *apex_ratelimit_create(const apex_config_t *config);

/**
 * Clean up and free all shards, locks, and active entry chains.
 */
void apex_ratelimit_destroy(void *limiter_ptr);

#ifdef __cplusplus
}
#endif

#endif /* APEX_RATELIMIT_H */
