#include "apex/ratelimit.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct rate_entry {
    char key[128];
    uint64_t last_time_us;
    double tokens;
    int32_t active_conns;
    struct rate_entry *next;
} rate_entry_t;

typedef struct {
    pthread_mutex_t lock;
    rate_entry_t *head;
    size_t count;
} rate_shard_t;

typedef struct {
    rate_shard_t shards[APEX_RATELIMIT_SHARDS];
} rate_limiter_t;

static inline uint64_t ratelimit_monotonic_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static inline uint32_t ratelimit_hash(const char *zone, const char *key) {
    uint32_t h = 2166136261u;
    if (zone != NULL) {
        for (const char *p = zone; *p; p++) {
            h ^= (uint8_t)*p;
            h *= 16777619u;
        }
    }
    h ^= 0x5c;
    h *= 16777619u;
    if (key != NULL) {
        for (const char *p = key; *p; p++) {
            h ^= (uint8_t)*p;
            h *= 16777619u;
        }
    }
    return h;
}

void *apex_ratelimit_create(const apex_config_t *config) {
    if (config == NULL) {
        return NULL;
    }
    if (config->http.rate_zone_count == 0 && config->http.conn_zone_count == 0) {
        return NULL;
    }

    rate_limiter_t *limiter = calloc(1, sizeof(*limiter));
    if (limiter == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < APEX_RATELIMIT_SHARDS; i++) {
        pthread_mutex_init(&limiter->shards[i].lock, NULL);
    }
    return limiter;
}

void apex_ratelimit_destroy(void *limiter_ptr) {
    if (limiter_ptr == NULL) {
        return;
    }
    rate_limiter_t *limiter = (rate_limiter_t *)limiter_ptr;
    for (size_t i = 0; i < APEX_RATELIMIT_SHARDS; i++) {
        pthread_mutex_destroy(&limiter->shards[i].lock);
        rate_entry_t *entry = limiter->shards[i].head;
        while (entry != NULL) {
            rate_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
    }
    free(limiter);
}

bool apex_rate_limit_check(const apex_runtime_t *runtime, const char *zone_name, const char *client_ip,
                           uint32_t burst, bool nodelay, uint32_t *retry_after_sec) {
    (void)nodelay;
    if (runtime == NULL || runtime->config == NULL || zone_name == NULL || zone_name[0] == '\0') {
        return true;
    }
    if (runtime->rate_limiter == NULL) {
        return true;
    }

    const apex_rate_limit_zone_t *zone = NULL;
    for (size_t i = 0; i < runtime->config->http.rate_zone_count; i++) {
        if (strcmp(runtime->config->http.rate_zones[i].name, zone_name) == 0) {
            zone = &runtime->config->http.rate_zones[i];
            break;
        }
    }
    if (zone == NULL || zone->rate_per_sec <= 0.0) {
        return true;
    }

    char key_buf[128];
    snprintf(key_buf, sizeof(key_buf), "%s:%s", zone_name,
             client_ip != NULL && client_ip[0] != '\0' ? client_ip : "127.0.0.1");

    rate_limiter_t *limiter = (rate_limiter_t *)runtime->rate_limiter;
    uint32_t shard_idx = ratelimit_hash(zone_name, client_ip) % APEX_RATELIMIT_SHARDS;
    rate_shard_t *shard = &limiter->shards[shard_idx];

    uint64_t now_us = ratelimit_monotonic_us();
    uint64_t ttl_us = (shard->count > APEX_RATELIMIT_MAX_ENTRIES_PER_SHARD)
                          ? APEX_RATELIMIT_EMERGENCY_TTL_US
                          : APEX_RATELIMIT_IDLE_TTL_US;

    pthread_mutex_lock(&shard->lock);
    rate_entry_t **curr = &shard->head;
    rate_entry_t *entry = NULL;
    while (*curr != NULL) {
        rate_entry_t *item = *curr;
        if (strcmp(item->key, key_buf) == 0) {
            entry = item;
            curr = &item->next;
        } else if (item->active_conns <= 0 && (now_us > item->last_time_us) &&
                   (now_us - item->last_time_us > ttl_us)) {
            *curr = item->next;
            free(item);
            if (shard->count > 0) {
                shard->count--;
            }
        } else {
            curr = &item->next;
        }
    }

    if (entry == NULL) {
        if (shard->count >= APEX_RATELIMIT_MAX_ENTRIES_PER_SHARD) {
            rate_entry_t **scan = &shard->head;
            while (*scan != NULL) {
                rate_entry_t *cand = *scan;
                if (cand->active_conns <= 0) {
                    *scan = cand->next;
                    free(cand);
                    shard->count--;
                    break;
                }
                scan = &cand->next;
            }
        }

        entry = calloc(1, sizeof(*entry));
        if (entry == NULL) {
            pthread_mutex_unlock(&shard->lock);
            return true;
        }
        snprintf(entry->key, sizeof(entry->key), "%s", key_buf);
        entry->last_time_us = now_us;
        entry->tokens = 1.0 + (double)burst;
        entry->next = shard->head;
        shard->head = entry;
        shard->count++;
    }

    double elapsed_sec = (now_us >= entry->last_time_us) ? (double)(now_us - entry->last_time_us) / 1000000.0 : 0.0;
    entry->last_time_us = now_us;

    double max_tokens = 1.0 + (double)burst;
    entry->tokens += elapsed_sec * zone->rate_per_sec;
    if (entry->tokens > max_tokens) {
        entry->tokens = max_tokens;
    }

    if (entry->tokens >= 1.0) {
        entry->tokens -= 1.0;
        pthread_mutex_unlock(&shard->lock);
        return true;
    }

    if (retry_after_sec != NULL) {
        double needed = 1.0 - entry->tokens;
        double wait_sec = needed / zone->rate_per_sec;
        *retry_after_sec = (uint32_t)(wait_sec < 1.0 ? 1 : (uint32_t)(wait_sec + 0.999));
    }
    pthread_mutex_unlock(&shard->lock);
    return false;
}

bool apex_conn_limit_acquire(const apex_runtime_t *runtime, const char *zone_name, const char *client_ip,
                             uint32_t max_conns) {
    if (runtime == NULL || runtime->config == NULL || zone_name == NULL || zone_name[0] == '\0') {
        return true;
    }
    if (runtime->rate_limiter == NULL) {
        return true;
    }

    const apex_conn_limit_zone_t *zone = NULL;
    for (size_t i = 0; i < runtime->config->http.conn_zone_count; i++) {
        if (strcmp(runtime->config->http.conn_zones[i].name, zone_name) == 0) {
            zone = &runtime->config->http.conn_zones[i];
            break;
        }
    }
    if (zone == NULL) {
        return true;
    }

    char key_buf[128];
    snprintf(key_buf, sizeof(key_buf), "%s:%s", zone_name,
             client_ip != NULL && client_ip[0] != '\0' ? client_ip : "127.0.0.1");

    rate_limiter_t *limiter = (rate_limiter_t *)runtime->rate_limiter;
    uint32_t shard_idx = ratelimit_hash(zone_name, client_ip) % APEX_RATELIMIT_SHARDS;
    rate_shard_t *shard = &limiter->shards[shard_idx];

    uint64_t now_us = ratelimit_monotonic_us();
    uint64_t ttl_us = (shard->count > APEX_RATELIMIT_MAX_ENTRIES_PER_SHARD)
                          ? APEX_RATELIMIT_EMERGENCY_TTL_US
                          : APEX_RATELIMIT_IDLE_TTL_US;

    pthread_mutex_lock(&shard->lock);
    rate_entry_t **curr = &shard->head;
    rate_entry_t *entry = NULL;
    while (*curr != NULL) {
        rate_entry_t *item = *curr;
        if (strcmp(item->key, key_buf) == 0) {
            entry = item;
            curr = &item->next;
        } else if (item->active_conns <= 0 && (now_us > item->last_time_us) &&
                   (now_us - item->last_time_us > ttl_us)) {
            *curr = item->next;
            free(item);
            if (shard->count > 0) {
                shard->count--;
            }
        } else {
            curr = &item->next;
        }
    }

    if (entry == NULL) {
        if (shard->count >= APEX_RATELIMIT_MAX_ENTRIES_PER_SHARD) {
            rate_entry_t **scan = &shard->head;
            while (*scan != NULL) {
                rate_entry_t *cand = *scan;
                if (cand->active_conns <= 0) {
                    *scan = cand->next;
                    free(cand);
                    shard->count--;
                    break;
                }
                scan = &cand->next;
            }
        }

        entry = calloc(1, sizeof(*entry));
        if (entry == NULL) {
            pthread_mutex_unlock(&shard->lock);
            return true;
        }
        snprintf(entry->key, sizeof(entry->key), "%s", key_buf);
        entry->last_time_us = now_us;
        entry->tokens = 0;
        entry->active_conns = 0;
        entry->next = shard->head;
        shard->head = entry;
        shard->count++;
    }

    entry->last_time_us = now_us;
    if ((uint32_t)entry->active_conns >= max_conns) {
        pthread_mutex_unlock(&shard->lock);
        return false;
    }

    entry->active_conns++;
    pthread_mutex_unlock(&shard->lock);
    return true;
}

void apex_conn_limit_release(const apex_runtime_t *runtime, const char *zone_name, const char *client_ip) {
    if (runtime == NULL || zone_name == NULL || zone_name[0] == '\0') {
        return;
    }
    if (runtime->rate_limiter == NULL) {
        return;
    }

    char key_buf[128];
    snprintf(key_buf, sizeof(key_buf), "%s:%s", zone_name,
             client_ip != NULL && client_ip[0] != '\0' ? client_ip : "127.0.0.1");

    rate_limiter_t *limiter = (rate_limiter_t *)runtime->rate_limiter;
    uint32_t shard_idx = ratelimit_hash(zone_name, client_ip) % APEX_RATELIMIT_SHARDS;
    rate_shard_t *shard = &limiter->shards[shard_idx];

    pthread_mutex_lock(&shard->lock);
    for (rate_entry_t *entry = shard->head; entry != NULL; entry = entry->next) {
        if (strcmp(entry->key, key_buf) == 0) {
            if (entry->active_conns > 0) {
                entry->active_conns--;
            }
            entry->last_time_us = ratelimit_monotonic_us();
            break;
        }
    }
    pthread_mutex_unlock(&shard->lock);
}
