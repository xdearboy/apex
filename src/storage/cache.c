#include "apex/cache.h"
#include "internal.h"

#include <ctype.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define APEX_CACHE_SHARDS 1024
#define APEX_CACHE_BUCKETS 64

typedef struct cache_entry {
    char key[256];
    uint64_t hash;
    int status;
    char *headers;
    size_t headers_len;
    char *body;
    size_t body_len;
    size_t entry_size;
    uint64_t expires_at_ms;
    uint64_t created_at_ms;
    uint64_t last_accessed_ms;
    struct cache_entry *next_hash;
    struct cache_entry *prev_lru;
    struct cache_entry *next_lru;
} cache_entry_t;

typedef struct {
    pthread_mutex_t lock;
    cache_entry_t *buckets[APEX_CACHE_BUCKETS];
    cache_entry_t *lru_head;
    cache_entry_t *lru_tail;
    size_t shard_size;
} cache_shard_t;

typedef struct {
    char name[64];
    char path[APEX_CONFIG_PATH_MAX];
    size_t max_size;
    size_t keys_zone_size;
    uint64_t inactive_ms;
    _Atomic size_t total_size;
    cache_shard_t shards[APEX_CACHE_SHARDS];
} cache_zone_t;

struct apex_cache_manager {
    cache_zone_t *zones;
    size_t zone_count;
};

static inline uint64_t cache_hash_key(const char *key, size_t len) {
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint8_t)key[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static inline uint64_t cache_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void lru_remove(cache_shard_t *shard, cache_entry_t *entry) {
    if (entry->prev_lru != NULL) {
        entry->prev_lru->next_lru = entry->next_lru;
    } else if (shard->lru_head == entry) {
        shard->lru_head = entry->next_lru;
    }
    if (entry->next_lru != NULL) {
        entry->next_lru->prev_lru = entry->prev_lru;
    } else if (shard->lru_tail == entry) {
        shard->lru_tail = entry->prev_lru;
    }
    entry->prev_lru = NULL;
    entry->next_lru = NULL;
}

static void lru_push_head(cache_shard_t *shard, cache_entry_t *entry) {
    entry->prev_lru = NULL;
    entry->next_lru = shard->lru_head;
    if (shard->lru_head != NULL) {
        shard->lru_head->prev_lru = entry;
    } else {
        shard->lru_tail = entry;
    }
    shard->lru_head = entry;
}

static void lru_touch(cache_shard_t *shard, cache_entry_t *entry) {
    if (entry->prev_lru != NULL || entry->next_lru != NULL || shard->lru_head == entry) {
        lru_remove(shard, entry);
    }
    lru_push_head(shard, entry);
}

apex_cache_manager_t *apex_cache_manager_create(const apex_config_t *config) {
    if (config == NULL || config->http.cache_zone_count == 0) {
        return NULL;
    }
    apex_cache_manager_t *mgr = calloc(1, sizeof(*mgr));
    if (mgr == NULL) {
        return NULL;
    }
    mgr->zone_count = config->http.cache_zone_count;
    mgr->zones = calloc(mgr->zone_count, sizeof(*mgr->zones));
    if (mgr->zones == NULL) {
        free(mgr);
        return NULL;
    }
    for (size_t z = 0; z < mgr->zone_count; z++) {
        const apex_cache_zone_config_t *src_zone = &config->http.cache_zones[z];
        cache_zone_t *dst_zone = &mgr->zones[z];
        snprintf(dst_zone->name, sizeof(dst_zone->name), "%s", src_zone->name);
        snprintf(dst_zone->path, sizeof(dst_zone->path), "%s", src_zone->path);
        dst_zone->max_size = src_zone->max_size > 0 ? src_zone->max_size : 1024ULL * 1024ULL * 1024ULL;
        dst_zone->keys_zone_size = src_zone->keys_zone_size > 0 ? src_zone->keys_zone_size : 10 * 1024 * 1024;
        dst_zone->inactive_ms = src_zone->inactive_ms > 0 ? src_zone->inactive_ms : 600000;
        for (size_t s = 0; s < APEX_CACHE_SHARDS; s++) {
            pthread_mutex_init(&dst_zone->shards[s].lock, NULL);
        }
    }
    return mgr;
}

void apex_cache_manager_destroy(apex_cache_manager_t *manager) {
    if (manager == NULL) {
        return;
    }
    for (size_t z = 0; z < manager->zone_count; z++) {
        cache_zone_t *zone = &manager->zones[z];
        for (size_t s = 0; s < APEX_CACHE_SHARDS; s++) {
            cache_shard_t *shard = &zone->shards[s];
            pthread_mutex_destroy(&shard->lock);
            for (size_t b = 0; b < APEX_CACHE_BUCKETS; b++) {
                cache_entry_t *entry = shard->buckets[b];
                while (entry != NULL) {
                    cache_entry_t *next = entry->next_hash;
                    free(entry->headers);
                    free(entry->body);
                    free(entry);
                    entry = next;
                }
            }
        }
    }
    free(manager->zones);
    free(manager);
}

void apex_cached_response_free(apex_cached_response_t *cached) {
    if (cached == NULL) {
        return;
    }
    free(cached->headers);
    cached->headers = NULL;
    free(cached->body);
    cached->body = NULL;
    cached->headers_len = 0;
    cached->body_len = 0;
}

bool apex_cache_lookup(apex_cache_manager_t *manager, const char *zone_name,
                       const char *key, apex_cached_response_t *cached) {
    if (manager == NULL || zone_name == NULL || key == NULL || cached == NULL) {
        return false;
    }
    cache_zone_t *zone = NULL;
    for (size_t i = 0; i < manager->zone_count; i++) {
        if (strcmp(manager->zones[i].name, zone_name) == 0) {
            zone = &manager->zones[i];
            break;
        }
    }
    if (zone == NULL) {
        return false;
    }

    size_t key_len = strlen(key);
    uint64_t hash = cache_hash_key(key, key_len);
    size_t shard_idx = (size_t)(hash % APEX_CACHE_SHARDS);
    cache_shard_t *shard = &zone->shards[shard_idx];
    size_t bucket_idx = (size_t)((hash / APEX_CACHE_SHARDS) % APEX_CACHE_BUCKETS);

    uint64_t now = cache_now_ms();

    pthread_mutex_lock(&shard->lock);

    cache_entry_t **curr = &shard->buckets[bucket_idx];
    while (*curr != NULL) {
        cache_entry_t *entry = *curr;
        if (entry->hash == hash && strcmp(entry->key, key) == 0) {
            /* Check expiry and inactive timeout */
            if (now > entry->expires_at_ms ||
                (zone->inactive_ms > 0 && now - entry->last_accessed_ms > zone->inactive_ms)) {
                /* Expired: unlink from hash chain and LRU, then free */
                *curr = entry->next_hash;
                lru_remove(shard, entry);
                atomic_fetch_sub_explicit(&zone->total_size, entry->entry_size, memory_order_relaxed);
                shard->shard_size -= entry->entry_size;
                free(entry->headers);
                free(entry->body);
                free(entry);
                pthread_mutex_unlock(&shard->lock);
                return false;
            }

            if (entry->headers == NULL) {
                pthread_mutex_unlock(&shard->lock);
                return false;
            }

            char *resp_headers = malloc(entry->headers_len + 1);
            if (resp_headers == NULL) {
                pthread_mutex_unlock(&shard->lock);
                return false;
            }
            memcpy(resp_headers, entry->headers, entry->headers_len);
            resp_headers[entry->headers_len] = '\0';

            char *resp_body = NULL;
            if (entry->body_len > 0) {
                if (entry->body == NULL) {
                    free(resp_headers);
                    pthread_mutex_unlock(&shard->lock);
                    return false;
                }
                resp_body = malloc(entry->body_len + 1);
                if (resp_body == NULL) {
                    free(resp_headers);
                    pthread_mutex_unlock(&shard->lock);
                    return false;
                }
                memcpy(resp_body, entry->body, entry->body_len);
                resp_body[entry->body_len] = '\0';
            }

            /* Cache hit: update last_accessed and move to head of LRU */
            entry->last_accessed_ms = now;
            lru_touch(shard, entry);

            cached->status = entry->status;
            cached->expires_at_ms = entry->expires_at_ms;
            cached->age_seconds = (now >= entry->created_at_ms && entry->created_at_ms > 0)
                                      ? ((now - entry->created_at_ms) / 1000ULL)
                                      : 0ULL;
            cached->headers = resp_headers;
            cached->headers_len = entry->headers_len;
            cached->body = resp_body;
            cached->body_len = entry->body_len;

            pthread_mutex_unlock(&shard->lock);
            return true;
        }
        curr = &entry->next_hash;
    }

    pthread_mutex_unlock(&shard->lock);
    return false;
}

bool apex_cache_store(apex_cache_manager_t *manager, const char *zone_name,
                      const char *key, int status, const char *headers, size_t headers_len,
                      const char *body, size_t body_len, uint64_t valid_ms) {
    if (manager == NULL || zone_name == NULL || key == NULL || headers == NULL || valid_ms == 0) {
        return false;
    }
    cache_zone_t *zone = NULL;
    for (size_t i = 0; i < manager->zone_count; i++) {
        if (strcmp(manager->zones[i].name, zone_name) == 0) {
            zone = &manager->zones[i];
            break;
        }
    }
    if (zone == NULL) {
        return false;
    }

    size_t key_len = strlen(key);
    if (key_len >= sizeof(((cache_entry_t *)0)->key)) {
        return false;
    }

    size_t entry_size = sizeof(cache_entry_t) + headers_len + body_len;
    if (entry_size > zone->max_size) {
        return false;
    }

    char *new_headers = malloc(headers_len + 1);
    if (new_headers == NULL) {
        return false;
    }
    memcpy(new_headers, headers, headers_len);
    new_headers[headers_len] = '\0';

    char *new_body = NULL;
    if (body_len > 0 && body != NULL) {
        new_body = malloc(body_len + 1);
        if (new_body == NULL) {
            free(new_headers);
            return false;
        }
        memcpy(new_body, body, body_len);
        new_body[body_len] = '\0';
    }

    uint64_t hash = cache_hash_key(key, key_len);
    size_t shard_idx = (size_t)(hash % APEX_CACHE_SHARDS);
    cache_shard_t *shard = &zone->shards[shard_idx];
    size_t bucket_idx = (size_t)((hash / APEX_CACHE_SHARDS) % APEX_CACHE_BUCKETS);

    uint64_t now = cache_now_ms();

    pthread_mutex_lock(&shard->lock);

    /* Evict from shard LRU if exceeding max_size */
    while (atomic_load_explicit(&zone->total_size, memory_order_relaxed) + entry_size > zone->max_size) {
        cache_entry_t *victim = shard->lru_tail;
        if (victim == NULL) {
            break;
        }
        /* Remove victim from hash bucket */
        size_t v_bucket = (size_t)((victim->hash / APEX_CACHE_SHARDS) % APEX_CACHE_BUCKETS);
        cache_entry_t **v_curr = &shard->buckets[v_bucket];
        while (*v_curr != NULL && *v_curr != victim) {
            v_curr = &(*v_curr)->next_hash;
        }
        if (*v_curr == victim) {
            *v_curr = victim->next_hash;
        }
        lru_remove(shard, victim);
        atomic_fetch_sub_explicit(&zone->total_size, victim->entry_size, memory_order_relaxed);
        shard->shard_size -= victim->entry_size;
        free(victim->headers);
        free(victim->body);
        free(victim);
    }

    /* Check if already present */
    cache_entry_t *entry = shard->buckets[bucket_idx];
    while (entry != NULL) {
        if (entry->hash == hash && strcmp(entry->key, key) == 0) {
            break;
        }
        entry = entry->next_hash;
    }

    if (entry != NULL) {
        atomic_fetch_sub_explicit(&zone->total_size, entry->entry_size, memory_order_relaxed);
        shard->shard_size -= entry->entry_size;
        free(entry->headers);
        free(entry->body);
    } else {
        entry = calloc(1, sizeof(*entry));
        if (entry == NULL) {
            free(new_headers);
            free(new_body);
            pthread_mutex_unlock(&shard->lock);
            return false;
        }
        entry->hash = hash;
        memcpy(entry->key, key, key_len + 1);
        entry->next_hash = shard->buckets[bucket_idx];
        shard->buckets[bucket_idx] = entry;
    }

    entry->status = status;
    entry->headers_len = headers_len;
    entry->headers = new_headers;
    entry->body_len = body_len;
    entry->body = new_body;

    entry->entry_size = entry_size;
    entry->expires_at_ms = now + valid_ms;
    entry->created_at_ms = now;
    entry->last_accessed_ms = now;

    lru_touch(shard, entry);
    shard->shard_size += entry_size;
    atomic_fetch_add_explicit(&zone->total_size, entry_size, memory_order_relaxed);

    pthread_mutex_unlock(&shard->lock);
    return true;
}

bool apex_cache_purge(apex_cache_manager_t *manager, const char *zone_name, const char *key) {
    if (manager == NULL || zone_name == NULL || key == NULL) {
        return false;
    }
    cache_zone_t *zone = NULL;
    for (size_t i = 0; i < manager->zone_count; i++) {
        if (strcmp(manager->zones[i].name, zone_name) == 0) {
            zone = &manager->zones[i];
            break;
        }
    }
    if (zone == NULL) {
        return false;
    }

    size_t key_len = strlen(key);
    uint64_t hash = cache_hash_key(key, key_len);
    size_t shard_idx = (size_t)(hash % APEX_CACHE_SHARDS);
    cache_shard_t *shard = &zone->shards[shard_idx];
    size_t bucket_idx = (size_t)((hash / APEX_CACHE_SHARDS) % APEX_CACHE_BUCKETS);

    pthread_mutex_lock(&shard->lock);
    cache_entry_t **curr = &shard->buckets[bucket_idx];
    while (*curr != NULL) {
        cache_entry_t *entry = *curr;
        if (entry->hash == hash && strcmp(entry->key, key) == 0) {
            *curr = entry->next_hash;
            lru_remove(shard, entry);
            atomic_fetch_sub_explicit(&zone->total_size, entry->entry_size, memory_order_relaxed);
            shard->shard_size -= entry->entry_size;
            free(entry->headers);
            free(entry->body);
            free(entry);
            pthread_mutex_unlock(&shard->lock);
            return true;
        }
        curr = &entry->next_hash;
    }
    pthread_mutex_unlock(&shard->lock);
    return false;
}

uint64_t apex_cache_evaluate_validity(const char *headers, size_t headers_len, int status,
                                      const apex_cache_valid_rule_t *rules, size_t rule_count) {
    if (headers == NULL || headers_len == 0) {
        return 0;
    }

    /* 1. Check upstream Cache-Control header */
    const char *cc_val = NULL;
    size_t cc_len = 0;
    const char *p = headers;
    while (p < headers + headers_len) {
        const char *end = strstr(p, "\r\n");
        if (end == NULL || end == p) {
            break;
        }
        if (strncasecmp(p, "Cache-Control:", 14) == 0) {
            cc_val = p + 14;
            while (*cc_val == ' ' || *cc_val == '\t') {
                cc_val++;
            }
            cc_len = (size_t)(end - cc_val);
            break;
        }
        p = end + 2;
    }

    if (cc_val != NULL && cc_len > 0) {
        char cc_lower[256];
        size_t copy_len = cc_len < sizeof(cc_lower) - 1 ? cc_len : sizeof(cc_lower) - 1;
        for (size_t i = 0; i < copy_len; i++) {
            cc_lower[i] = (char)tolower((unsigned char)cc_val[i]);
        }
        cc_lower[copy_len] = '\0';

        if (strstr(cc_lower, "no-store") != NULL ||
            strstr(cc_lower, "private") != NULL ||
            strstr(cc_lower, "no-cache") != NULL) {
            return 0;
        }

        const char *ma = strstr(cc_lower, "max-age=");
        if (ma != NULL) {
            char *endptr = NULL;
            unsigned long sec = strtoul(ma + 8, &endptr, 10);
            if (sec > 0) {
                return (uint64_t)sec * 1000ULL;
            } else {
                return 0;
            }
        }
    }

    /* 2. Check proxy_cache_valid rules */
    if (rules != NULL && rule_count > 0) {
        /* Exact status code match */
        for (size_t i = 0; i < rule_count; i++) {
            if (rules[i].status_code == status) {
                return rules[i].valid_ms;
            }
        }
        /* Wildcard any status code (status_code == 0) */
        for (size_t i = 0; i < rule_count; i++) {
            if (rules[i].status_code == 0) {
                return rules[i].valid_ms;
            }
        }
    }

    return 0;
}
