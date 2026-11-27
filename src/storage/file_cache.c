#include "apex/file_cache.h"
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Forward declarations of helpers from src/static.c */
const char *apex_mime_type(const char *path);
void apex_static_format_etag(time_t mtime, off_t size, char *out, size_t out_size);
void apex_static_format_http_date(time_t time_val, char *out, size_t out_size);

static inline uint64_t file_cache_monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
    }
    return 0;
}

static inline uint32_t file_cache_hash_path(const char *path, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)path[i];
        h *= 16777619u;
    }
    return h;
}

static void lru_remove_entry(apex_file_cache_shard_t *shard, apex_cached_file_t *entry) {
    if (entry->prev != NULL) {
        entry->prev->next = entry->next;
    } else if (shard->lru_head == entry) {
        shard->lru_head = entry->next;
    }
    if (entry->next != NULL) {
        entry->next->prev = entry->prev;
    } else if (shard->lru_tail == entry) {
        shard->lru_tail = entry->prev;
    }
    entry->prev = NULL;
    entry->next = NULL;
}

static void lru_push_front(apex_file_cache_shard_t *shard, apex_cached_file_t *entry) {
    entry->prev = NULL;
    entry->next = shard->lru_head;
    if (shard->lru_head != NULL) {
        shard->lru_head->prev = entry;
    }
    shard->lru_head = entry;
    if (shard->lru_tail == NULL) {
        shard->lru_tail = entry;
    }
}

static void free_cached_file_resources(apex_cached_file_t *entry) {
    if (entry == NULL) {
        return;
    }
    if (entry->mmap_addr != NULL && entry->mmap_addr != MAP_FAILED) {
        munmap(entry->mmap_addr, entry->mmap_len);
        entry->mmap_addr = NULL;
        entry->mmap_len = 0;
    }
    if (entry->fd >= 0) {
        close(entry->fd);
        entry->fd = -1;
    }
    free(entry);
}

apex_file_cache_t *apex_file_cache_create(const apex_open_file_cache_config_t *cfg) {
    if (cfg == NULL || !cfg->enabled) {
        return NULL;
    }

    apex_file_cache_t *cache = calloc(1, sizeof(*cache));
    if (cache == NULL) {
        return NULL;
    }

    cache->enabled = true;
    cache->max_entries = cfg->max_entries > 0 ? cfg->max_entries : 1000;
    cache->inactive_sec = cfg->inactive_sec > 0 ? cfg->inactive_sec : 60;
    cache->valid_sec = cfg->valid_sec > 0 ? cfg->valid_sec : 60;
    cache->min_uses = cfg->min_uses > 0 ? cfg->min_uses : 1;
    cache->errors = cfg->errors;

    size_t buckets_per_shard = (cache->max_entries / APEX_FILE_CACHE_SHARDS) * 2;
    if (buckets_per_shard < 64) {
        buckets_per_shard = 64;
    }

    for (size_t s = 0; s < APEX_FILE_CACHE_SHARDS; s++) {
        apex_file_cache_shard_t *shard = &cache->shards[s];
        pthread_rwlock_init(&shard->lock, NULL);
        shard->bucket_count = buckets_per_shard;
        shard->buckets = calloc(buckets_per_shard, sizeof(apex_cached_file_t *));
        if (shard->buckets == NULL) {
            apex_file_cache_destroy(cache);
            return NULL;
        }
    }

    return cache;
}

void apex_file_cache_destroy(apex_file_cache_t *cache) {
    if (cache == NULL) {
        return;
    }

    for (size_t s = 0; s < APEX_FILE_CACHE_SHARDS; s++) {
        apex_file_cache_shard_t *shard = &cache->shards[s];
        pthread_rwlock_wrlock(&shard->lock);

        apex_cached_file_t *curr = shard->lru_head;
        while (curr != NULL) {
            apex_cached_file_t *next = curr->next;
            free_cached_file_resources(curr);
            curr = next;
        }
        shard->lru_head = NULL;
        shard->lru_tail = NULL;
        shard->count = 0;

        free(shard->buckets);
        shard->buckets = NULL;

        pthread_rwlock_unlock(&shard->lock);
        pthread_rwlock_destroy(&shard->lock);
    }

    free(cache);
}

void apex_file_cache_flush(apex_file_cache_t *cache) {
    if (cache == NULL) {
        return;
    }

    for (size_t s = 0; s < APEX_FILE_CACHE_SHARDS; s++) {
        apex_file_cache_shard_t *shard = &cache->shards[s];
        pthread_rwlock_wrlock(&shard->lock);

        for (size_t b = 0; b < shard->bucket_count; b++) {
            shard->buckets[b] = NULL;
        }

        apex_cached_file_t *curr = shard->lru_head;
        while (curr != NULL) {
            apex_cached_file_t *next = curr->next;
            curr->evicted = true;
            if (atomic_load_explicit(&curr->ref_count, memory_order_acquire) == 0) {
                free_cached_file_resources(curr);
            }
            curr = next;
        }

        shard->lru_head = NULL;
        shard->lru_tail = NULL;
        shard->count = 0;

        pthread_rwlock_unlock(&shard->lock);
    }
}

bool apex_file_cache_acquire(apex_file_cache_t *cache, const char *path, size_t path_len,
                             apex_cached_file_t **out_file) {
    if (cache == NULL || path == NULL || path_len == 0 || path_len >= APEX_CONFIG_PATH_MAX || out_file == NULL) {
        return false;
    }

    uint32_t hash = file_cache_hash_path(path, path_len);
    size_t shard_idx = hash % APEX_FILE_CACHE_SHARDS;
    apex_file_cache_shard_t *shard = &cache->shards[shard_idx];
    size_t bucket_idx = (hash >> 8) % shard->bucket_count;

    uint64_t now_ms = file_cache_monotonic_ms();
    uint64_t inactive_ms = (uint64_t)cache->inactive_sec * 1000ULL;
    uint64_t valid_ms = (uint64_t)cache->valid_sec * 1000ULL;

    pthread_rwlock_wrlock(&shard->lock);

    /* Search bucket */
    apex_cached_file_t *prev_hash = NULL;
    apex_cached_file_t *entry = shard->buckets[bucket_idx];

    while (entry != NULL) {
        if (entry->path_len == path_len && memcmp(entry->path, path, path_len) == 0) {
            break;
        }
        prev_hash = entry;
        entry = entry->hash_next;
    }

    if (entry != NULL) {
        /* Check inactive expiry */
        if (now_ms >= entry->last_accessed_ms && (now_ms - entry->last_accessed_ms) > inactive_ms) {
            /* Evict expired entry from bucket and LRU */
            if (prev_hash != NULL) {
                prev_hash->hash_next = entry->hash_next;
            } else {
                shard->buckets[bucket_idx] = entry->hash_next;
            }
            lru_remove_entry(shard, entry);
            shard->count--;
            entry->evicted = true;
            if (atomic_load_explicit(&entry->ref_count, memory_order_acquire) == 0) {
                free_cached_file_resources(entry);
            }
            entry = NULL;
        } else {
            /* If valid entry, check periodic validation */
            if (entry->err_code == 0) {
                if (now_ms >= entry->last_validated_ms && (now_ms - entry->last_validated_ms) >= valid_ms) {
                    struct stat current_st;
                    if (fstat(entry->fd, &current_st) == 0 && current_st.st_nlink > 0) {
                        if (current_st.st_mtime != entry->stat_info.st_mtime ||
                            current_st.st_size != entry->stat_info.st_size) {
                            entry->stat_info = current_st;
                            apex_static_format_etag(current_st.st_mtime, current_st.st_size,
                                                   entry->etag, sizeof(entry->etag));
                            apex_static_format_http_date(current_st.st_mtime, entry->last_modified,
                                                        sizeof(entry->last_modified));
                            /* Refresh mmap if mapped */
                            if (entry->mmap_addr != NULL) {
                                munmap(entry->mmap_addr, entry->mmap_len);
                                entry->mmap_addr = NULL;
                                entry->mmap_len = 0;
                                if ((size_t)current_st.st_size <= APEX_FILE_CACHE_MAX_MMAP && current_st.st_size > 0) {
                                    void *mapped = mmap(NULL, (size_t)current_st.st_size, PROT_READ, MAP_PRIVATE, entry->fd, 0);
                                    if (mapped != MAP_FAILED) {
                                        entry->mmap_addr = mapped;
                                        entry->mmap_len = (size_t)current_st.st_size;
                                    }
                                }
                            }
                        }
                    }
                    entry->last_validated_ms = now_ms;
                }
            }

            entry->last_accessed_ms = now_ms;
            entry->use_count++;
            atomic_fetch_add_explicit(&entry->ref_count, 1, memory_order_release);

            /* Move to front of LRU */
            lru_remove_entry(shard, entry);
            lru_push_front(shard, entry);

            pthread_rwlock_unlock(&shard->lock);
            *out_file = entry;
            return true;
        }
    }

    /* Cache miss: open file from disk */
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    int err_code = 0;

    if (fd < 0) {
        err_code = errno;
        if (!cache->errors) {
            pthread_rwlock_unlock(&shard->lock);
            return false;
        }
    } else {
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
            close(fd);
            pthread_rwlock_unlock(&shard->lock);
            return false;
        }
    }

    /* Enforce capacity limit on shard */
    size_t shard_capacity = cache->max_entries / APEX_FILE_CACHE_SHARDS;
    if (shard_capacity == 0) {
        shard_capacity = 1;
    }

    while (shard->count >= shard_capacity && shard->lru_tail != NULL) {
        apex_cached_file_t *victim = shard->lru_tail;
        /* Look for unreferenced tail entries */
        while (victim != NULL && atomic_load_explicit(&victim->ref_count, memory_order_acquire) > 0) {
            victim = victim->prev;
        }
        if (victim == NULL) {
            break; /* All entries are currently referenced */
        }

        /* Unlink victim from bucket */
        uint32_t v_hash = file_cache_hash_path(victim->path, victim->path_len);
        size_t v_bidx = (v_hash >> 8) % shard->bucket_count;
        apex_cached_file_t *v_prev = NULL;
        apex_cached_file_t *v_curr = shard->buckets[v_bidx];
        while (v_curr != NULL && v_curr != victim) {
            v_prev = v_curr;
            v_curr = v_curr->hash_next;
        }
        if (v_curr == victim) {
            if (v_prev != NULL) {
                v_prev->hash_next = victim->hash_next;
            } else {
                shard->buckets[v_bidx] = victim->hash_next;
            }
        }

        lru_remove_entry(shard, victim);
        shard->count--;
        victim->evicted = true;
        free_cached_file_resources(victim);
    }

    /* Allocate new cache entry */
    apex_cached_file_t *new_entry = calloc(1, sizeof(*new_entry));
    if (new_entry == NULL) {
        if (fd >= 0) {
            close(fd);
        }
        pthread_rwlock_unlock(&shard->lock);
        return false;
    }

    memcpy(new_entry->path, path, path_len);
    new_entry->path[path_len] = '\0';
    new_entry->path_len = path_len;
    new_entry->fd = fd;
    new_entry->err_code = err_code;
    new_entry->created_at_ms = now_ms;
    new_entry->last_accessed_ms = now_ms;
    new_entry->last_validated_ms = now_ms;
    new_entry->use_count = 1;
    atomic_store_explicit(&new_entry->ref_count, 1, memory_order_release);

    if (err_code == 0) {
        new_entry->stat_info = st;
        const char *mt = apex_mime_type(path);
        if (mt != NULL) {
            snprintf(new_entry->content_type, sizeof(new_entry->content_type), "%s", mt);
        } else {
            snprintf(new_entry->content_type, sizeof(new_entry->content_type), "application/octet-stream");
        }
        apex_static_format_etag(st.st_mtime, st.st_size, new_entry->etag, sizeof(new_entry->etag));
        apex_static_format_http_date(st.st_mtime, new_entry->last_modified, sizeof(new_entry->last_modified));

        /* Pre-mmap for small/medium files to bypass syscalls completely */
        if ((size_t)st.st_size <= APEX_FILE_CACHE_MAX_MMAP && st.st_size > 0) {
            void *mapped = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            if (mapped != MAP_FAILED) {
                new_entry->mmap_addr = mapped;
                new_entry->mmap_len = (size_t)st.st_size;
            }
        }
    }

    /* Insert into bucket and LRU head */
    new_entry->hash_next = shard->buckets[bucket_idx];
    shard->buckets[bucket_idx] = new_entry;
    lru_push_front(shard, new_entry);
    shard->count++;

    pthread_rwlock_unlock(&shard->lock);

    *out_file = new_entry;
    return true;
}

void apex_file_cache_release(apex_file_cache_t *cache, apex_cached_file_t *file) {
    (void)cache;
    if (file == NULL) {
        return;
    }

    int32_t remaining = atomic_fetch_sub_explicit(&file->ref_count, 1, memory_order_acq_rel) - 1;
    if (remaining <= 0 && file->evicted) {
        free_cached_file_resources(file);
    }
}

