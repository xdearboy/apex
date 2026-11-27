#ifndef APEX_FILE_CACHE_H
#define APEX_FILE_CACHE_H

#include "apex/config.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

#define APEX_FILE_CACHE_MAX_MMAP ((size_t)4 * 1024u * 1024u) /* 4 MB memory mapping threshold */
#define APEX_FILE_CACHE_SHARDS 16u

typedef struct apex_cached_file {
    char path[APEX_CONFIG_PATH_MAX];
    size_t path_len;
    int fd;
    struct stat stat_info;
    char content_type[64];
    char etag[64];
    char last_modified[64];
    void *mmap_addr;
    size_t mmap_len;
    int err_code; /* 0 for valid file, or errno (ENOENT, EACCES) for negative cache */
    uint64_t created_at_ms;
    uint64_t last_accessed_ms;
    uint64_t last_validated_ms;
    uint32_t use_count;
    _Atomic int32_t ref_count;
    bool evicted;
    struct apex_cached_file *prev;
    struct apex_cached_file *next;
    struct apex_cached_file *hash_next;
} apex_cached_file_t;

typedef struct {
    pthread_rwlock_t lock;
    apex_cached_file_t **buckets;
    size_t bucket_count;
    apex_cached_file_t *lru_head;
    apex_cached_file_t *lru_tail;
    size_t count;
} apex_file_cache_shard_t;

typedef struct apex_file_cache {
    apex_file_cache_shard_t shards[APEX_FILE_CACHE_SHARDS];
    size_t max_entries;
    uint32_t inactive_sec;
    uint32_t valid_sec;
    uint32_t min_uses;
    bool errors;
    bool enabled;
} apex_file_cache_t;

/* Creates and initializes an open file cache instance */
apex_file_cache_t *apex_file_cache_create(const apex_open_file_cache_config_t *cfg);

/* Destroys the cache and closes all open file descriptors */
void apex_file_cache_destroy(apex_file_cache_t *cache);

/* Acquires a file from the cache, verifying validity and opening if needed.
 * Returns true if entry acquired (check out_file->err_code for negative hit),
 * false on memory allocation failure or when disabled.
 * The caller MUST call apex_file_cache_release when finished with the entry. */
bool apex_file_cache_acquire(apex_file_cache_t *cache, const char *path, size_t path_len,
                             apex_cached_file_t **out_file);

/* Releases reference to the cached file. Closes descriptor if entry was evicted. */
void apex_file_cache_release(apex_file_cache_t *cache, apex_cached_file_t *file);

/* Flushes all cached descriptors across all shards */
void apex_file_cache_flush(apex_file_cache_t *cache);

#ifdef __cplusplus
}
#endif

#endif /* APEX_FILE_CACHE_H */
