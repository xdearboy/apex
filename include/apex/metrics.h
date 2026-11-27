#ifndef APEX_METRICS_H
#define APEX_METRICS_H

#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APEX_METRICS_BUCKETS_COUNT 10

/* Global connection & cache counters (lightly updated / gauge style) */
typedef struct {
    _Atomic uint64_t accepts;
    _Atomic uint64_t handled;
    _Atomic uint64_t requests;
    _Atomic int64_t active_connections;
    _Atomic int64_t reading_connections;
    _Atomic int64_t writing_connections;
    _Atomic int64_t waiting_connections;
    _Atomic uint64_t responses_2xx;
    _Atomic uint64_t responses_3xx;
    _Atomic uint64_t responses_4xx;
    _Atomic uint64_t responses_5xx;
    _Atomic uint64_t cache_hits;
    _Atomic uint64_t cache_misses;
    _Atomic uint64_t cache_bypasses;
} apex_server_stats_t;

/* Per-worker metrics structure aligned to 64 bytes (L1 cache line) to prevent
 * false sharing and cache bouncing across CPU cores on the hot path. */
typedef struct __attribute__((aligned(64))) {
    alignas(64) _Atomic uint64_t requests_total;
    _Atomic uint64_t responses_2xx;
    _Atomic uint64_t responses_3xx;
    _Atomic uint64_t responses_4xx;
    _Atomic uint64_t responses_5xx;
    _Atomic uint64_t bytes_sent;
    _Atomic uint64_t bytes_received;
    _Atomic uint64_t duration_buckets[APEX_METRICS_BUCKETS_COUNT];
    _Atomic uint64_t duration_sum_us;
} apex_worker_metrics_t;

/* Aggregated snapshot across all workers and server stats */
typedef struct {
    uint64_t requests_total;
    uint64_t responses_2xx;
    uint64_t responses_3xx;
    uint64_t responses_4xx;
    uint64_t responses_5xx;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t duration_buckets[APEX_METRICS_BUCKETS_COUNT];
    uint64_t duration_sum_us;
    int64_t active_connections;
    int64_t reading_connections;
    int64_t writing_connections;
    int64_t waiting_connections;
    uint64_t accepts;
    uint64_t handled;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t cache_bypasses;
    uint64_t memory_rss_bytes;
} apex_aggregated_metrics_t;

/* Ultra-fast hot-path recording helper (no locks, relaxed atomics, 0 false sharing) */
static inline void apex_metrics_record_request(apex_worker_metrics_t *metrics, int status_code,
                                              size_t bytes_in, size_t bytes_out, uint64_t duration_us) {
    if (metrics == NULL) {
        return;
    }
    atomic_fetch_add_explicit(&metrics->requests_total, 1, memory_order_relaxed);
    if (status_code >= 200 && status_code < 300) {
        atomic_fetch_add_explicit(&metrics->responses_2xx, 1, memory_order_relaxed);
    } else if (status_code >= 300 && status_code < 400) {
        atomic_fetch_add_explicit(&metrics->responses_3xx, 1, memory_order_relaxed);
    } else if (status_code >= 400 && status_code < 500) {
        atomic_fetch_add_explicit(&metrics->responses_4xx, 1, memory_order_relaxed);
    } else if (status_code >= 500) {
        atomic_fetch_add_explicit(&metrics->responses_5xx, 1, memory_order_relaxed);
    }

    if (bytes_in > 0) {
        atomic_fetch_add_explicit(&metrics->bytes_received, bytes_in, memory_order_relaxed);
    }
    if (bytes_out > 0) {
        atomic_fetch_add_explicit(&metrics->bytes_sent, bytes_out, memory_order_relaxed);
    }

    atomic_fetch_add_explicit(&metrics->duration_sum_us, duration_us, memory_order_relaxed);

    /* Bucket distribution: <= 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, > 1s */
    int bucket = 9;
    if (duration_us <= 1000) {
        bucket = 0;
    } else if (duration_us <= 5000) {
        bucket = 1;
    } else if (duration_us <= 10000) {
        bucket = 2;
    } else if (duration_us <= 25000) {
        bucket = 3;
    } else if (duration_us <= 50000) {
        bucket = 4;
    } else if (duration_us <= 100000) {
        bucket = 5;
    } else if (duration_us <= 250000) {
        bucket = 6;
    } else if (duration_us <= 500000) {
        bucket = 7;
    } else if (duration_us <= 1000000) {
        bucket = 8;
    }
    atomic_fetch_add_explicit(&metrics->duration_buckets[bucket], 1, memory_order_relaxed);
}

/* Formats Prometheus text exposition buffer from aggregated metrics */
size_t apex_metrics_format_prometheus(const apex_aggregated_metrics_t *agg, char *dest, size_t max_len);

#endif /* APEX_METRICS_H */
