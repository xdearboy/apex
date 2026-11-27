#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "apex/metrics.h"
#include "internal.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>

static uint64_t get_process_rss_bytes(void) {
#if defined(__linux__)
    FILE *fp = fopen("/proc/self/statm", "r");
    if (fp != NULL) {
        long pages = 0;
        long resident = 0;
        if (fscanf(fp, "%ld %ld", &pages, &resident) == 2) {
            fclose(fp);
            long page_size = sysconf(_SC_PAGESIZE);
            if (page_size <= 0) {
                page_size = 4096;
            }
            return (uint64_t)resident * (uint64_t)page_size;
        }
        fclose(fp);
    }
#endif
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
#if defined(__APPLE__)
        return (uint64_t)usage.ru_maxrss;
#else
        return (uint64_t)usage.ru_maxrss * 1024ULL;
#endif
    }
    return 0;
}

void apex_metrics_aggregate(const worker_arg_t *workers, size_t worker_count,
                            const apex_server_stats_t *stats, apex_aggregated_metrics_t *out) {
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));

    if (stats != NULL) {
        out->active_connections = atomic_load_explicit(&stats->active_connections, memory_order_relaxed);
        out->reading_connections = atomic_load_explicit(&stats->reading_connections, memory_order_relaxed);
        out->writing_connections = atomic_load_explicit(&stats->writing_connections, memory_order_relaxed);
        out->waiting_connections = atomic_load_explicit(&stats->waiting_connections, memory_order_relaxed);
        if (out->active_connections < 0) out->active_connections = 0;
        if (out->reading_connections < 0) out->reading_connections = 0;
        if (out->writing_connections < 0) out->writing_connections = 0;
        if (out->waiting_connections < 0) out->waiting_connections = 0;

        out->accepts = atomic_load_explicit(&stats->accepts, memory_order_relaxed);
        out->handled = atomic_load_explicit(&stats->handled, memory_order_relaxed);
        out->requests_total = atomic_load_explicit(&stats->requests, memory_order_relaxed);
        out->responses_2xx = atomic_load_explicit(&stats->responses_2xx, memory_order_relaxed);
        out->responses_3xx = atomic_load_explicit(&stats->responses_3xx, memory_order_relaxed);
        out->responses_4xx = atomic_load_explicit(&stats->responses_4xx, memory_order_relaxed);
        out->responses_5xx = atomic_load_explicit(&stats->responses_5xx, memory_order_relaxed);
        out->cache_hits = atomic_load_explicit(&stats->cache_hits, memory_order_relaxed);
        out->cache_misses = atomic_load_explicit(&stats->cache_misses, memory_order_relaxed);
        out->cache_bypasses = atomic_load_explicit(&stats->cache_bypasses, memory_order_relaxed);
    }

    if (workers != NULL && worker_count > 0) {
        uint64_t worker_requests = 0;
        uint64_t worker_2xx = 0, worker_3xx = 0, worker_4xx = 0, worker_5xx = 0;

        for (size_t i = 0; i < worker_count; i++) {
            const apex_worker_metrics_t *w = &workers[i].metrics;
            worker_requests += atomic_load_explicit(&w->requests_total, memory_order_relaxed);
            worker_2xx += atomic_load_explicit(&w->responses_2xx, memory_order_relaxed);
            worker_3xx += atomic_load_explicit(&w->responses_3xx, memory_order_relaxed);
            worker_4xx += atomic_load_explicit(&w->responses_4xx, memory_order_relaxed);
            worker_5xx += atomic_load_explicit(&w->responses_5xx, memory_order_relaxed);

            out->bytes_sent += atomic_load_explicit(&w->bytes_sent, memory_order_relaxed);
            out->bytes_received += atomic_load_explicit(&w->bytes_received, memory_order_relaxed);
            out->duration_sum_us += atomic_load_explicit(&w->duration_sum_us, memory_order_relaxed);

            for (size_t b = 0; b < APEX_METRICS_BUCKETS_COUNT; b++) {
                out->duration_buckets[b] += atomic_load_explicit(&w->duration_buckets[b], memory_order_relaxed);
            }
        }

        if (worker_requests > 0) {
            out->requests_total = worker_requests;
            out->responses_2xx = worker_2xx;
            out->responses_3xx = worker_3xx;
            out->responses_4xx = worker_4xx;
            out->responses_5xx = worker_5xx;
        }
    }

    out->memory_rss_bytes = get_process_rss_bytes();
}

size_t apex_metrics_format_prometheus(const apex_aggregated_metrics_t *agg, char *dest, size_t max_len) {
    if (agg == NULL || dest == NULL || max_len == 0) {
        return 0;
    }

    static const char *const BUCKET_LE[APEX_METRICS_BUCKETS_COUNT] = {
        "0.001", "0.005", "0.010", "0.025", "0.050",
        "0.100", "0.250", "0.500", "1.000", "+Inf"
    };

    size_t offset = 0;
    int written = snprintf(dest + offset, max_len - offset,
        "# HELP apex_up Boolean indicating if the Apex service is up and running.\n"
        "# TYPE apex_up gauge\n"
        "apex_up 1\n\n"
        "# HELP apex_connections_active Active client connections\n"
        "# TYPE apex_connections_active gauge\n"
        "apex_connections_active %lld\n\n"
        "# HELP apex_connections_reading Connections reading request\n"
        "# TYPE apex_connections_reading gauge\n"
        "apex_connections_reading %lld\n\n"
        "# HELP apex_connections_writing Connections writing response\n"
        "# TYPE apex_connections_writing gauge\n"
        "apex_connections_writing %lld\n\n"
        "# HELP apex_connections_waiting Connections waiting for request\n"
        "# TYPE apex_connections_waiting gauge\n"
        "apex_connections_waiting %lld\n\n"
        "# HELP apex_connections_accepted_total Total accepted connections\n"
        "# TYPE apex_connections_accepted_total counter\n"
        "apex_connections_accepted_total %llu\n\n"
        "# HELP apex_connections_handled_total Total handled connections\n"
        "# TYPE apex_connections_handled_total counter\n"
        "apex_connections_handled_total %llu\n\n"
        "# HELP apex_http_requests_total Total HTTP requests handled\n"
        "# TYPE apex_http_requests_total counter\n"
        "apex_http_requests_total %llu\n\n"
        "# HELP apex_http_responses_total Total HTTP responses sent by status code class\n"
        "# TYPE apex_http_responses_total counter\n"
        "apex_http_responses_total{code=\"2xx\"} %llu\n"
        "apex_http_responses_total{code=\"3xx\"} %llu\n"
        "apex_http_responses_total{code=\"4xx\"} %llu\n"
        "apex_http_responses_total{code=\"5xx\"} %llu\n\n"
        "# HELP apex_cache_requests_total Cache requests by status\n"
        "# TYPE apex_cache_requests_total counter\n"
        "apex_cache_requests_total{status=\"hit\"} %llu\n"
        "apex_cache_requests_total{status=\"miss\"} %llu\n"
        "apex_cache_requests_total{status=\"bypass\"} %llu\n\n"
        "# HELP apex_http_bytes_sent_total Total bytes sent to clients.\n"
        "# TYPE apex_http_bytes_sent_total counter\n"
        "apex_http_bytes_sent_total %llu\n\n"
        "# HELP apex_http_bytes_received_total Total bytes received from clients.\n"
        "# TYPE apex_http_bytes_received_total counter\n"
        "apex_http_bytes_received_total %llu\n\n"
        "# HELP apex_memory_rss_bytes Process RSS memory usage in bytes.\n"
        "# TYPE apex_memory_rss_bytes gauge\n"
        "apex_memory_rss_bytes %llu\n\n"
        "# HELP apex_http_request_duration_seconds HTTP request duration histogram in seconds.\n"
        "# TYPE apex_http_request_duration_seconds histogram\n",
        (long long)agg->active_connections,
        (long long)agg->reading_connections,
        (long long)agg->writing_connections,
        (long long)agg->waiting_connections,
        (unsigned long long)agg->accepts,
        (unsigned long long)agg->handled,
        (unsigned long long)agg->requests_total,
        (unsigned long long)agg->responses_2xx,
        (unsigned long long)agg->responses_3xx,
        (unsigned long long)agg->responses_4xx,
        (unsigned long long)agg->responses_5xx,
        (unsigned long long)agg->cache_hits,
        (unsigned long long)agg->cache_misses,
        (unsigned long long)agg->cache_bypasses,
        (unsigned long long)agg->bytes_sent,
        (unsigned long long)agg->bytes_received,
        (unsigned long long)agg->memory_rss_bytes
    );

    if (written < 0 || (size_t)written >= max_len - offset) {
        return max_len > 0 ? max_len - 1 : 0;
    }
    offset += (size_t)written;

    /* Prometheus cumulative histogram: each bucket includes counts of all previous buckets */
    uint64_t cumulative_count = 0;
    for (size_t b = 0; b < APEX_METRICS_BUCKETS_COUNT; b++) {
        cumulative_count += agg->duration_buckets[b];
        written = snprintf(dest + offset, max_len - offset,
            "apex_http_request_duration_seconds_bucket{le=\"%s\"} %llu\n",
            BUCKET_LE[b], (unsigned long long)cumulative_count);
        if (written < 0 || (size_t)written >= max_len - offset) {
            return max_len > 0 ? max_len - 1 : 0;
        }
        offset += (size_t)written;
    }

    double duration_sum_sec = (double)agg->duration_sum_us / 1000000.0;
    written = snprintf(dest + offset, max_len - offset,
        "apex_http_request_duration_seconds_sum %.6f\n"
        "apex_http_request_duration_seconds_count %llu\n",
        duration_sum_sec, (unsigned long long)agg->requests_total);

    if (written < 0 || (size_t)written >= max_len - offset) {
        return max_len > 0 ? max_len - 1 : 0;
    }
    offset += (size_t)written;

    return offset;
}
