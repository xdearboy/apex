#include "metrics.h"

worker_metric_t *worker_metrics = NULL;
global_metric_t *global_metric = NULL;
static int g_num_workers = 0;

uint64_t monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

int metrics_init(int num_workers) {
    g_num_workers = num_workers;
    worker_metrics = mmap(NULL, (size_t)num_workers * sizeof(*worker_metrics),
                          PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
                          -1, 0);
    global_metric = mmap(NULL, sizeof(*global_metric),
                         PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
                         -1, 0);

    if (worker_metrics == MAP_FAILED || global_metric == MAP_FAILED) {
        perror("mmap metrics");
        return -1;
    }

    atomic_store_explicit(&global_metric->last_sample_ns, monotonic_ns(), memory_order_relaxed);
    atomic_store_explicit(&global_metric->last_total, 0, memory_order_relaxed);
    atomic_store_explicit(&global_metric->rps, 0, memory_order_relaxed);
    atomic_store_explicit(&global_metric->peak_rps, 0, memory_order_relaxed);

    return 0;
}

void metrics_destroy(int num_workers) {
    if (worker_metrics && worker_metrics != MAP_FAILED)
        munmap(worker_metrics, (size_t)num_workers * sizeof(*worker_metrics));
    if (global_metric && global_metric != MAP_FAILED)
        munmap(global_metric, sizeof(*global_metric));
}

uint64_t total_requests(void) {
    uint64_t total = 0;
    for (int i = 0; i < g_num_workers; ++i)
        total += atomic_load_explicit(&worker_metrics[i].published, memory_order_relaxed);
    return total;
}

uint64_t current_rps(uint64_t total) {
    const uint64_t now = monotonic_ns();
    uint64_t then = atomic_load_explicit(&global_metric->last_sample_ns, memory_order_relaxed);

    if (now - then >= UINT64_C(1000000000) &&
        atomic_compare_exchange_strong_explicit(&global_metric->last_sample_ns,
                                                &then, now,
                                                memory_order_relaxed,
                                                memory_order_relaxed)) {
        const uint64_t previous = atomic_exchange_explicit(&global_metric->last_total,
                                                            total,
                                                            memory_order_relaxed);
        const uint64_t rps = (total - previous) * UINT64_C(1000000000) / (now - then);
        atomic_store_explicit(&global_metric->rps, rps, memory_order_relaxed);

        record_peak_rps(rps);
        return rps;
    }

    return atomic_load_explicit(&global_metric->rps, memory_order_relaxed);
}

void record_peak_rps(uint64_t rps) {
    uint64_t peak = atomic_load_explicit(&global_metric->peak_rps, memory_order_relaxed);
    while (rps > peak &&
           !atomic_compare_exchange_weak_explicit(&global_metric->peak_rps, &peak, rps,
                                                 memory_order_relaxed,
                                                 memory_order_relaxed)) {
    }
}
