#ifndef METRICS_H
#define METRICS_H

#include "tachyon.h"

typedef struct {
    _Atomic uint64_t published;
    uint8_t pad[56];
} worker_metric_t;

typedef struct {
    _Atomic uint64_t last_total;
    _Atomic uint64_t last_sample_ns;
    _Atomic uint64_t rps;
    _Atomic uint64_t peak_rps;
} global_metric_t;

extern worker_metric_t *worker_metrics;
extern global_metric_t *global_metric;

int metrics_init(int num_workers);
void metrics_destroy(int num_workers);
uint64_t monotonic_ns(void);
uint64_t total_requests(void);
uint64_t current_rps(uint64_t total);
void record_peak_rps(uint64_t rps);

#endif /* METRICS_H */
