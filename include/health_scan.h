#ifndef LIMINAL_HEALTH_SCAN_H
#define LIMINAL_HEALTH_SCAN_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float coherence_var;
    float delay_var;
    float drift_avg;
    float breath_hrv;
} HealthScan;

void health_scan_init(void);
void health_scan_enable(bool enable);
void health_scan_set_interval(uint32_t interval);
void health_scan_enable_reporting(bool enable);
void health_scan_step(uint64_t cycle,
                      float coherence,
                      float delay_seconds,
                      float drift);
const HealthScan *health_scan_state(void);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_HEALTH_SCAN_H */
