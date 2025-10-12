#include "health_scan.h"

#include "soil.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#define HEALTH_SCAN_MAX_WINDOW 64U

static bool scan_enabled = false;
static bool report_enabled = false;
static uint32_t scan_interval = 10U;

static float coherence_samples[HEALTH_SCAN_MAX_WINDOW];
static float delay_samples[HEALTH_SCAN_MAX_WINDOW];
static float drift_samples[HEALTH_SCAN_MAX_WINDOW];
static uint64_t total_samples = 0ULL;
static size_t write_index = 0U;

static HealthScan last_scan = {0};

static size_t effective_window(void)
{
    if (scan_interval == 0U) {
        return 0U;
    }
    size_t window = (size_t)scan_interval;
    if (window > HEALTH_SCAN_MAX_WINDOW) {
        window = HEALTH_SCAN_MAX_WINDOW;
    }
    size_t available = (total_samples < (uint64_t)window) ? (size_t)total_samples : window;
    return available;
}

static void record_sample(float coherence, float delay_seconds, float drift)
{
    coherence_samples[write_index] = isfinite(coherence) ? coherence : 0.0f;
    delay_samples[write_index] = isfinite(delay_seconds) ? delay_seconds : 0.0f;
    drift_samples[write_index] = isfinite(drift) ? drift : 0.0f;

    write_index = (write_index + 1U) % HEALTH_SCAN_MAX_WINDOW;
    ++total_samples;
}

static float window_mean(const float *samples, size_t count)
{
    if (count == 0U) {
        return 0.0f;
    }

    float sum = 0.0f;
    size_t index = (write_index + HEALTH_SCAN_MAX_WINDOW - count) % HEALTH_SCAN_MAX_WINDOW;
    for (size_t i = 0; i < count; ++i) {
        sum += samples[index];
        index = (index + 1U) % HEALTH_SCAN_MAX_WINDOW;
    }
    return sum / (float)count;
}

static float window_variance(const float *samples, size_t count, float mean)
{
    if (count == 0U) {
        return 0.0f;
    }

    float accum = 0.0f;
    size_t index = (write_index + HEALTH_SCAN_MAX_WINDOW - count) % HEALTH_SCAN_MAX_WINDOW;
    for (size_t i = 0; i < count; ++i) {
        float delta = samples[index] - mean;
        accum += delta * delta;
        index = (index + 1U) % HEALTH_SCAN_MAX_WINDOW;
    }
    return accum / (float)count;
}

static void log_scan(const HealthScan *scan)
{
    static const char imprint[] = "health_echo";
    float magnitude = fabsf(scan->breath_hrv);
    uint32_t energy = (uint32_t)fmaxf(1.0f, magnitude * 120.0f);
    soil_trace trace = soil_trace_make(energy, imprint, sizeof(imprint) - 1U);
    soil_write(&trace);
}

void health_scan_init(void)
{
    scan_enabled = false;
    report_enabled = false;
    scan_interval = 10U;
    memset(coherence_samples, 0, sizeof(coherence_samples));
    memset(delay_samples, 0, sizeof(delay_samples));
    memset(drift_samples, 0, sizeof(drift_samples));
    total_samples = 0ULL;
    write_index = 0U;
    memset(&last_scan, 0, sizeof(last_scan));
}

void health_scan_enable(bool enable)
{
    scan_enabled = enable;
}

void health_scan_set_interval(uint32_t interval)
{
    if (interval == 0U) {
        interval = 10U;
    }
    if (interval > HEALTH_SCAN_MAX_WINDOW) {
        interval = HEALTH_SCAN_MAX_WINDOW;
    }
    scan_interval = interval;
}

void health_scan_enable_reporting(bool enable)
{
    report_enabled = enable;
}

void health_scan_step(uint64_t cycle, float coherence, float delay_seconds, float drift)
{
    if (!scan_enabled) {
        return;
    }

    record_sample(coherence, delay_seconds, drift);

    if (scan_interval == 0U || cycle == 0ULL) {
        return;
    }
    if (cycle % (uint64_t)scan_interval != 0ULL) {
        return;
    }

    size_t window = effective_window();
    if (window < (size_t)scan_interval) {
        return;
    }

    float coherence_mean = window_mean(coherence_samples, window);
    float delay_mean = window_mean(delay_samples, window);
    float drift_mean = window_mean(drift_samples, window);

    float coherence_var = window_variance(coherence_samples, window, coherence_mean);
    float delay_var = window_variance(delay_samples, window, delay_mean);

    float breath_hrv = 0.0f;
    if (fabsf(delay_mean) > 1e-6f) {
        breath_hrv = delay_var / fabsf(delay_mean);
    }

    last_scan.coherence_var = coherence_var;
    last_scan.delay_var = delay_var;
    last_scan.drift_avg = drift_mean;
    last_scan.breath_hrv = breath_hrv;

    log_scan(&last_scan);

    if (report_enabled) {
        printf("health: coh_var=%.3f delay_var=%.3f drift_avg=%.3f hrv=%.3f\n",
               last_scan.coherence_var,
               last_scan.delay_var,
               last_scan.drift_avg,
               last_scan.breath_hrv);
    }
}
