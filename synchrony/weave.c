#define _POSIX_C_SOURCE 199309L

#include "weave.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#ifdef _WIN32
#include <windows.h>
#endif

#define WEAVE_MAX_PHASES 16
#define WEAVE_MIN_PHASES 4

static ClockGrid clock_grid = {
    .phase_count = 8,
    .current_phase = 0,
    .phase_time = { 4.0f },
    .sync_quality = 1.0f,
    .latency_avg = 0.0f
};

static const float default_shift_deg[WEAVE_MODULE_COUNT] = {
    0.0f,   /* pulse */
    72.0f,  /* soil */
    144.0f, /* reflection */
    216.0f, /* awareness */
    288.0f, /* council */
    330.0f  /* dream */
};

static const char *module_labels[WEAVE_MODULE_COUNT] = {
    "pulse",
    "soil",
    "reflection",
    "awareness",
    "council",
    "dream"
};

static struct {
    float shift_deg[WEAVE_MODULE_COUNT];
    bool shift_set[WEAVE_MODULE_COUNT];
} weave_config = {
    .shift_deg = {0},
    .shift_set = {false}
};

static int phase_assignment[WEAVE_MAX_PHASES] = {0};
static uint64_t total_phases = 0;
static float drift_measure = 0.0f;
static float latency_measure = 0.0f;
static bool echo_pending = false;
static struct timespec last_phase_time = {0, 0};
static bool last_phase_valid = false;

static float normalize_degrees(float degrees)
{
    if (!isfinite(degrees)) {
        return 0.0f;
    }
    while (degrees < 0.0f) {
        degrees += 360.0f;
    }
    while (degrees >= 360.0f) {
        degrees -= 360.0f;
    }
    return degrees;
}

static float diff_timespec_ms(const struct timespec *start, const struct timespec *end)
{
    if (!start || !end) {
        return 0.0f;
    }

    double sec = (double)end->tv_sec - (double)start->tv_sec;
    double nsec = (double)end->tv_nsec - (double)start->tv_nsec;
    double total_ms = sec * 1000.0 + nsec / 1000000.0;
    if (total_ms < 0.0) {
        total_ms = 0.0;
    }
    return (float)total_ms;
}

static void rebuild_phase_assignment(void)
{
    if (clock_grid.phase_count < WEAVE_MIN_PHASES) {
        clock_grid.phase_count = WEAVE_MIN_PHASES;
    } else if (clock_grid.phase_count > WEAVE_MAX_PHASES) {
        clock_grid.phase_count = WEAVE_MAX_PHASES;
    }

    for (int i = 0; i < clock_grid.phase_count; ++i) {
        phase_assignment[i] = -1;
    }

    struct module_entry {
        int module;
        float shift;
    } entries[WEAVE_MODULE_COUNT];

    for (int i = 0; i < WEAVE_MODULE_COUNT; ++i) {
        float shift = weave_config.shift_set[i] ? weave_config.shift_deg[i] : default_shift_deg[i];
        entries[i].module = i;
        entries[i].shift = normalize_degrees(shift);
    }

    for (int i = 0; i < WEAVE_MODULE_COUNT - 1; ++i) {
        for (int j = i + 1; j < WEAVE_MODULE_COUNT; ++j) {
            if (entries[j].shift < entries[i].shift) {
                struct module_entry tmp = entries[i];
                entries[i] = entries[j];
                entries[j] = tmp;
            }
        }
    }

    for (int idx = 0; idx < WEAVE_MODULE_COUNT; ++idx) {
        int module = entries[idx].module;
        float shift = entries[idx].shift;
        int target = (int)lroundf((shift / 360.0f) * (float)clock_grid.phase_count);
        if (target < 0) {
            target = 0;
        }
        target %= clock_grid.phase_count;
        for (int attempt = 0; attempt < clock_grid.phase_count; ++attempt) {
            int phase_index = (target + attempt) % clock_grid.phase_count;
            if (phase_assignment[phase_index] < 0) {
                phase_assignment[phase_index] = module;
                break;
            }
        }
    }

    int fill_cursor = 0;
    for (int phase = 0; phase < clock_grid.phase_count; ++phase) {
        if (phase_assignment[phase] >= 0) {
            continue;
        }
        phase_assignment[phase] = entries[fill_cursor].module;
        fill_cursor = (fill_cursor + 1) % WEAVE_MODULE_COUNT;
    }
}

static void ensure_phase_time_defaults(void)
{
    const float default_phase_ms = 4.0f;
    for (int i = 0; i < clock_grid.phase_count; ++i) {
        if (clock_grid.phase_time[i] <= 0.0f) {
            clock_grid.phase_time[i] = default_phase_ms;
        }
    }
}

void weave_init(int phases)
{
    if (phases < WEAVE_MIN_PHASES) {
        phases = WEAVE_MIN_PHASES;
    } else if (phases > WEAVE_MAX_PHASES) {
        phases = WEAVE_MAX_PHASES;
    }

    clock_grid.phase_count = phases;
    clock_grid.current_phase = 0;
    clock_grid.sync_quality = 1.0f;
    clock_grid.latency_avg = 0.0f;

    for (int i = 0; i < clock_grid.phase_count; ++i) {
        clock_grid.phase_time[i] = 4.0f;
    }
    for (int i = clock_grid.phase_count; i < WEAVE_MAX_PHASES; ++i) {
        clock_grid.phase_time[i] = 0.0f;
    }

    drift_measure = 0.0f;
    latency_measure = 0.0f;
    echo_pending = false;
    total_phases = 0;
    last_phase_time.tv_sec = 0;
    last_phase_time.tv_nsec = 0;
    last_phase_valid = false;

    rebuild_phase_assignment();
    ensure_phase_time_defaults();
}

void weave_set_phase_shift(size_t module_index, float degrees)
{
    if (module_index >= WEAVE_MODULE_COUNT) {
        return;
    }
    weave_config.shift_deg[module_index] = normalize_degrees(degrees);
    weave_config.shift_set[module_index] = true;
    rebuild_phase_assignment();
}

size_t weave_module_count(void)
{
    return WEAVE_MODULE_COUNT;
}

int weave_module_lookup(const char *name)
{
    if (!name) {
        return -1;
    }
    for (size_t i = 0; i < WEAVE_MODULE_COUNT; ++i) {
        if (strcasecmp(name, module_labels[i]) == 0) {
            return (int)i;
        }
    }
    return -1;
}

const char *weave_module_label(size_t index)
{
    if (index >= WEAVE_MODULE_COUNT) {
        return NULL;
    }
    return module_labels[index];
}

const ClockGrid *weave_clock(void)
{
    return &clock_grid;
}

int weave_current_phase_index(void)
{
    return clock_grid.current_phase;
}

float weave_current_drift(void)
{
    return drift_measure;
}

float weave_current_latency(void)
{
    return latency_measure;
}

float weave_sync_quality(void)
{
    return clock_grid.sync_quality;
}

static void update_metrics(const struct timespec *now)
{
    if (last_phase_valid) {
        float elapsed = diff_timespec_ms(&last_phase_time, now);
        float expected = 0.0f;
        if (clock_grid.current_phase >= 0 && clock_grid.current_phase < clock_grid.phase_count) {
            expected = clock_grid.phase_time[clock_grid.current_phase];
        }
        if (expected <= 0.0f) {
            expected = 4.0f;
        }
        float drift = fabsf(elapsed - expected);
        if (drift_measure <= 0.0f) {
            drift_measure = drift;
        } else {
            drift_measure = drift_measure * 0.82f + drift * 0.18f;
        }
        if (latency_measure <= 0.0f) {
            latency_measure = elapsed;
        } else {
            latency_measure = latency_measure * 0.78f + elapsed * 0.22f;
        }
    }

    last_phase_time = *now;
    last_phase_valid = true;
}

void weave_measure_sync(void)
{
    const float latency_target = 4.0f;
    float latency_score = 1.0f;
    if (latency_target > 0.0f) {
        float deviation = fabsf(latency_measure - latency_target);
        float normalized = deviation / latency_target;
        if (normalized > 1.0f) {
            normalized = 1.0f;
        }
        latency_score = 1.0f - normalized;
    }

    float drift_score = 1.0f;
    const float drift_reference = 5.0f;
    if (drift_reference > 0.0f) {
        float normalized = drift_measure / drift_reference;
        if (normalized > 1.0f) {
            normalized = 1.0f;
        }
        drift_score = 1.0f - normalized;
    }

    float quality = 0.65f * latency_score + 0.35f * drift_score;
    if (quality < 0.0f) {
        quality = 0.0f;
    } else if (quality > 1.0f) {
        quality = 1.0f;
    }
    clock_grid.sync_quality = quality;
    clock_grid.latency_avg = latency_measure;
}

void weave_next_phase(void)
{
    struct timespec now;
#ifdef _WIN32
    time_t now_time = time(NULL);
    now.tv_sec = now_time;
    now.tv_nsec = 0;
#else
    clock_gettime(CLOCK_MONOTONIC, &now);
#endif
    update_metrics(&now);
    weave_measure_sync();

    int next_phase = clock_grid.current_phase + 1;
    if (next_phase >= clock_grid.phase_count) {
        next_phase = 0;
    }
    clock_grid.current_phase = next_phase;

    ++total_phases;
    if (total_phases % 8ULL == 0ULL) {
        echo_pending = true;
    }

    ensure_phase_time_defaults();
    float delay_ms = clock_grid.phase_time[next_phase];
    if (delay_ms < 0.5f) {
        delay_ms = 0.5f;
    }
    double delay_seconds = delay_ms / 1000.0;
    time_t sec = (time_t)delay_seconds;
    double frac = delay_seconds - (double)sec;
    if (frac < 0.0) {
        frac = 0.0;
    }
    long nsec = (long)(frac * 1000000000.0);
    if (nsec < 0) {
        nsec = 0;
    }
    if (nsec >= 1000000000L) {
        sec += nsec / 1000000000L;
        nsec %= 1000000000L;
    }
#ifdef _WIN32
    Sleep((DWORD)(delay_ms));
#else
    struct timespec req = { .tv_sec = sec, .tv_nsec = nsec };
    nanosleep(&req, NULL);
#endif
}

bool weave_should_emit_echo(void)
{
    return echo_pending;
}

void weave_mark_echo_emitted(void)
{
    echo_pending = false;
}

void weave_trace_line(char *buffer, size_t size)
{
    if (!buffer || size == 0) {
        return;
    }
    buffer[0] = '\0';

    int phase_count = clock_grid.phase_count;
    if (phase_count <= 0) {
        return;
    }

    int current_index = clock_grid.current_phase;
    if (current_index < 0 || current_index >= phase_count) {
        current_index = 0;
    }

    int module_index = 0;
    if (current_index < phase_count) {
        module_index = phase_assignment[current_index];
        if (module_index < 0) {
            module_index = 0;
        }
    }

    size_t offset = 0;
    offset += snprintf(buffer + offset, size - offset, "[phase %d/%d] %s",
                       current_index + 1,
                       phase_count,
                       weave_module_label((size_t)module_index));

    for (int step = 1; step < WEAVE_MODULE_COUNT && offset + 1 < size; ++step) {
        int idx = (current_index + step) % phase_count;
        int next_module = phase_assignment[idx];
        if (next_module < 0) {
            continue;
        }
        offset += snprintf(buffer + offset, size - offset, " \342\206\222 %s", weave_module_label((size_t)next_module));
    }

    if (offset + 1 < size) {
        buffer[offset++] = '\n';
    }

    snprintf(buffer + offset, size > offset ? size - offset : 0,
             "drift=%.3f | latency=%.1fms | sync=%.3f\n",
             drift_measure,
             clock_grid.latency_avg,
             clock_grid.sync_quality);
}
