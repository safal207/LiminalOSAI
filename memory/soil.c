#define _POSIX_C_SOURCE 199309L

#include "soil.h"

#include <string.h>
#include <time.h>

static soil_trace soil_buffer[SOIL_CAPACITY];
static size_t soil_head = 0;
static size_t soil_count = 0;

static soil_pre_echo soil_pre_echo_buffer[SOIL_PRE_ECHO_CAPACITY];
static size_t soil_pre_echo_head = 0;
static size_t soil_pre_echo_count = 0;

static void soil_reset_pre_echo(void)
{
    // unified merge by Codex
    memset(soil_pre_echo_buffer, 0, sizeof(soil_pre_echo_buffer));
    soil_pre_echo_head = 0;
    soil_pre_echo_count = 0;
}

static uint64_t soil_now_timestamp(void)
{
    struct timespec ts;
#ifdef _WIN32
    // Windows doesn't have clock_gettime, use GetSystemTimePreciseAsFileTime or time()
    time_t now = time(NULL);
    ts.tv_sec = now;
    ts.tv_nsec = 0;
#elif defined(CLOCK_REALTIME)
    clock_gettime(CLOCK_REALTIME, &ts);
#else
    ts.tv_sec = time(NULL);
    ts.tv_nsec = 0;
#endif
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void soil_init(void)
{
    memset(soil_buffer, 0, sizeof(soil_buffer));
    soil_head = 0;
    soil_count = 0;
    soil_reset_pre_echo(); // unified merge by Codex
}

void soil_pre_echo_clear(void)
{
    soil_reset_pre_echo();
}

void soil_store_pre_echo(const soil_pre_echo *echo)
{
    if (!echo) {
        return;
    }

    soil_pre_echo_buffer[soil_pre_echo_head] = *echo;
    soil_pre_echo_buffer[soil_pre_echo_head].trace.timestamp = soil_now_timestamp(); // unified merge by Codex
    soil_pre_echo_head = (soil_pre_echo_head + 1) % SOIL_PRE_ECHO_CAPACITY;
    if (soil_pre_echo_count < SOIL_PRE_ECHO_CAPACITY) {
        ++soil_pre_echo_count;
    }
}

size_t soil_recent_pre_echo(soil_pre_echo *out_buffer, size_t max_count)
{
    if (!out_buffer || max_count == 0) {
        return 0;
    }

    size_t to_copy = soil_pre_echo_count < max_count ? soil_pre_echo_count : max_count;
    size_t start = (soil_pre_echo_head + SOIL_PRE_ECHO_CAPACITY - to_copy) % SOIL_PRE_ECHO_CAPACITY;

    for (size_t i = 0; i < to_copy; ++i) {
        out_buffer[i] = soil_pre_echo_buffer[(start + i) % SOIL_PRE_ECHO_CAPACITY];
    }

    return to_copy;
}

void soil_write(const soil_trace *trace)
{
    if (!trace) {
        return;
    }

    soil_trace *slot = &soil_buffer[soil_head];
    *slot = *trace;
    slot->timestamp = soil_now_timestamp();

    soil_head = (soil_head + 1) % SOIL_CAPACITY;
    if (soil_count < SOIL_CAPACITY) {
        ++soil_count;
    }
}

soil_trace soil_read_last(void)
{
    soil_trace empty = {0};
    if (soil_count == 0) {
        return empty;
    }

    size_t idx = (soil_head + SOIL_CAPACITY - 1) % SOIL_CAPACITY;
    return soil_buffer[idx];
}

void soil_decay(void)
{
    if (soil_count == 0) {
        return;
    }

    size_t start = (soil_head + SOIL_CAPACITY - soil_count) % SOIL_CAPACITY;
    for (size_t i = 0; i < soil_count; ++i) {
        size_t idx = (start + i) % SOIL_CAPACITY;
        if (soil_buffer[idx].energy > 0) {
            --soil_buffer[idx].energy;
        }
    }
}

size_t soil_recent(soil_trace *out_buffer, size_t max_count)
{
    if (!out_buffer || max_count == 0) {
        return 0;
    }

    size_t to_copy = soil_count < max_count ? soil_count : max_count;
    size_t start = (soil_head + SOIL_CAPACITY - to_copy) % SOIL_CAPACITY;

    for (size_t i = 0; i < to_copy; ++i) {
        out_buffer[i] = soil_buffer[(start + i) % SOIL_CAPACITY];
    }

    return to_copy;
}

soil_trace soil_trace_make(uint32_t energy, const void *data, size_t data_len)
{
    soil_trace trace;
    memset(&trace, 0, sizeof(trace));
    trace.timestamp = soil_now_timestamp();
    trace.energy = energy;

    if (data && data_len > 0) {
        if (data_len > SOIL_TRACE_DATA_SIZE) {
            data_len = SOIL_TRACE_DATA_SIZE;
        }
        memcpy(trace.data, data, data_len);
    }

    return trace;
}

soil_pre_echo soil_pre_echo_make(uint32_t energy,
                                const void *data,
                                size_t data_len,
                                float anticipation_hint,
                                float resonance_hint)
{
    soil_pre_echo echo;
    echo.trace = soil_trace_make(energy, data, data_len);
    echo.anticipation_hint = anticipation_hint; // unified merge by Codex
    echo.resonance_hint = resonance_hint;
    return echo;
}
