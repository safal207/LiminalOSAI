#include "soil.h"

#include <string.h>

#ifndef SOIL_CAPACITY
#define SOIL_CAPACITY 128
#endif

static soil_trace soil_buffer[SOIL_CAPACITY];
static size_t soil_head = 0;
static size_t soil_count = 0;
static uint64_t soil_pulses = 0;

void soil_init(void)
{
    memset(soil_buffer, 0, sizeof(soil_buffer));
    soil_head = 0;
    soil_count = 0;
    soil_pulses = 0;
}

void soil_trace_record(soil_trace_type type, uint32_t energy)
{
    soil_trace *slot = &soil_buffer[soil_head];
    slot->type = type;
    slot->pulse_id = ++soil_pulses;
    slot->energy = energy;

    soil_head = (soil_head + 1) % SOIL_CAPACITY;
    if (soil_count < SOIL_CAPACITY) {
        ++soil_count;
    }
}

size_t soil_snapshot(soil_trace *out_buffer, size_t max_count)
{
    if (!out_buffer || max_count == 0) {
        return 0;
    }

    size_t to_copy = soil_count < max_count ? soil_count : max_count;
    size_t idx = (soil_head + SOIL_CAPACITY - soil_count) % SOIL_CAPACITY;

    for (size_t i = 0; i < to_copy; ++i) {
        out_buffer[i] = soil_buffer[idx];
        idx = (idx + 1) % SOIL_CAPACITY;
    }

    return to_copy;
}

uint64_t soil_total_pulses(void)
{
    return soil_pulses;
}
