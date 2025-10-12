#include "reflection.h"

#include "soil.h"
#include "symbol.h"

#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define REFLECTION_CAPACITY 32

typedef struct {
    Reflection record;
    char symbols[128];
    uint64_t pulse_index;
} reflection_entry;

static reflection_entry reflection_buffer[REFLECTION_CAPACITY];
static size_t reflection_head = 0;
static size_t reflection_count = 0;
static uint64_t reflection_pulse_counter = 0;
static float last_energy = -1.0f;
static float last_stability = -1.0f;

static uint64_t reflection_timestamp_now(void)
{
    struct timespec ts;
#if defined(CLOCK_REALTIME)
    clock_gettime(CLOCK_REALTIME, &ts);
#else
    ts.tv_sec = time(NULL);
    ts.tv_nsec = 0;
#endif
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void reflection_store(const reflection_entry *entry)
{
    if (!entry) {
        return;
    }

    reflection_buffer[reflection_head] = *entry;
    reflection_head = (reflection_head + 1U) % REFLECTION_CAPACITY;
    if (reflection_count < REFLECTION_CAPACITY) {
        ++reflection_count;
    }
}

static void reflection_write_to_soil(const reflection_entry *entry)
{
    if (!entry) {
        return;
    }

    char imprint[SOIL_TRACE_DATA_SIZE];
    char message[128];
    int written = snprintf(
        message,
        sizeof(message),
        "reflect#%" PRIu64 " e=%.2f r=%.2f s=%.2f sym=%s note=%s",
        entry->pulse_index,
        entry->record.energy_avg,
        entry->record.resonance_avg,
        entry->record.stability,
        entry->symbols,
        entry->record.note);

    if (written < 0) {
        message[0] = '\0';
        written = 0;
    }

    size_t copy_len = (size_t)written;
    if (copy_len >= sizeof(imprint)) {
        copy_len = sizeof(imprint) - 1U;
    }

    memcpy(imprint, message, copy_len);
    imprint[copy_len] = '\0';

    uint32_t energy = (uint32_t)(entry->record.stability * 100.0f + 0.5f);
    if (energy == 0U) {
        energy = 1U;
    }

    soil_trace trace = soil_trace_make(energy, imprint, copy_len);
    soil_write(&trace);
}

static void reflection_format_symbols(char *out, size_t out_size)
{
    if (!out || out_size == 0) {
        return;
    }

    const Symbol *active[16];
    size_t count = symbol_layer_active(active, sizeof(active) / sizeof(active[0]));
    size_t pos = 0;

    if (out_size < 3) {
        if (out_size > 0) {
            out[0] = '\0';
        }
        return;
    }

    out[pos++] = '[';
    if (count == 0) {
        const char *quiet = "quiet";
        size_t quiet_len = strlen(quiet);
        if (quiet_len + pos < out_size) {
            memcpy(out + pos, quiet, quiet_len);
            pos += quiet_len;
        }
    } else {
        for (size_t i = 0; i < count; ++i) {
            const char *key = active[i] ? active[i]->key : "?";
            size_t key_len = strlen(key);
            if (pos + key_len + 2 >= out_size) {
                break;
            }
            memcpy(out + pos, key, key_len);
            pos += key_len;
            if (i + 1U < count) {
                const char separator[] = ", ";
                if (pos + sizeof(separator) - 1 >= out_size) {
                    break;
                }
                memcpy(out + pos, separator, sizeof(separator) - 1);
                pos += sizeof(separator) - 1;
            }
        }
    }

    if (pos + 1 >= out_size) {
        pos = out_size - 2;
    }

    out[pos++] = ']';
    out[pos] = '\0';
}

void reflect_log(float energy, float resonance, float stability, const char *note)
{
    ++reflection_pulse_counter;

    bool should_log = false;
    if (last_energy < 0.0f || last_stability < 0.0f) {
        should_log = true;
    } else {
        float energy_delta = fabsf(energy - last_energy);
        float stability_delta = fabsf(stability - last_stability);
        float energy_reference = fabsf(last_energy) > 0.0001f ? fabsf(last_energy) : 1.0f;
        float stability_reference = fabsf(last_stability) > 0.0001f ? fabsf(last_stability) : 1.0f;

        if ((energy_reference > 0.0f && energy_delta / energy_reference > 0.05f) ||
            (stability_reference > 0.0f && stability_delta / stability_reference > 0.05f)) {
            should_log = true;
        }
    }

    last_energy = energy;
    last_stability = stability;

    if (!should_log) {
        return;
    }

    reflection_entry entry;
    memset(&entry, 0, sizeof(entry));

    entry.record.timestamp = reflection_timestamp_now();
    entry.record.energy_avg = energy;
    entry.record.resonance_avg = resonance;
    entry.record.stability = stability;

    if (note && *note) {
        strncpy(entry.record.note, note, sizeof(entry.record.note) - 1U);
        entry.record.note[sizeof(entry.record.note) - 1U] = '\0';
    } else {
        entry.record.note[0] = '\0';
    }

    reflection_format_symbols(entry.symbols, sizeof(entry.symbols));
    entry.pulse_index = reflection_pulse_counter;

    reflection_store(&entry);
    reflection_write_to_soil(&entry);
}

void reflect_dump(int n)
{
    if (n <= 0 || reflection_count == 0) {
        fputs("Reflection log is quiet.\n", stdout);
        return;
    }

    size_t to_dump = (size_t)n < reflection_count ? (size_t)n : reflection_count;
    size_t start = (reflection_head + REFLECTION_CAPACITY - to_dump) % REFLECTION_CAPACITY;

    for (size_t i = 0; i < to_dump; ++i) {
        const reflection_entry *entry = &reflection_buffer[(start + i) % REFLECTION_CAPACITY];
        fprintf(stdout,
                "Pulse #%" PRIu64 " | energy %.2f | stability %.2f | symbols: %s\n",
                entry->pulse_index,
                entry->record.energy_avg,
                entry->record.stability,
                entry->symbols);
        fprintf(stdout, "note: %s\n", entry->record.note[0] ? entry->record.note : "(silent)");
    }
}
