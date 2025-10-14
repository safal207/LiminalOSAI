#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#endif

#include "introspect.h"

#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <time.h>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#ifndef INTROSPECT_LOG_PATH
#define INTROSPECT_LOG_PATH "logs/introspect_v1.log"
#endif

static double sanitize_value(double value)
{
    if (!isfinite(value)) {
        return 0.0;
    }
    return value;
}

static void ensure_logs_directory(void)
{
#if defined(_WIN32)
    _mkdir("logs");
#else
    struct stat st;
    if (stat("logs", &st) == 0) {
        return;
    }
    mkdir("logs", 0777);
#endif
}

static void format_timestamp(char *buffer, size_t size)
{
    if (!buffer || size == 0) {
        return;
    }
    time_t now = time(NULL);
    struct tm tm_now;
#if defined(_WIN32)
    gmtime_s(&tm_now, &now);
#else
    gmtime_r(&now, &tm_now);
#endif
    if (strftime(buffer, size, "%Y-%m-%dT%H:%M:%SZ", &tm_now) == 0) {
        if (size > 0) {
            buffer[0] = '\0';
        }
    }
}

void introspect_state_init(State *state)
{
    if (!state) {
        return;
    }
    state->enabled = false;
    state->harmony_enabled = false;
    state->harmony_line_open = false;
    state->cycle_index = 0;
    state->amp_sum = 0.0;
    state->tempo_sum = 0.0;
    state->sample_count = 0;
    state->stream = NULL;
    state->last_harmony = 0.0;
}

void introspect_enable(State *state, bool enabled)
{
    if (!state) {
        return;
    }
    state->enabled = enabled;
    if (!enabled) {
        state->harmony_line_open = false;
    }
}

void introspect_enable_harmony(State *state, bool enabled)
{
    if (!state) {
        return;
    }
    state->harmony_enabled = enabled;
    if (!enabled) {
        state->harmony_line_open = false;
        state->last_harmony = 0.0;
    }
}

void introspect_finalize(State *state)
{
    if (!state) {
        return;
    }
    if (state->stream) {
        fclose(state->stream);
        state->stream = NULL;
    }
    state->amp_sum = 0.0;
    state->tempo_sum = 0.0;
    state->sample_count = 0;
    state->harmony_line_open = false;
    state->last_harmony = 0.0;
}

void introspect_tick(State *state, const Metrics *metrics)
{
    if (!state || !metrics || !state->enabled) {
        return;
    }

    if (!state->stream) {
        ensure_logs_directory();
        state->stream = fopen(INTROSPECT_LOG_PATH, "a");
        if (!state->stream) {
            state->enabled = false;
            return;
        }
    }

    state->amp_sum += sanitize_value(metrics->amp);
    state->tempo_sum += sanitize_value(metrics->tempo);
    if (state->sample_count < UINT32_MAX) {
        state->sample_count += 1U;
    }

    if (state->sample_count == 0U) {
        return;
    }

    ++state->cycle_index;
    double avg_amp = state->amp_sum / (double)state->sample_count;
    double avg_tempo = state->tempo_sum / (double)state->sample_count;

    char timestamp[32];
    format_timestamp(timestamp, sizeof(timestamp));

    double consent = sanitize_value(metrics->consent);
    double influence = sanitize_value(metrics->influence);
    double bond_coh = sanitize_value(metrics->bond_coh);
    double err = sanitize_value(metrics->error_margin);

    if (state->harmony_enabled) {
        if (fprintf(state->stream,
                    "%s cycle=%" PRIu64 " avg_amp=%.4f avg_tempo=%.4f consent=%.4f influence=%.4f bond_coh=%.4f err=%.4f ",
                    timestamp,
                    state->cycle_index,
                    avg_amp,
                    avg_tempo,
                    consent,
                    influence,
                    bond_coh,
                    err) < 0) {
            state->harmony_line_open = false;
        } else {
            state->harmony_line_open = true;
        }
    } else {
        if (fprintf(state->stream,
                    "%s cycle=%" PRIu64 " avg_amp=%.4f avg_tempo=%.4f consent=%.4f influence=%.4f bond_coh=%.4f err=%.4f\n",
                    timestamp,
                    state->cycle_index,
                    avg_amp,
                    avg_tempo,
                    consent,
                    influence,
                    bond_coh,
                    err) >= 0) {
            fflush(state->stream);
        }
        state->harmony_line_open = false;
        state->last_harmony = 0.0;
    }

    state->amp_sum = 0.0;
    state->tempo_sum = 0.0;
    state->sample_count = 0U;
}
