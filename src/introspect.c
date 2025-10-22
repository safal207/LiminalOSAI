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

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#ifndef INTROSPECT_LOG_PATH
#define INTROSPECT_LOG_PATH "logs/introspect.jsonl"
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

static double clamp_unit(double value)
{
    if (value < 0.0) {
        return 0.0;
    }
    if (value > 1.0) {
        return 1.0;
    }
    return value;
}

static void introspect_commit_locked(introspect_state *state, double harmony)
{
    if (!state || !state->stream) {
        return;
    }

    double amp = sanitize_value(state->pending_amp);
    double tempo = sanitize_value(state->pending_tempo);
    double consent = clamp_unit(state->pending_consent);
    double influence = clamp_unit(state->pending_influence);
    double harmony_clamped = clamp_unit(harmony);

    int written = 0;
    if (state->pending_has_dream) {
        double dream = clamp_unit(state->pending_dream);
        written = fprintf(state->stream,
                          "{\"amp\":%.4f,\"tempo\":%.4f,\"consent\":%.4f,\"influence\":%.4f,\"harmony\":%.4f,\"dream\":%.4f}\n",
                          amp,
                          tempo,
                          consent,
                          influence,
                          harmony_clamped,
                          dream);
    } else {
        written = fprintf(state->stream,
                          "{\"amp\":%.4f,\"tempo\":%.4f,\"consent\":%.4f,\"influence\":%.4f,\"harmony\":%.4f}\n",
                          amp,
                          tempo,
                          consent,
                          influence,
                          harmony_clamped);
    }

    if (written >= 0) {
        fflush(state->stream);
    } else {
        state->enabled = false;
    }

    state->pending_has_dream = false;
    state->harmony_line_open = false;
}

void introspect_state_init(introspect_state *state)
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
    state->pending_amp = 0.0;
    state->pending_tempo = 0.0;
    state->pending_consent = 0.0;
    state->pending_influence = 0.0;
    state->pending_dream = 0.0;
    state->pending_has_dream = false;
}

void introspect_enable(introspect_state *state, bool enabled)
{
    if (!state) {
        return;
    }
    state->enabled = enabled;
    if (!enabled) {
        state->harmony_line_open = false;
        state->pending_has_dream = false;
        state->pending_dream = 0.0;
    }
}

void introspect_enable_harmony(introspect_state *state, bool enabled)
{
    if (!state) {
        return;
    }
    state->harmony_enabled = enabled;
    if (!enabled) {
        state->harmony_line_open = false;
        state->last_harmony = 0.0;
        state->pending_has_dream = false;
    }
}

void introspect_finalize(introspect_state *state)
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
    state->pending_has_dream = false;
    state->pending_dream = 0.0;
}

void introspect_tick(introspect_state *state, const introspect_metrics *metrics)
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
    double consent = clamp_unit(sanitize_value(metrics->consent));
    double influence = clamp_unit(sanitize_value(metrics->influence));
    double harmony = clamp_unit(sanitize_value(metrics->harmony));

    double dream_value = metrics->dream;
    bool has_dream = isfinite(dream_value);
    double dream = 0.0;
    if (has_dream) {
        dream = clamp_unit(dream_value);
    }

    state->pending_amp = avg_amp;
    state->pending_tempo = avg_tempo;
    state->pending_consent = consent;
    state->pending_influence = influence;
    state->pending_has_dream = has_dream;
    state->pending_dream = dream;

    state->amp_sum = 0.0;
    state->tempo_sum = 0.0;
    state->sample_count = 0U;

    if (!state->harmony_enabled) {
        introspect_commit_locked(state, harmony);
        state->last_harmony = harmony;
        return;
    }

    state->last_harmony = harmony;
    state->harmony_line_open = true;
}

void introspect_commit(introspect_state *state, double harmony)
{
    if (!state || !state->enabled) {
        return;
    }

    if (!state->harmony_line_open) {
        return;
    }

    double sanitized_harmony = clamp_unit(sanitize_value(harmony));
    state->last_harmony = sanitized_harmony;

    if (!state->stream) {
        return;
    }

    introspect_commit_locked(state, sanitized_harmony);
}
