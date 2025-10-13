#include "anticipation_v2.h"

#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#ifndef ANT2_LOG_PATH
#define ANT2_LOG_PATH "logs/anticipation_v2.log"
#endif

#ifndef ANT2_MEMORY_PATH
#define ANT2_MEMORY_PATH "soil/collective_memory.jsonl"
#endif

static float clamp01(float value)
{
    if (!isfinite(value)) {
        return 0.0f;
    }
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

static float clamp_gain(float value)
{
    if (!isfinite(value)) {
        return 0.0f;
    }
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

static void ensure_directory(const char *path)
{
    if (!path || !*path) {
        return;
    }
    if (mkdir(path, 0777) != 0) {
        if (errno != EEXIST) {
            /* ignore errors; logging is best-effort */
        }
    }
}

void ant2_init(AnticipationV2 *state)
{
    if (!state) {
        return;
    }
    memset(state, 0, sizeof(*state));
    state->gain = 0.6f;
    state->initialized = false;
}

void ant2_set_enabled(AnticipationV2 *state, bool enabled)
{
    if (!state) {
        return;
    }
    state->enabled = enabled;
}

void ant2_set_gain(AnticipationV2 *state, float gain)
{
    if (!state) {
        return;
    }
    state->gain = clamp_gain(gain);
}

void ant2_set_trace(AnticipationV2 *state, bool trace)
{
    if (!state) {
        return;
    }
    state->trace = trace;
}

static void ant2_log_step(const AnticipationV2 *state,
                          float ema,
                          float drift,
                          float prediction,
                          float ff,
                          float influence)
{
    if (!state || (!state->trace && fabsf(ff) < 1e-6f)) {
        return;
    }

    ensure_directory("logs");

    FILE *fp = fopen(ANT2_LOG_PATH, "a");
    if (!fp) {
        return;
    }

    float mae = state->mae;
    float gain = clamp_gain(state->gain);

    fprintf(fp,
            "{\"ema_coh\":%.4f,\"drift\":%.4f,\"pred\":%.4f,\"ff\":%.4f,\"gain\":%.4f,\"influence\":%.4f,\"mae\":%.4f}\n",
            ema,
            drift,
            prediction,
            ff,
            gain,
            influence,
            mae);
    fclose(fp);
}

static void ant2_snapshot_gain(const AnticipationV2 *state, const char *path)
{
    if (!state || !state->enabled) {
        return;
    }
    const char *target = path && *path ? path : ANT2_MEMORY_PATH;
    ensure_directory("soil");
    FILE *fp = fopen(target, "a");
    if (!fp) {
        return;
    }

    time_t now = time(NULL);
    if (now == (time_t)(-1)) {
        now = 0;
    }

    fprintf(fp,
            "{\"type\":\"ant2_snapshot\",\"ant2_gain\":%.4f,\"mae\":%.4f,\"drift\":%.4f,\"ts\":%" PRIuMAX "}\n",
            clamp_gain(state->gain),
            state->mae,
            state->drift,
            (uintmax_t)now);
    fclose(fp);
}

float ant2_step(AnticipationV2 *state,
                float group_coherence,
                float delay_normalized,
                float influence,
                const char *memory_path)
{
    if (!state || !state->enabled) {
        return 0.0f;
    }

    float influence_clamped = clamp01(influence);
    if (influence_clamped <= 0.0f) {
        ant2_log_step(state, state->ema_coh, state->drift, state->last_prediction, 0.0f, 0.0f);
        return 0.0f;
    }

    float coh = clamp01(group_coherence);
    float delay = clamp01(delay_normalized);

    if (!state->initialized) {
        state->ema_coh = coh;
        state->ema_delay = delay;
        state->drift = 0.0f;
        state->mae = 0.0f;
        state->last_prediction = coh;
        state->initialized = true;
    }

    const float ema_alpha = 0.18f;
    const float drift_alpha = 0.30f;
    const float mae_alpha = 0.15f;

    state->ema_coh += ema_alpha * (coh - state->ema_coh);
    state->ema_delay += ema_alpha * (delay - state->ema_delay);

    float drift_sample = state->ema_coh - state->ema_delay;
    state->drift = (1.0f - drift_alpha) * state->drift + drift_alpha * drift_sample;

    float prediction = clamp01(state->ema_coh + state->drift);
    state->last_prediction = prediction;

    float error = prediction - coh;
    float ff_raw = clamp_gain(state->gain) * error;
    if (ff_raw > 0.04f) {
        ff_raw = 0.04f;
    } else if (ff_raw < -0.04f) {
        ff_raw = -0.04f;
    }

    float ff = ff_raw * influence_clamped;

    state->mae = (1.0f - mae_alpha) * state->mae + mae_alpha * fabsf(error);
    state->cycle_count += 1UL;

    ant2_log_step(state, state->ema_coh, state->drift, prediction, ff, influence_clamped);

    if (state->mae < 0.04f && fabsf(state->drift) < 0.02f) {
        state->stable_count += 1U;
        if (state->stable_count >= 4U) {
            ant2_snapshot_gain(state, memory_path);
            state->stable_count = 0U;
        }
    } else {
        state->stable_count = 0U;
    }

    return ff;
}

void ant2_feedback(AnticipationV2 *state, float feedback_delta)
{
    if (!state || !state->enabled) {
        return;
    }
    if (!isfinite(feedback_delta)) {
        return;
    }
    if (feedback_delta > 0.06f) {
        float gain = clamp_gain(state->gain * 0.98f);
        if (gain < 0.02f) {
            gain = 0.02f;
        }
        state->gain = gain;
    }
}
