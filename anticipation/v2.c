#include "anticipation_v2.h"

#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#ifndef ANT2_LOG_PATH
#define ANT2_LOG_PATH "logs/anticipation_v2.log"
#endif

#ifndef ANT2_MEMORY_PATH
#define ANT2_MEMORY_PATH "soil/collective_memory.jsonl"
#endif

static const float EMA_ALPHA = 0.25f;
static const float MAE_ALPHA = 0.15f;
static const float DRIFT_STABILITY_LIMIT = 0.02f;
static const float MAE_STABILITY_LIMIT = 0.04f;
static const float FEEDBACK_WINDUP_DAMPING = 0.97f;

typedef struct {
    bool initialized;
    bool trace_enabled;
    bool prediction_ready;
    bool stable_logged;
    float last_pred_coh;
    float last_pred_delay;
    float last_ff;
    float last_influence;
    float last_ff_rel;
} Ant2Meta;

static Ant2Meta ant2_meta = {false, false, false, false, 0.5f, 1.0f, 0.0f, 0.0f, 0.0f};

static float clampf(float value, float min_value, float max_value)
{
    if (value < min_value) {
        return min_value;
    }
    if (value > max_value) {
        return max_value;
    }
    return value;
}

static void ensure_directory(const char *path)
{
    if (!path || !*path) {
        return;
    }
#if defined(_WIN32)
    _mkdir(path);
#else
    struct stat st;
    if (stat(path, &st) == 0) {
        return;
    }
    mkdir(path, 0777);
#endif
}

static void ant2_log_state(const Ant2 *state, float pred_coh, float pred_delay, float ff, float influence)
{
    if (!ant2_meta.trace_enabled || !state) {
        return;
    }
    ensure_directory("logs");
    FILE *fp = fopen(ANT2_LOG_PATH, "a");
    if (!fp) {
        return;
    }
    fprintf(fp,
            "{\"ema_coh\":%.3f,\"ema_delay\":%.3f,\"drift\":%.3f,\"drift_delay\":%.3f,"
            "\"pred\":%.3f,\"pred_delay\":%.3f,\"ff\":%+.3f,\"ff_rel\":%+.3f,\"gain\":%.3f,"
            "\"influence\":%.3f,\"mae\":%.4f}\n",
            state->ema_coh,
            state->ema_delay,
            state->drift_coh,
            state->drift_del,
            pred_coh,
            pred_delay,
            ff,
            ant2_meta.last_ff_rel,
            state->gain,
            influence,
            state->mae);
    fclose(fp);
}

static void ant2_store_snapshot(const Ant2 *state)
{
    if (!state) {
        return;
    }
    ensure_directory("soil");
    FILE *fp = fopen(ANT2_MEMORY_PATH, "a");
    if (!fp) {
        return;
    }
    time_t now = time(NULL);
    fprintf(fp,
            "{\"type\":\"ant2_snapshot\",\"timestamp\":%ld,\"ant2_gain\":%.3f,"
            "\"ema_coh\":%.3f,\"ema_delay\":%.3f,\"mae\":%.4f}\n",
            (long)now,
            state->gain,
            state->ema_coh,
            state->ema_delay,
            state->mae);
    fclose(fp);
}

void ant2_init(Ant2 *state, float initial_gain)
{
    if (!state) {
        return;
    }
    state->ema_coh = 0.5f;
    state->ema_delay = 1.0f;
    state->drift_coh = 0.0f;
    state->drift_del = 0.0f;
    state->gain = clampf(initial_gain, 0.0f, 1.0f);
    state->mae = 0.0f;

    ant2_meta.initialized = false;
    ant2_meta.trace_enabled = false;
    ant2_meta.prediction_ready = false;
    ant2_meta.stable_logged = false;
    ant2_meta.last_pred_coh = 0.5f;
    ant2_meta.last_pred_delay = 1.0f;
    ant2_meta.last_ff = 0.0f;
    ant2_meta.last_influence = 0.0f;
    ant2_meta.last_ff_rel = 0.0f;
}

void ant2_set_trace(bool enable)
{
    ant2_meta.trace_enabled = enable;
}

float ant2_feedforward(Ant2 *state,
                       float target_coherence,
                       float actual_coherence,
                       float actual_delay_norm,
                       float bond_influence,
                       float *predicted_coherence,
                       float *predicted_delay,
                       float *ff_out)
{
    if (!state) {
        return 1.0f;
    }

    if (!isfinite(actual_coherence)) {
        actual_coherence = state->ema_coh;
    }
    actual_coherence = clampf(actual_coherence, 0.0f, 1.0f);

    if (!isfinite(actual_delay_norm)) {
        actual_delay_norm = state->ema_delay;
    }
    if (actual_delay_norm < 0.0f) {
        actual_delay_norm = 0.0f;
    }

    float prev_ema_coh = state->ema_coh;
    float prev_ema_delay = state->ema_delay;

    if (!ant2_meta.initialized) {
        state->ema_coh = actual_coherence;
        state->ema_delay = actual_delay_norm;
        state->drift_coh = 0.0f;
        state->drift_del = 0.0f;
        state->mae = 0.0f;
        ant2_meta.initialized = true;
    } else {
        state->drift_coh = actual_coherence - prev_ema_coh;
        state->drift_del = actual_delay_norm - prev_ema_delay;
        state->ema_coh = prev_ema_coh + EMA_ALPHA * (actual_coherence - prev_ema_coh);
        state->ema_delay = prev_ema_delay + EMA_ALPHA * (actual_delay_norm - prev_ema_delay);
    }

    if (ant2_meta.prediction_ready) {
        float err_coh = actual_coherence - ant2_meta.last_pred_coh;
        float err_delay = actual_delay_norm - ant2_meta.last_pred_delay;
        float combined = 0.5f * (fabsf(err_coh) + fabsf(err_delay));
        state->mae = (1.0f - MAE_ALPHA) * state->mae + MAE_ALPHA * combined;
    }

    if (!isfinite(target_coherence)) {
        target_coherence = 0.8f;
    }
    target_coherence = clampf(target_coherence, 0.0f, 1.0f);

    if (state->mae > MAE_STABILITY_LIMIT) {
        state->gain *= 0.9f;
    } else {
        state->gain += 0.02f;
    }
    state->gain = clampf(state->gain, 0.0f, 1.0f);

    float pred_coh = state->ema_coh + 0.7f * state->drift_coh;
    float pred_delay = state->ema_delay + 0.7f * state->drift_del;

    ant2_meta.last_pred_coh = pred_coh;
    ant2_meta.last_pred_delay = pred_delay;
    ant2_meta.prediction_ready = true;

    float ff = (target_coherence - pred_coh) * 0.10f;
    ff = clampf(ff, -0.04f, 0.04f);
    float influence = clampf(isfinite(bond_influence) ? bond_influence : 0.0f, 0.0f, 1.0f);
    ff *= influence;

    if (predicted_coherence) {
        *predicted_coherence = pred_coh;
    }
    if (predicted_delay) {
        *predicted_delay = pred_delay;
    }
    if (ff_out) {
        *ff_out = ff;
    }

    ant2_meta.last_ff = ff;
    ant2_meta.last_influence = influence;

    ant2_log_state(state, pred_coh, pred_delay, ff, influence);

    bool stable = state->mae < MAE_STABILITY_LIMIT &&
                  fabsf(state->drift_coh) < DRIFT_STABILITY_LIMIT &&
                  fabsf(state->drift_del) < DRIFT_STABILITY_LIMIT;
    if (stable) {
        if (!ant2_meta.stable_logged) {
            ant2_store_snapshot(state);
            ant2_meta.stable_logged = true;
        }
    } else {
        ant2_meta.stable_logged = false;
    }

    float scale = 1.0f - state->gain * ff;
    if (!isfinite(scale)) {
        scale = 1.0f;
    }
    return scale;
}

void ant2_feedback_adjust(Ant2 *state, float feedback_delta_rel, float windup_threshold)
{
    if (!state) {
        return;
    }
    if (!isfinite(feedback_delta_rel)) {
        return;
    }
    ant2_meta.last_ff_rel = feedback_delta_rel;
    if (!isfinite(windup_threshold) || windup_threshold <= 0.0f) {
        windup_threshold = ANT2_FEEDBACK_WINDUP_THRESHOLD;
    }
    if (fabsf(feedback_delta_rel) > windup_threshold) {
        state->gain *= FEEDBACK_WINDUP_DAMPING;
        state->gain = clampf(state->gain, 0.0f, 1.0f);
    }
}
