#include "mirror.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#ifndef MIRROR_LOG_PATH
#define MIRROR_LOG_PATH "logs/mirror_trace.log"
#endif

typedef struct {
    float amp_state;
    float tempo_state;
} MirrorState;

static MirrorState mirror_state = {1.0f, 1.0f};
static float mirror_softness = 0.5f;
static bool mirror_trace_enabled = false;
static bool mirror_enabled = false;

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

static void mirror_log(float influence,
                       float energy,
                       float calm,
                       float tempo,
                       float gain_amp,
                       float gain_tempo)
{
    if (!mirror_trace_enabled) {
        return;
    }

    ensure_logs_directory();
    FILE *fp = fopen(MIRROR_LOG_PATH, "a");
    if (!fp) {
        return;
    }

    fprintf(fp,
            "{\"influence\":%.3f,\"energy\":%.3f,\"calm\":%.3f,\"tempo\":%.3f,\"gain_amp\":%.3f,\"gain_tempo\":%.3f,\"softness\":%.3f}\n",
            influence,
            energy,
            calm,
            tempo,
            gain_amp,
            gain_tempo,
            mirror_softness);
    fclose(fp);
}

void mirror_reset(void)
{
    mirror_state.amp_state = 1.0f;
    mirror_state.tempo_state = 1.0f;
}

void mirror_set_softness(float softness)
{
    if (!isfinite(softness)) {
        softness = 0.5f;
    }
    mirror_softness = clampf(softness, 0.1f, 0.9f);
}

void mirror_set_trace(bool enable)
{
    mirror_trace_enabled = enable;
}

void mirror_enable(bool enable)
{
    mirror_enabled = enable;
    if (!enable) {
        mirror_reset();
    }
}

MirrorGains mirror_update(float influence,
                          float energy,
                          float calm,
                          float tempo,
                          float consent)
{
    MirrorGains gains = {1.0f, 1.0f};

    float inf = clampf(isfinite(influence) ? influence : 0.0f, 0.0f, 1.0f);
    float energy_norm = clampf(isfinite(energy) ? energy : 0.0f, 0.0f, 1.0f);
    float calm_norm = clampf(isfinite(calm) ? calm : 0.0f, 0.0f, 1.0f);
    float tempo_norm = clampf(isfinite(tempo) ? tempo : 0.0f, 0.0f, 1.0f);
    float consent_norm = clampf(isfinite(consent) ? consent : 0.0f, 0.0f, 1.0f);

    if (!mirror_enabled || consent_norm < 0.3f || inf <= 0.0f) {
        mirror_reset();
        mirror_log(inf, energy_norm, calm_norm, tempo_norm, gains.gain_amp, gains.gain_tempo);
        return gains;
    }

    float amp_target = 1.0f + (energy_norm - 0.5f) * 0.6f - (calm_norm - 0.5f) * 0.4f;
    float tempo_target = 1.0f + (tempo_norm - 0.5f) * 0.3f - (energy_norm - 0.5f) * 0.2f;

    if (!isfinite(amp_target) || amp_target <= 0.0f) {
        amp_target = 1.0f;
    }
    if (!isfinite(tempo_target) || tempo_target <= 0.0f) {
        tempo_target = 1.0f;
    }

    float softness = mirror_softness;
    mirror_state.amp_state += softness * (amp_target - mirror_state.amp_state);
    mirror_state.tempo_state += softness * (tempo_target - mirror_state.tempo_state);

    mirror_state.amp_state = clampf(mirror_state.amp_state, 0.5f, 1.2f);
    mirror_state.tempo_state = clampf(mirror_state.tempo_state, 0.8f, 1.2f);

    float amp_delta = mirror_state.amp_state - 1.0f;
    float tempo_delta = mirror_state.tempo_state - 1.0f;

    float applied_amp = 1.0f + amp_delta * inf;
    float applied_tempo = 1.0f + tempo_delta * inf;

    if (!isfinite(applied_amp)) {
        applied_amp = 1.0f;
    }
    if (!isfinite(applied_tempo)) {
        applied_tempo = 1.0f;
    }

    gains.gain_amp = clampf(applied_amp, 0.5f, 1.2f);
    gains.gain_tempo = clampf(applied_tempo, 0.8f, 1.2f);

    mirror_log(inf, energy_norm, calm_norm, tempo_norm, gains.gain_amp, gains.gain_tempo);
    return gains;
}
