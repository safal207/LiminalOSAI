#include "awareness.h"

#include "resonant.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#ifndef AWARENESS_SOURCE_ID
#define AWARENESS_SOURCE_ID 7
#endif

static AwarenessState state;
static float last_resonance = -1.0f;
static float last_stability = -1.0f;
static bool auto_tune = false;
static double last_cycle_duration = 0.1;
static float cycle_scale = 1.0f;
static double coherence_scale = 1.0;

static const float RESONANCE_MAX = 12.0f;

static float clamp_unit(float value)
{
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

void awareness_emit_dialogue(float variance)
{
    float level = clamp_unit(isfinite(variance) ? variance : 0.0f);
    bus_emit_wave("dialogue", level);
    printf(" inner council murmurs: dialogue variance %.2f\n", level);
}

void awareness_init(void)
{
    memset(&state, 0, sizeof(state));
    state.awareness_level = 1.0f;
    state.self_coherence = 1.0f;
    state.drift = 0.0f;
    last_resonance = -1.0f;
    last_stability = -1.0f;
    auto_tune = false;
    cycle_scale = 1.0f;
    last_cycle_duration = 0.1;
    coherence_scale = 1.0;
}

void awareness_set_auto_tune(bool enable)
{
    auto_tune = enable;
}

bool awareness_auto_tune_enabled(void)
{
    return auto_tune;
}

AwarenessState awareness_state(void)
{
    return state;
}

bool awareness_update(float resonance_avg, float stability)
{
    float res_norm = 0.0f;
    if (RESONANCE_MAX > 0.0f) {
        res_norm = resonance_avg / RESONANCE_MAX;
    }
    if (!isfinite(res_norm)) {
        res_norm = 0.0f;
    }
    res_norm = clamp_unit(res_norm);

    float drift = fabsf(stability - res_norm);
    if (!isfinite(drift)) {
        drift = 1.0f;
    }
    drift = clamp_unit(drift);

    state.drift = drift;
    state.awareness_level = clamp_unit(1.0f - drift);

    if (last_resonance >= 0.0f && last_stability >= 0.0f) {
        float resonance_delta = clamp_unit(fabsf(resonance_avg - last_resonance));
        float stability_delta = clamp_unit(fabsf(stability - last_stability));
        float coherence = 1.0f - 0.5f * (resonance_delta + stability_delta);
        state.self_coherence = clamp_unit(coherence);
    } else {
        state.self_coherence = 1.0f;
    }

    last_resonance = resonance_avg;
    last_stability = stability;

    bool wave_emitted = false;
    if (drift > 0.2f) {
        bus_emit_wave("realign", state.awareness_level);
        printf("awareness: %.2f | drift: %.2f | wave: realign\n", state.awareness_level, state.drift);
        printf(" inner council whispers: recalibrating harmony\n");
        cycle_scale = 1.0f + drift * 0.5f;
        if (cycle_scale < 1.0f) {
            cycle_scale = 1.0f;
        }
        wave_emitted = true;
    } else {
        cycle_scale = 1.0f;
    }

    return wave_emitted;
}

double awareness_adjust_delay(double base_seconds)
{
    if (base_seconds <= 0.0) {
        base_seconds = 0.001;
    }

    double scaled = base_seconds;
    if (auto_tune) {
        scaled = base_seconds * (double)cycle_scale * coherence_scale;
    }

    last_cycle_duration = scaled;
    return scaled;
}

double awareness_cycle_duration(void)
{
    return last_cycle_duration;
}

void awareness_set_coherence_scale(double scale)
{
    if (!isfinite(scale) || scale <= 0.0) {
        coherence_scale = 1.0;
        return;
    }

    if (scale < 0.1) {
        scale = 0.1;
    } else if (scale > 5.0) {
        scale = 5.0;
    }

    coherence_scale = scale;
}
