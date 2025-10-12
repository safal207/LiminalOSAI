#include "coherence.h"

#include "awareness.h"
#include "resonant.h"
#include "soil.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#ifndef COHERENCE_SOURCE_ID
#define COHERENCE_SOURCE_ID 11
#endif

static CoherenceField field_state;
static float integral_term = 0.0f;
static float target_level = 0.80f;
static double delay_scale = 1.0;
static double last_delay_seconds = 0.1;
static bool climate_logging = false;
static unsigned long pulse_counter = 0UL;
static float last_adjust = 0.0f;
static float pid_scale_factor = 1.0f;

static const float ENERGY_MAX = 12.0f;
static const float EMA_ALPHA = 0.2f;
static const double MIN_DELAY_SCALE = 0.2;
static const double MAX_DELAY_SCALE = 1.8;

static float clamp01(float value)
{
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

static void emit_wave(const char *tag, float level)
{
    char payload[RESONANT_MSG_DATA_SIZE];
    if (!tag) {
        tag = "climate";
    }

    if (!isfinite(level) || level < 0.0f) {
        level = 0.0f;
    }
    if (level > 1.0f) {
        level = 1.0f;
    }

    int written = snprintf(payload, sizeof(payload), "%s:%.2f", tag, level);
    if (written < 0) {
        written = 0;
        payload[0] = '\0';
    }

    uint32_t energy = (uint32_t)(level * 120.0f);
    if (energy == 0U) {
        energy = 1U;
    }

    resonant_msg msg = resonant_msg_make(COHERENCE_SOURCE_ID, RESONANT_BROADCAST_ID, energy, payload, (size_t)written);
    bus_emit(&msg);
}

static void log_climate(void)
{
    if (!climate_logging) {
        return;
    }
    if (pulse_counter % 5UL != 0UL) {
        return;
    }

    char imprint[SOIL_TRACE_DATA_SIZE];
    int written = snprintf(imprint, sizeof(imprint), "climate_echo c=%.2f", field_state.coherence);
    if (written < 0) {
        written = 0;
        imprint[0] = '\0';
    }

    uint32_t energy = (uint32_t)(field_state.coherence * 100.0f);
    if (energy == 0U) {
        energy = 1U;
    }

    soil_trace trace = soil_trace_make(energy, imprint, (size_t)written);
    soil_write(&trace);
}

void coherence_init(void)
{
    memset(&field_state, 0, sizeof(field_state));
    integral_term = 0.0f;
    target_level = 0.80f;
    delay_scale = 1.0;
    last_delay_seconds = 0.1;
    climate_logging = false;
    pulse_counter = 0UL;
    last_adjust = 0.0f;
}

void coherence_set_target(float target)
{
    target_level = clamp01(target);
}

float coherence_target(void)
{
    return target_level;
}

void coherence_enable_logging(bool enable)
{
    climate_logging = enable;
}

const CoherenceField *coherence_state(void)
{
    return &field_state;
}

double coherence_delay_scale(void)
{
    return delay_scale;
}

void coherence_register_delay(double seconds)
{
    if (!isfinite(seconds) || seconds < 0.0) {
        seconds = 0.0;
    }
    last_delay_seconds = seconds;
}

double coherence_last_delay(void)
{
    return last_delay_seconds;
}

float coherence_adjustment(void)
{
    return last_adjust;
}

void coherence_set_pid_scale(float scale)
{
    if (!isfinite(scale) || scale <= 0.0f) {
        pid_scale_factor = 1.0f;
        return;
    }
    if (scale < 0.2f) {
        scale = 0.2f;
    } else if (scale > 2.0f) {
        scale = 2.0f;
    }
    pid_scale_factor = scale;
}

const CoherenceField *coherence_update(float energy_avg,
                                       float resonance_avg,
                                       float stability_avg,
                                       float awareness_level)
{
    ++pulse_counter;

    float energy_norm = 0.0f;
    if (ENERGY_MAX > 0.0f) {
        energy_norm = energy_avg / ENERGY_MAX;
    }
    float resonance_norm = 0.0f;
    if (ENERGY_MAX > 0.0f) {
        resonance_norm = resonance_avg / ENERGY_MAX;
    }

    energy_norm = clamp01(isfinite(energy_norm) ? energy_norm : 0.0f);
    resonance_norm = clamp01(isfinite(resonance_norm) ? resonance_norm : 0.0f);

    if (pulse_counter == 1UL) {
        field_state.energy_smooth = energy_norm;
        field_state.resonance_smooth = resonance_norm;
    } else {
        field_state.energy_smooth = EMA_ALPHA * energy_norm + (1.0f - EMA_ALPHA) * field_state.energy_smooth;
        field_state.resonance_smooth = EMA_ALPHA * resonance_norm + (1.0f - EMA_ALPHA) * field_state.resonance_smooth;
    }

    field_state.stability_avg = clamp01(isfinite(stability_avg) ? stability_avg : 0.0f);
    field_state.awareness_level = clamp01(isfinite(awareness_level) ? awareness_level : 0.0f);

    float coherence = 0.35f * field_state.awareness_level +
                      0.25f * field_state.stability_avg +
                      0.20f * field_state.resonance_smooth +
                      0.20f * field_state.energy_smooth;
    field_state.coherence = clamp01(isfinite(coherence) ? coherence : 0.0f);

    float err = target_level - field_state.coherence;
    integral_term += err;
    if (integral_term > 1.0f) {
        integral_term = 1.0f;
    } else if (integral_term < -1.0f) {
        integral_term = -1.0f;
    }

    const float kP = 0.15f;
    const float kI = 0.05f;
    last_adjust = (kP * err + kI * integral_term) * pid_scale_factor;

    double scale = 1.0 - (double)last_adjust;
    if (!isfinite(scale)) {
        scale = 1.0;
    }
    if (scale < MIN_DELAY_SCALE) {
        scale = MIN_DELAY_SCALE;
    } else if (scale > MAX_DELAY_SCALE) {
        scale = MAX_DELAY_SCALE;
    }
    delay_scale = scale;

    awareness_set_coherence_scale(delay_scale);

    if (field_state.coherence < 0.5f) {
        emit_wave("soothe", 0.5f - field_state.coherence);
    } else if (field_state.coherence > 0.9f) {
        emit_wave("flow", field_state.coherence);
    }

    log_climate();

    return &field_state;
}
