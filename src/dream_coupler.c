#include "dream_coupler.h"

#include <math.h>

static float clamp_unit(float value)
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

static float sanitize_non_negative(float value)
{
    if (!isfinite(value) || value < 0.0f) {
        return 0.0f;
    }
    return value;
}

const char *dream_coupler_phase_name(DreamCouplerPhase phase)
{
    switch (phase) {
    case DREAM_COUPLER_PHASE_DREAM:
        return "DREAM";
    case DREAM_COUPLER_PHASE_WAKE:
        return "WAKE";
    case DREAM_COUPLER_PHASE_REST:
    default:
        return "REST";
    }
}

static DreamCouplerPhase dream_coupler_step(DreamCouplerPhase current, const Metrics *metrics)
{
    if (!metrics) {
        return DREAM_COUPLER_PHASE_REST;
    }

    float harmony = clamp_unit(metrics->harmony);
    float amp = clamp_unit(metrics->amp);
    float tempo = sanitize_non_negative(metrics->tempo);
    float influence = clamp_unit(metrics->influence);

    bool dream_ready = harmony > 0.8f && amp < 0.6f;
    bool wake_ready = tempo > 1.0f && influence > 0.7f;

    switch (current) {
    case DREAM_COUPLER_PHASE_REST:
        if (dream_ready) {
            return DREAM_COUPLER_PHASE_DREAM;
        }
        if (wake_ready) {
            return DREAM_COUPLER_PHASE_WAKE;
        }
        return DREAM_COUPLER_PHASE_REST;
    case DREAM_COUPLER_PHASE_DREAM:
        if (wake_ready) {
            return DREAM_COUPLER_PHASE_WAKE;
        }
        return dream_ready ? DREAM_COUPLER_PHASE_DREAM : DREAM_COUPLER_PHASE_REST;
    case DREAM_COUPLER_PHASE_WAKE:
        return wake_ready ? DREAM_COUPLER_PHASE_WAKE : DREAM_COUPLER_PHASE_REST;
    default:
        break;
    }

    return DREAM_COUPLER_PHASE_REST;
}

void dream_couple(State *state, Metrics *metrics)
{
    DreamCouplerPhase current = state ? state->dream_phase : DREAM_COUPLER_PHASE_REST;
    DreamCouplerPhase next_phase = dream_coupler_step(current, metrics);

    if (metrics) {
        metrics->harmony = clamp_unit(metrics->harmony);
    }
    if (state) {
        state->dream_phase = next_phase;
    }
}
