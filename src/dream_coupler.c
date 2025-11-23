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

DreamCouplerPhase dream_coupler_evaluate(const Metrics *metrics)
{
    if (!metrics) {
        return DREAM_COUPLER_PHASE_REST;
    }

    float harmony = clamp_unit(metrics->harmony);
    float amp = clamp_unit(metrics->amp);
    float tempo = sanitize_non_negative(metrics->tempo);
    float influence = clamp_unit(metrics->influence);

    if (harmony > 0.8f && amp < 0.6f) {
        return DREAM_COUPLER_PHASE_DREAM;
    }
    if (tempo > 1.0f && influence > 0.7f) {
        return DREAM_COUPLER_PHASE_WAKE;
    }
    return DREAM_COUPLER_PHASE_REST;
}

void dream_couple(State *state, Metrics *metrics)
{
    DreamCouplerPhase next_phase = dream_coupler_evaluate(metrics);

    if (metrics) {
        metrics->harmony = clamp_unit(metrics->harmony);
    }
    if (state) {
        state->dream_phase = next_phase;
        state->next_dream_phase = next_phase;
        state->has_dream_preview = false;
    }
}
