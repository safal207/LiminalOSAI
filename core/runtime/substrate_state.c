#include "substrate_state.h"

#include <math.h>

void substrate_state_init(liminal_state *state)
{
    state->breath_rate = 0.72f;
    state->breath_position = 0.0f;
    state->memory_trace = 0.0f;
    state->resonance = 0.50f;
    state->sync_quality = 0.50f;
    state->vitality = 0.60f;
    state->phase_offset = 0.0f;
    state->cycles = 0U;
    state->adaptive_profile = false;
    state->human_affinity_active = false;
}

void substrate_state_remember(liminal_state *state, float imprint)
{
    const float blend = 0.18f;
    state->memory_trace = state->memory_trace * (1.0f - blend) + imprint * blend;
    if (state->memory_trace > 1.0f) {
        state->memory_trace = 1.0f;
    } else if (state->memory_trace < -1.0f) {
        state->memory_trace = -1.0f;
    }
}

void substrate_state_rest(liminal_state *state)
{
    state->vitality += 0.02f;
    if (state->vitality > 1.0f) {
        state->vitality = 1.0f;
    }
    state->breath_rate *= 0.995f;
    if (state->breath_rate < 0.20f) {
        state->breath_rate = 0.20f;
    }
}

void substrate_state_reflect(liminal_state *state)
{
    state->resonance = 0.6f * state->resonance + 0.4f * state->memory_trace;
    if (state->resonance < 0.0f) {
        state->resonance = 0.0f;
    } else if (state->resonance > 1.0f) {
        state->resonance = 1.0f;
    }
}

void substrate_state_pulse(liminal_state *state, float delta)
{
    state->breath_position += state->breath_rate * delta;
    if (state->breath_position >= 1.0f) {
        state->breath_position -= (float)floor(state->breath_position);
        state->cycles += 1U;
    }
    state->sync_quality = 0.70f * state->sync_quality + 0.30f * (1.0f - fabsf(0.5f - state->breath_position));
}
