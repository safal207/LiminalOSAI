#include "council.h"

#include <math.h>
#include <stdbool.h>
#include <stdio.h>

static InnerCouncil council_state_cache;
static bool council_ready = false;

static float clamp_unit(float value)
{
    if (value < -1.0f) {
        return -1.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

static float normalize_vote(float value)
{
    if (!isfinite(value)) {
        return 0.0f;
    }
    return clamp_unit(value * 2.0f);
}

void council_init(void)
{
    council_state_cache.reflection_vote = 0.0f;
    council_state_cache.awareness_vote = 0.0f;
    council_state_cache.coherence_vote = 0.0f;
    council_state_cache.health_vote = 0.0f;
    council_state_cache.final_decision = 0.0f;
    council_ready = false;
}

void council_summon(void)
{
    puts("\n summoning inner council ...");
    puts(" 🜂 reflection | 🜁 awareness | 🜃 coherence | 🜄 health");
}

InnerCouncil council_update(float reflection_stability,
                            float awareness_level,
                            float coherence_level,
                            float health_drift,
                            float decision_threshold)
{
    InnerCouncil result = {0};

    result.reflection_vote = normalize_vote(reflection_stability - 0.5f);
    result.awareness_vote = normalize_vote(awareness_level - 0.5f);
    result.coherence_vote = normalize_vote(coherence_level - 0.5f);
    result.health_vote = -normalize_vote(health_drift - 0.1f);

    float decision = 0.35f * result.coherence_vote +
                     0.25f * result.awareness_vote +
                     0.25f * result.reflection_vote +
                     0.15f * result.health_vote;

    decision = clamp_unit(decision);
    if (!isfinite(decision)) {
        decision = 0.0f;
    }

    float threshold = decision_threshold;
    if (!isfinite(threshold) || threshold < 0.0f) {
        threshold = 0.0f;
    }
    if (fabsf(decision) < threshold) {
        decision = 0.0f;
    }

    result.final_decision = decision;

    council_state_cache = result;
    council_ready = true;
    return result;
}

const InnerCouncil *council_state(void)
{
    if (!council_ready) {
        return NULL;
    }
    return &council_state_cache;
}

