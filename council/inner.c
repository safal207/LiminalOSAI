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
    council_state_cache.anticipation_vote = 0.0f;
    council_state_cache.anticipation_field_vote = 0.0f;
    council_state_cache.anticipation_level_vote = 0.0f;
    council_state_cache.anticipation_micro_vote = 0.0f;
    council_state_cache.anticipation_trend_vote = 0.0f;
    council_state_cache.final_decision = 0.0f;
    council_ready = false;
}

void council_summon(void)
{
    puts("\n summoning inner council ...");
    puts(" 🜂 reflection | 🜁 awareness | 🜃 coherence | 🜄 health | 🜔 anticipation");
}

InnerCouncil council_update(float reflection_stability,
                            float awareness_level,
                            float coherence_level,
                            float health_drift,
                            float anticipation_field,
                            float anticipation_level,
                            float anticipation_micro,
                            float anticipation_trend,
                            float decision_threshold)
{
    InnerCouncil result = {0};

    result.reflection_vote = normalize_vote(reflection_stability - 0.5f);
    result.awareness_vote = normalize_vote(awareness_level - 0.5f);
    result.coherence_vote = normalize_vote(coherence_level - 0.5f);
    result.health_vote = -normalize_vote(health_drift - 0.1f);
    result.anticipation_field_vote = normalize_vote(anticipation_field - 0.5f);
    result.anticipation_level_vote = normalize_vote(anticipation_level - 0.5f);
    result.anticipation_micro_vote = normalize_vote(anticipation_micro - 0.5f);
    result.anticipation_trend_vote = normalize_vote(anticipation_trend - 0.5f);

    float anticipation_vote = 0.5f * result.anticipation_field_vote +
                              0.2f * result.anticipation_level_vote +
                              0.15f * result.anticipation_micro_vote +
                              0.15f * result.anticipation_trend_vote;
    anticipation_vote = clamp_unit(anticipation_vote);
    if (!isfinite(anticipation_vote)) {
        anticipation_vote = 0.0f;
    }
    result.anticipation_vote = anticipation_vote;

    float decision = 0.30f * result.coherence_vote +
                     0.22f * result.awareness_vote +
                     0.20f * result.reflection_vote +
                     0.13f * result.health_vote +
                     0.15f * result.anticipation_vote;

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

