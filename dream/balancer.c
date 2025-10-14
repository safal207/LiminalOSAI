#include "dream_balance.h"
#include "council.h"
#include "dream.h"

#include <math.h>

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

static float clamp_signed(float value)
{
    if (value < -1.0f) {
        return -1.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

DreamAlignmentBalance dream_alignment_balance(const InnerCouncil *council,
                                              const DreamState *dream,
                                              float anticipation_field,
                                              float anticipation_level,
                                              float anticipation_trend)
{
    DreamAlignmentBalance result = {0.0f, 0.0f, 0.5f};

    float dream_pull = 0.0f;
    if (dream && dream->active) {
        dream_pull = clamp_unit(dream->dream_intensity) * 2.0f - 1.0f;
    }

    float anticipation_vote = 0.0f;
    float council_vote = 0.0f;
    if (council) {
        anticipation_vote = clamp_signed(council->anticipation_vote);
        council_vote = anticipation_vote;
    }

    float anticipation_mix = 0.35f * clamp_unit(anticipation_level) +
                             0.30f * clamp_unit(anticipation_field) +
                             0.35f * clamp_unit(anticipation_trend);
    anticipation_mix = clamp_unit(anticipation_mix);

    float alignment_delta = anticipation_mix * 2.0f - 1.0f;
    alignment_delta += council_vote;
    alignment_delta -= dream_pull;
    alignment_delta = clamp_signed(alignment_delta);

    // unified merge by Codex
    result.balance_strength = clamp_signed(0.6f * alignment_delta + 0.2f * council_vote);
    result.coherence_bias = clamp_signed(alignment_delta * 0.12f + (anticipation_level - 0.5f) * 0.08f);
    result.anticipation_sync = clamp_unit(0.5f + alignment_delta * 0.30f + (anticipation_trend - 0.5f) * 0.20f);

    if (!isfinite(result.balance_strength)) {
        result.balance_strength = 0.0f;
    }
    if (!isfinite(result.coherence_bias)) {
        result.coherence_bias = 0.0f;
    }
    if (!isfinite(result.anticipation_sync)) {
        result.anticipation_sync = 0.5f;
    }

    return result;
}
