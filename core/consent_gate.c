#include "consent_gate.h"

#include <math.h>
#include <stddef.h>
#include <string.h>

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

static float clamp_score(float value)
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

static void set_reason(ConsentGate *gate, const char *reason)
{
    if (!gate) {
        return;
    }
    if (!reason || !*reason) {
        gate->last_reason[0] = '\0';
        return;
    }
    strncpy(gate->last_reason, reason, CONSENT_GATE_REASON_MAX - 1);
    gate->last_reason[CONSENT_GATE_REASON_MAX - 1] = '\0';
}

void consent_gate_init(ConsentGate *gate)
{
    if (!gate) {
        return;
    }
    memset(gate, 0, sizeof(*gate));
    gate->threshold_open = 0.75f;
    gate->threshold_close = 0.60f;
    gate->hysteresis = 0.05f;
    gate->open_bias = 0.0f;
    gate->warmup_cycles = 0U;
    gate->warmup_remaining = 0U;
    gate->refractory_cycles = 0U;
    gate->refractory_remaining = 0U;
    gate->open = false;
    gate->nan_guard = false;
    gate->last_reason[0] = '\0';
}

void consent_gate_set_thresholds(ConsentGate *gate, float open_threshold, float close_threshold)
{
    if (!gate) {
        return;
    }

    float open_clamped = clamp_unit(open_threshold);
    float close_clamped = clamp_unit(close_threshold);
    if (open_clamped < close_clamped) {
        float mid = 0.5f * (open_clamped + close_clamped);
        open_clamped = mid;
        close_clamped = mid;
    }

    gate->threshold_open = open_clamped;
    gate->threshold_close = close_clamped;
}

void consent_gate_set_hysteresis(ConsentGate *gate, float hysteresis)
{
    if (!gate) {
        return;
    }
    if (!isfinite(hysteresis) || hysteresis < 0.0f) {
        hysteresis = 0.0f;
    }
    if (hysteresis > 1.0f) {
        hysteresis = 1.0f;
    }
    gate->hysteresis = hysteresis;
}

void consent_gate_update(ConsentGate *gate,
                         float consent,
                         float trust,
                         float harmony,
                         float presence,
                         float kiss)
{
    if (!gate) {
        return;
    }

    bool invalid = false;
    float inputs[5] = { consent, trust, harmony, presence, kiss };
    for (size_t i = 0; i < 5U; ++i) {
        if (!isfinite(inputs[i])) {
            invalid = true;
            break;
        }
    }

    if (invalid) {
        gate->nan_guard = true;
        gate->consent = 0.0f;
        gate->trust = 0.0f;
        gate->harmony = 0.0f;
        gate->presence = 0.0f;
        gate->kiss = 0.0f;
        gate->score = 0.0f;
        if (gate->refractory_cycles > 0U) {
            gate->refractory_remaining = gate->refractory_cycles;
        }
        gate->open = false;
        set_reason(gate, "nan_guard");
        return;
    }

    gate->nan_guard = false;
    gate->consent = clamp_unit(consent);
    gate->trust = clamp_unit(trust);
    gate->harmony = clamp_unit(harmony);
    gate->presence = clamp_unit(presence);
    gate->kiss = clamp_unit(kiss);

    float bias = gate->open_bias;
    if (!isfinite(bias)) {
        bias = 0.0f;
    }
    if (bias > 1.0f) {
        bias = 1.0f;
    } else if (bias < -1.0f) {
        bias = -1.0f;
    }

    float weighted = 0.30f * gate->consent +
                     0.30f * gate->trust +
                     0.20f * gate->harmony +
                     0.15f * gate->presence +
                     0.05f * gate->kiss +
                     bias;
    gate->score = clamp_score(weighted);

    bool warm_block = false;
    if (gate->warmup_remaining > 0U) {
        warm_block = true;
        gate->warmup_remaining -= 1U;
    }

    bool refractory_block = false;
    if (gate->refractory_remaining > 0U) {
        refractory_block = true;
        gate->refractory_remaining -= 1U;
    }

    const float consent_floor = 0.3f;
    bool forced_block = false;
    if (gate->consent < consent_floor) {
        forced_block = true;
        set_reason(gate, "low_consent");
    }

    float trust_presence = 0.5f * (gate->trust + gate->presence);
    if (!forced_block && trust_presence < 0.5f) {
        forced_block = true;
        set_reason(gate, "trust_presence");
    }

    if (forced_block) {
        gate->open = false;
        if (gate->refractory_cycles > 0U) {
            gate->refractory_remaining = gate->refractory_cycles;
        }
        return;
    }

    float close_threshold = gate->threshold_close - gate->hysteresis;
    if (close_threshold < 0.0f) {
        close_threshold = 0.0f;
    }
    float open_threshold = gate->threshold_open + gate->hysteresis;
    if (open_threshold > 1.0f) {
        open_threshold = 1.0f;
    }

    if (gate->open) {
        if (gate->score < close_threshold) {
            gate->open = false;
            if (gate->refractory_cycles > 0U) {
                gate->refractory_remaining = gate->refractory_cycles;
            }
            set_reason(gate, "score");
        }
        return;
    }

    if (warm_block) {
        set_reason(gate, "warmup");
        return;
    }

    if (refractory_block) {
        set_reason(gate, "refractory");
        return;
    }

    if (gate->score >= open_threshold) {
        gate->open = true;
        set_reason(gate, "");
    } else {
        set_reason(gate, "score");
    }
}

float consent_gate_score(const ConsentGate *gate)
{
    if (!gate) {
        return 0.0f;
    }
    return gate->score;
}

bool consent_gate_is_open(const ConsentGate *gate)
{
    if (!gate) {
        return false;
    }
    return gate->open;
}
