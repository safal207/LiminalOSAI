#include "synaptic_bridge.h"

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

void bridge_init(SynapticBridge *b)
{
    if (!b) {
        return;
    }

    b->plasticity = 0.65f;
    b->retention = 0.75f;
    b->fatigue = 0.0f;
    b->recovery = 0.03f;
}

void bridge_update(SynapticBridge *b,
                   const DreamReplay *d,
                   Harmony *h,
                   Astro *a)
{
    if (!b || !d) {
        return;
    }

    float plasticity = clamp_unit(b->plasticity);
    float retention = clamp_unit(b->retention);
    float recovery = clamp_unit(b->recovery);
    float blend = clamp_unit(d->blend_factor);
    float fatigue_before = clamp_unit(b->fatigue + 0.1f * (1.0f - blend));
    float memory_after = clamp_unit(d->memory_after);
    float gain = memory_after * retention * (1.0f - fatigue_before);

    if (h) {
        float baseline = h->baseline;
        if (!isfinite(baseline)) {
            baseline = 0.0f;
        }
        baseline += gain * plasticity;
        h->baseline = clamp_unit(baseline);
    }

    if (a) {
        float memory = a->memory;
        if (!isfinite(memory)) {
            memory = 0.0f;
        }
        memory += gain * (1.0f - plasticity);
        a->memory = clamp_unit(memory);
    }

    float fatigue_after = fatigue_before * (1.0f - recovery);
    b->fatigue = clamp_unit(fatigue_after);
}

float bridge_stability(const SynapticBridge *b)
{
    if (!b) {
        return 0.0f;
    }

    float fatigue = clamp_unit(b->fatigue);
    float plasticity = clamp_unit(b->plasticity);
    float retention = clamp_unit(b->retention);
    float recovery = clamp_unit(b->recovery);
    float resilience = 1.0f - fatigue;
    float synthesis = 0.5f * (plasticity + retention);
    float recovery_term = 0.5f * recovery;
    float stability = 0.6f * resilience + 0.3f * synthesis + 0.1f * recovery_term;
    return clamp_unit(stability);
}
