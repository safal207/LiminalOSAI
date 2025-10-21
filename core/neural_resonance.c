#include "neural_resonance.h"

#include "dream_replay.h"
#include "astro_sync.h"

#include <math.h>
#include <float.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

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

static float clamp_range(float value, float min_value, float max_value)
{
    if (!isfinite(value)) {
        return min_value;
    }
    if (value < min_value) {
        return min_value;
    }
    if (value > max_value) {
        return max_value;
    }
    return value;
}

void resonance_init(NeuralResonance *n)
{
    if (!n) {
        return;
    }
    n->freq_hz = 0.0f;
    n->coherence = 0.5f;
    n->amplitude = 0.6f;
    n->phase_shift = 0.0f;
}

void resonance_update(NeuralResonance *n,
                      const Harmony *h,
                      const Astro *a,
                      const DreamReplay *d,
                      const SynapticBridge *b)
{
    if (!n) {
        return;
    }

    float harmony_baseline = 0.0f;
    float harmony_agreement = 0.5f;
    if (h) {
        harmony_baseline = clamp_unit(h->baseline);
        harmony_agreement = clamp_unit(h->agreement);
    }

    float astro_tempo = 0.0f;
    float astro_memory = 0.0f;
    if (a) {
        astro_tempo = clamp_range(a->tempo, 0.0f, 2.0f);
        astro_memory = clamp_unit(a->memory);
    }

    float dream_blend = 0.0f;
    if (d) {
        dream_blend = clamp_unit(d->blend_factor);
    }

    float bridge_alignment = 0.5f;
    float bridge_stability = 0.5f;
    float bridge_resonance = 0.5f;
    float bridge_phase = 0.0f;
    if (b) {
        bridge_alignment = clamp_unit(b->alignment);
        bridge_stability = clamp_unit(b->stability);
        bridge_resonance = clamp_unit(b->resonance_flow);
        bridge_phase = clamp_range(b->phase_offset, -0.5f, 0.5f);
    }

    float freq = 0.5f * (harmony_baseline + astro_tempo);
    n->freq_hz = isfinite(freq) ? freq : 0.0f;

    float coherence = 0.25f * (harmony_agreement + bridge_stability + dream_blend + astro_memory);
    n->coherence = clamp_unit(coherence);

    float amplitude = n->coherence * 1.2f;
    amplitude *= (0.85f + 0.15f * bridge_alignment);
    amplitude *= (0.9f + 0.2f * bridge_resonance);
    n->amplitude = clamp_range(amplitude, 0.0f, 1.2f);

    float phase_drive = n->freq_hz * (float)M_PI;
    float raw_shift = sinf(phase_drive) * 0.1f + bridge_phase * 0.5f;
    n->phase_shift = clamp_range(raw_shift, -0.25f, 0.25f);
}

float resonance_stability(const NeuralResonance *n)
{
    if (!n) {
        return 0.0f;
    }
    float coherence = clamp_unit(n->coherence);
    float amplitude = clamp_unit(n->amplitude);
    float freq_norm = clamp_unit(n->freq_hz * 0.5f);
    float phase_relax = clamp_unit(1.0f - fabsf(n->phase_shift) * 4.0f);

    float stability = 0.4f * coherence + 0.3f * phase_relax + 0.3f * (0.6f * amplitude + 0.4f * freq_norm);
    return clamp_unit(stability);
}
