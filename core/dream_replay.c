#include "dream_replay.h"

#include "astro_sync.h"
#include "trs_filter.h"

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

void dream_init(DreamReplay *d)
{
    if (!d) {
        return;
    }

    d->replay_rate = 0.2f;
    d->blend_factor = 0.5f;
    d->decay = 0.01f;
    d->rem = 0.0f;
    d->cycles = 16;
    d->consolidate_mode = false;
    d->memory_projection = 0.6f;
    d->memory_after = 0.6f;
    d->last_gain = 1.0f;
}

void dream_tick(DreamReplay *d,
                const Astro *astro,
                const Harmony *h,
                const TRS *t)
{
    if (!d || !astro) {
        return;
    }

    float astro_memory = clamp_unit(astro->memory);
    float astro_tone = clamp_unit(astro->tone);

    if (astro_memory > 0.6f) {
        d->consolidate_mode = true;
        d->replay_rate = clamp_range(d->replay_rate, 0.05f, 0.35f);
    } else if (astro_memory < 0.55f) {
        d->consolidate_mode = false;
    }

    int micro_cycles = d->cycles;
    if (micro_cycles <= 0) {
        micro_cycles = 1;
    } else if (micro_cycles > 256) {
        micro_cycles = 256;
    }

    float memory_projection = astro_memory;
    float phase = d->rem;
    float gain_sum = 0.0f;

    for (int i = 0; i < micro_cycles; ++i) {
        phase = fmodf(phase + d->replay_rate, 1.0f);
        if (phase < 0.0f) {
            phase += 1.0f;
        }
        float rem_wave = 0.5f + 0.5f * sinf(2.0f * (float)M_PI * phase);
        float harmony_baseline = astro_memory;
        float harmony_coherence = clamp_unit(astro->last_stability);
        float harmony_amp = clamp_unit(astro->last_wave * 0.5f + astro->last_gain * 0.5f);
        if (h) {
            harmony_baseline = clamp_unit(h->baseline);
            harmony_coherence = clamp_unit(h->coherence);
            harmony_amp = clamp_range(h->amplitude, 0.0f, 2.0f);
        }
        float trace_mix = 0.5f * harmony_baseline + 0.5f * harmony_coherence;
        if (t) {
            float influence = clamp_unit(fabsf(t->sm_influence));
            float consent = clamp_unit(fabsf(t->sm_consent));
            float trs_delta = clamp_unit(fabsf(t->sm_influence - t->sm_harmony));
            trace_mix = 0.4f * trace_mix + 0.6f * (0.5f * (influence + consent));
            if (trs_delta > 0.5f) {
                trace_mix *= 0.9f;
            }
        }
        float mode_bias = d->consolidate_mode ? 0.72f : 0.55f;
        float blend = mode_bias * rem_wave + (1.0f - mode_bias) * trace_mix;
        blend = 0.6f * blend + 0.4f * astro_tone;
        d->blend_factor = clamp_unit(blend);
        float effective_decay = d->decay;
        if (!isfinite(effective_decay) || effective_decay < 0.0f) {
            effective_decay = 0.0f;
        } else if (effective_decay > 0.2f) {
            effective_decay = 0.2f;
        }
        if (d->consolidate_mode) {
            effective_decay *= 0.5f;
        }
        float retention = 1.0f - effective_decay * (1.0f - d->blend_factor);
        if (retention < 0.0f) {
            retention = 0.0f;
        }
        memory_projection = clamp_unit(memory_projection * retention + (1.0f - retention) * harmony_baseline);
        memory_projection = fmaxf(memory_projection, astro_memory * 0.96f);
        float micro_gain = 0.9f + 0.2f * d->blend_factor;
        micro_gain += 0.05f * (harmony_amp - 0.5f);
        if (d->consolidate_mode) {
            micro_gain += 0.04f * (rem_wave - 0.5f);
        }
        if (t) {
            float trs_delta = clamp_unit(fabsf(t->sm_influence - t->sm_harmony));
            micro_gain -= 0.05f * trs_delta;
        }
        micro_gain = clamp_range(micro_gain, 0.8f, 1.1f);
        gain_sum += micro_gain;
    }

    d->rem = phase;
    float projected = clamp_unit(memory_projection);
    d->memory_projection = 0.7f * d->memory_projection + 0.3f * projected;
    d->memory_after = d->memory_projection;
    float averaged_gain = gain_sum / (float)micro_cycles;
    averaged_gain = clamp_range(averaged_gain, 0.8f, 1.1f);
    d->last_gain = 0.7f * d->last_gain + 0.3f * averaged_gain;
    d->last_gain = clamp_range(d->last_gain, 0.8f, 1.1f);
}

float dream_feedback(const DreamReplay *d)
{
    if (!d) {
        return 1.0f;
    }
    return clamp_range(d->last_gain, 0.8f, 1.1f);
}
