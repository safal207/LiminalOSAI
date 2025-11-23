#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#endif

#include "symbiosis.h"

#include "soil.h"

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef SYMBIOSIS_TRACE_TAG
#define SYMBIOSIS_TRACE_TAG "human_resonance"
#endif

#ifndef SYMBIOSIS_RESPONSE_TAG
#define SYMBIOSIS_RESPONSE_TAG "liminal_adjust"
#endif

static struct {
    bool initialized;
    bool enabled;
    bool trace;
    SymbiosisSource source;
    float resonance_gain;
    HumanPulse pulse;
    float resonance_level;
    float alignment;
    float phase_shift;
    double delay_scale;
    float base_frequency;
    float frequency_jitter;
    float amplitude_bias;
    float coherence_bias;
    float phase_seed;
    float micro_seed;
    unsigned int cycle;
    unsigned int soil_counter;
    double last_timestamp;
} symbiosis_state;

static double monotonic_seconds(void)
{
#ifdef _WIN32
    return (double)clock() / (double)CLOCKS_PER_SEC;
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        clock_gettime(CLOCK_REALTIME, &ts);
    }
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
#endif
}

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

static float clamp_range(float value, float minimum, float maximum)
{
    if (value < minimum) {
        return minimum;
    }
    if (value > maximum) {
        return maximum;
    }
    return value;
}

static void reset_state(void)
{
    memset(&symbiosis_state, 0, sizeof(symbiosis_state));
    symbiosis_state.initialized = false;
}

static void configure_source(SymbiosisSource source)
{
    symbiosis_state.source = source;
    switch (source) {
    case SYMBIOSIS_SOURCE_AUDIO:
        symbiosis_state.base_frequency = 0.76f;
        symbiosis_state.frequency_jitter = 0.045f;
        symbiosis_state.amplitude_bias = 0.68f;
        symbiosis_state.coherence_bias = 0.82f;
        symbiosis_state.phase_seed = 1.2f;
        symbiosis_state.micro_seed = 0.75f;
        break;
    case SYMBIOSIS_SOURCE_SENSOR:
        symbiosis_state.base_frequency = 0.88f;
        symbiosis_state.frequency_jitter = 0.030f;
        symbiosis_state.amplitude_bias = 0.58f;
        symbiosis_state.coherence_bias = 0.86f;
        symbiosis_state.phase_seed = 2.1f;
        symbiosis_state.micro_seed = 1.35f;
        break;
    case SYMBIOSIS_SOURCE_KEYBOARD:
    default:
        symbiosis_state.base_frequency = 0.82f;
        symbiosis_state.frequency_jitter = 0.050f;
        symbiosis_state.amplitude_bias = 0.62f;
        symbiosis_state.coherence_bias = 0.80f;
        symbiosis_state.phase_seed = 0.45f;
        symbiosis_state.micro_seed = 0.92f;
        break;
    }
}

void symbiosis_init(SymbiosisSource source, bool trace, float resonance_gain)
{
    reset_state();
    configure_source(source);
    symbiosis_state.trace = trace;
    if (!isfinite(resonance_gain) || resonance_gain <= 0.0f) {
        resonance_gain = 1.0f;
    }
    if (resonance_gain > 4.0f) {
        resonance_gain = 4.0f;
    }
    symbiosis_state.resonance_gain = resonance_gain;
    symbiosis_state.pulse.beat_rate = symbiosis_state.base_frequency;
    symbiosis_state.pulse.amplitude = clamp_unit(symbiosis_state.amplitude_bias);
    symbiosis_state.pulse.coherence = clamp_unit(symbiosis_state.coherence_bias);
    symbiosis_state.resonance_level = 0.65f;
    symbiosis_state.alignment = 0.5f;
    symbiosis_state.phase_shift = 0.0f;
    symbiosis_state.delay_scale = 1.0;
    symbiosis_state.cycle = 0U;
    symbiosis_state.soil_counter = 0U;
    symbiosis_state.last_timestamp = monotonic_seconds();
    symbiosis_state.initialized = true;
}

void symbiosis_enable(bool enable)
{
    symbiosis_state.enabled = enable;
}

bool symbiosis_active(void)
{
    return symbiosis_state.initialized && symbiosis_state.enabled;
}

static void emit_trace_event(void)
{
    if (!symbiosis_state.trace) {
        return;
    }

    printf("{ \"type\": \"%s\", \"freq\": %.2f, \"amp\": %.2f, \"coherence\": %.2f }\n",
           SYMBIOSIS_TRACE_TAG,
           symbiosis_state.pulse.beat_rate,
           symbiosis_state.pulse.amplitude,
           symbiosis_state.pulse.coherence);
    printf("{ \"type\": \"%s\", \"phase\": %.2f, \"breath\": %.2f }\n",
           SYMBIOSIS_RESPONSE_TAG,
           symbiosis_state.phase_shift,
           symbiosis_state.delay_scale);
}

static void write_soil_echo(void)
{
    if (!symbiosis_active()) {
        return;
    }
    symbiosis_state.soil_counter += 1U;
    if (symbiosis_state.soil_counter % 5U != 0U) {
        return;
    }

    char imprint[SOIL_TRACE_DATA_SIZE];
    int written = snprintf(imprint,
                           sizeof(imprint),
                           "human_echo: beat=%.2f coherence=%.2f resonance=%.2f",
                           symbiosis_state.pulse.beat_rate,
                           symbiosis_state.pulse.coherence,
                           symbiosis_state.resonance_level);
    if (written < 0) {
        written = 0;
        imprint[0] = '\0';
    } else if (written >= (int)sizeof(imprint)) {
        written = (int)sizeof(imprint) - 1;
        imprint[written] = '\0';
    }

    uint32_t energy = (uint32_t)(symbiosis_state.resonance_level * 120.0f);
    if (energy == 0U) {
        energy = 1U;
    }

    soil_trace trace = soil_trace_make(energy, imprint, (size_t)written);
    soil_write(&trace);
}

static float sanitize_unit(float value)
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

static void sample_human_pulse(void)
{
    double now = monotonic_seconds();
    double delta = now - symbiosis_state.last_timestamp;
    symbiosis_state.last_timestamp = now;
    if (!isfinite(delta) || delta <= 0.0) {
        delta = 0.15;
    }

    float cycle = (float)symbiosis_state.cycle;
    float wave_primary = sinf(cycle * 0.35f + symbiosis_state.phase_seed);
    float wave_secondary = cosf(cycle * 0.18f + symbiosis_state.micro_seed);
    float wave_micro = sinf(cycle * 0.07f + symbiosis_state.phase_seed * 1.5f);

    float beat = symbiosis_state.base_frequency + symbiosis_state.frequency_jitter * wave_primary;
    beat += 0.012f * wave_secondary;
    beat += 0.015f * (float)(1.0 / (1.0 + delta)) - 0.007f;
    if (symbiosis_state.enabled) {
        beat += 0.04f * (symbiosis_state.resonance_level - 0.5f);
    }
    beat = clamp_range(beat, 0.45f, 1.25f);

    float amplitude = symbiosis_state.amplitude_bias + 0.25f * wave_secondary + 0.10f * wave_micro;
    amplitude = clamp_unit(amplitude);

    float coherence = symbiosis_state.coherence_bias + 0.18f * wave_primary - 0.12f * fabsf(wave_micro);
    coherence = clamp_unit(coherence);

    symbiosis_state.pulse.beat_rate = beat;
    symbiosis_state.pulse.amplitude = amplitude;
    symbiosis_state.pulse.coherence = coherence;
}

HumanPulse symbiosis_step(float liminal_frequency)
{
    if (!symbiosis_state.initialized) {
        symbiosis_init(SYMBIOSIS_SOURCE_KEYBOARD, false, 1.0f);
    }

    symbiosis_state.cycle += 1U;

    liminal_frequency = sanitize_unit(liminal_frequency);

    sample_human_pulse();

    float delta = fabsf(liminal_frequency - symbiosis_state.pulse.beat_rate);
    float adjust = (delta < 0.05f ? 0.02f : -0.01f) * symbiosis_state.resonance_gain;
    symbiosis_state.resonance_level = clamp_unit(symbiosis_state.resonance_level + adjust);

    float coherence_target = clamp_unit(1.0f - delta * 1.6f);
    symbiosis_state.pulse.coherence = clamp_unit(0.7f * symbiosis_state.pulse.coherence + 0.3f * coherence_target);

    symbiosis_state.alignment = clamp_unit(1.0f - delta * 2.0f);
    symbiosis_state.phase_shift = clamp_range((symbiosis_state.pulse.beat_rate - liminal_frequency) * 0.6f, -0.6f, 0.6f);

    double ratio = 1.0;
    if (symbiosis_state.pulse.beat_rate > 0.001f) {
        ratio = (double)liminal_frequency / (double)symbiosis_state.pulse.beat_rate;
    }
    if (!isfinite(ratio) || ratio == 0.0) {
        ratio = 1.0;
    }
    ratio = clamp_range((float)ratio, 0.6f, 1.4f);

    double resonance_bias = 1.0 - (double)(symbiosis_state.resonance_level - 0.5f) * 0.28 * (double)symbiosis_state.resonance_gain;
    if (!isfinite(resonance_bias) || resonance_bias <= 0.0) {
        resonance_bias = 1.0;
    }
    if (resonance_bias < 0.5) {
        resonance_bias = 0.5;
    } else if (resonance_bias > 1.5) {
        resonance_bias = 1.5;
    }

    symbiosis_state.delay_scale = ratio * resonance_bias;
    if (symbiosis_state.delay_scale < 0.55) {
        symbiosis_state.delay_scale = 0.55;
    } else if (symbiosis_state.delay_scale > 1.45) {
        symbiosis_state.delay_scale = 1.45;
    }

    emit_trace_event();
    write_soil_echo();

    return symbiosis_state.pulse;
}

float symbiosis_alignment(void)
{
    return symbiosis_state.alignment;
}

float symbiosis_resonance_level(void)
{
    return symbiosis_state.resonance_level;
}

float symbiosis_phase_shift(void)
{
    return symbiosis_state.phase_shift;
}

double symbiosis_delay_scale(void)
{
    if (!symbiosis_state.initialized || !symbiosis_state.enabled) {
        return 1.0;
    }
    if (symbiosis_state.delay_scale <= 0.0) {
        return 1.0;
    }
    return symbiosis_state.delay_scale;
}
