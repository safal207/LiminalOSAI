#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#endif

#include "empathic.h"

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef EMPATHIC_EVENT_TAG
#define EMPATHIC_EVENT_TAG "empathic_field"
#endif

#ifndef EMPATHIC_ACK_TAG
#define EMPATHIC_ACK_TAG "empathic_ack"
#endif

static struct {
    bool initialized;
    bool enabled;
    bool trace;
    EmpathicSource source;
    float gain;
    EmotionField field;
    float resonance;
    float target_coherence;
    float delay_scale;
    float coherence_bias;
    float base_warmth;
    float base_tension;
    float base_harmony;
    float base_empathy;
    float warmth_phase;
    float tension_phase;
    float harmony_phase;
    float empathy_phase;
    float warmth_freq;
    float tension_freq;
    float harmony_freq;
    float empathy_freq;
    double last_timestamp;
    float last_coherence;
} empathic_state;

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

static float blend(float current, float target, float rate)
{
    if (rate <= 0.0f) {
        return target;
    }
    if (rate >= 1.0f) {
        return target;
    }
    return current + (target - current) * rate;
}

static void reset_state(void)
{
    memset(&empathic_state, 0, sizeof(empathic_state));
    empathic_state.last_coherence = -1.0f;
}

static void configure_source(EmpathicSource source)
{
    empathic_state.source = source;
    switch (source) {
    case EMPATHIC_SOURCE_TEXT:
        empathic_state.base_warmth = 0.64f;
        empathic_state.base_tension = 0.38f;
        empathic_state.base_harmony = 0.70f;
        empathic_state.base_empathy = 0.66f;
        empathic_state.warmth_phase = 0.35f;
        empathic_state.tension_phase = 1.10f;
        empathic_state.harmony_phase = 0.78f;
        empathic_state.empathy_phase = 1.65f;
        empathic_state.warmth_freq = 0.27f;
        empathic_state.tension_freq = 0.43f;
        empathic_state.harmony_freq = 0.18f;
        empathic_state.empathy_freq = 0.32f;
        break;
    case EMPATHIC_SOURCE_SENSOR:
        empathic_state.base_warmth = 0.58f;
        empathic_state.base_tension = 0.48f;
        empathic_state.base_harmony = 0.74f;
        empathic_state.base_empathy = 0.61f;
        empathic_state.warmth_phase = 1.25f;
        empathic_state.tension_phase = 0.52f;
        empathic_state.harmony_phase = 1.72f;
        empathic_state.empathy_phase = 0.94f;
        empathic_state.warmth_freq = 0.34f;
        empathic_state.tension_freq = 0.29f;
        empathic_state.harmony_freq = 0.22f;
        empathic_state.empathy_freq = 0.31f;
        break;
    case EMPATHIC_SOURCE_AUDIO:
    default:
        empathic_state.base_warmth = 0.70f;
        empathic_state.base_tension = 0.42f;
        empathic_state.base_harmony = 0.76f;
        empathic_state.base_empathy = 0.68f;
        empathic_state.warmth_phase = 0.62f;
        empathic_state.tension_phase = 1.48f;
        empathic_state.harmony_phase = 0.94f;
        empathic_state.empathy_phase = 1.26f;
        empathic_state.warmth_freq = 0.31f;
        empathic_state.tension_freq = 0.37f;
        empathic_state.harmony_freq = 0.21f;
        empathic_state.empathy_freq = 0.28f;
        break;
    }
}

void empathic_init(EmpathicSource source, bool trace, float gain)
{
    reset_state();
    configure_source(source);
    empathic_state.trace = trace;
    if (!isfinite(gain) || gain <= 0.0f) {
        gain = 1.0f;
    }
    if (gain > 3.5f) {
        gain = 3.5f;
    }
    empathic_state.gain = gain;
    empathic_state.field.warmth = empathic_state.base_warmth;
    empathic_state.field.tension = empathic_state.base_tension;
    empathic_state.field.harmony = empathic_state.base_harmony;
    empathic_state.field.empathy = empathic_state.base_empathy;
    empathic_state.resonance = 0.65f;
    empathic_state.target_coherence = 0.80f;
    empathic_state.delay_scale = 1.0f;
    empathic_state.coherence_bias = 0.0f;
    empathic_state.last_timestamp = monotonic_seconds();
    empathic_state.initialized = true;
}

void empathic_enable(bool enable)
{
    empathic_state.enabled = enable;
    if (!enable) {
        empathic_state.last_coherence = -1.0f;
    }
}

bool empathic_active(void)
{
    return empathic_state.initialized && empathic_state.enabled;
}

static void update_field(float alignment_hint, float resonance_hint)
{
    double now = monotonic_seconds();
    float dt = (float)(now - empathic_state.last_timestamp);
    if (!isfinite(dt) || dt < 0.0f || dt > 2.0f) {
        dt = 0.2f;
    }
    empathic_state.last_timestamp = now;

    float warmth_wave = sinf((float)now * empathic_state.warmth_freq + empathic_state.warmth_phase);
    float tension_wave = cosf((float)now * empathic_state.tension_freq + empathic_state.tension_phase);
    float harmony_wave = sinf((float)now * empathic_state.harmony_freq + empathic_state.harmony_phase);
    float empathy_wave = cosf((float)now * empathic_state.empathy_freq + empathic_state.empathy_phase);

    float alignment_center = clamp_unit(alignment_hint);
    float resonance_center = clamp_unit(resonance_hint);

    float warmth_target = empathic_state.base_warmth + warmth_wave * 0.12f * empathic_state.gain + (alignment_center - 0.5f) * 0.28f * empathic_state.gain;
    float tension_target = empathic_state.base_tension + tension_wave * 0.15f * empathic_state.gain + (0.5f - alignment_center) * 0.20f * empathic_state.gain;
    float harmony_target = empathic_state.base_harmony + harmony_wave * 0.10f + (1.0f - fabsf(alignment_center - 0.5f)) * 0.18f * empathic_state.gain;
    float empathy_target = empathic_state.base_empathy + empathy_wave * 0.08f + (resonance_center - 0.5f) * 0.22f * empathic_state.gain;

    float blend_rate = clamp_range(dt * 0.35f, 0.05f, 0.35f);
    empathic_state.field.warmth = clamp_unit(blend(empathic_state.field.warmth, warmth_target, blend_rate));
    empathic_state.field.tension = clamp_unit(blend(empathic_state.field.tension, tension_target, blend_rate));
    empathic_state.field.harmony = clamp_unit(blend(empathic_state.field.harmony, harmony_target, blend_rate));
    empathic_state.field.empathy = clamp_unit(blend(empathic_state.field.empathy, empathy_target, blend_rate));
}

EmpathicResponse empathic_step(float base_target, float alignment_hint, float resonance_hint)
{
    EmpathicResponse response;
    response.field = empathic_state.field;
    response.resonance = empathic_state.resonance;
    response.target_coherence = empathic_state.target_coherence;
    response.delay_scale = empathic_state.delay_scale;
    response.coherence_bias = empathic_state.coherence_bias;

    if (!empathic_active()) {
        if (empathic_state.initialized) {
            empathic_state.target_coherence = clamp_unit(base_target);
            empathic_state.delay_scale = 1.0f;
            empathic_state.coherence_bias = 0.0f;
        }
        response.target_coherence = clamp_unit(base_target);
        response.delay_scale = 1.0f;
        response.coherence_bias = 0.0f;
        return response;
    }

    if (!isfinite(base_target)) {
        base_target = 0.80f;
    }

    update_field(alignment_hint, resonance_hint);

    float resonance_center = clamp_unit(resonance_hint);
    empathic_state.resonance = clamp_unit(0.55f + (empathic_state.field.empathy - 0.5f) * 0.45f + (resonance_center - 0.5f) * 0.30f);

    float warmth_delta = (empathic_state.field.warmth - 0.5f) * 0.2f * empathic_state.gain;
    empathic_state.target_coherence = clamp_unit(base_target + warmth_delta);

    float tension_delta = (empathic_state.field.tension - 0.5f) * 0.3f * empathic_state.gain;
    empathic_state.delay_scale = clamp_range(1.0f + tension_delta, 0.7f, 1.35f);

    float harmony_delta = (empathic_state.field.harmony - 0.5f) * 0.05f * empathic_state.gain;
    empathic_state.coherence_bias = clamp_range(harmony_delta, -0.15f, 0.15f);

    response.field = empathic_state.field;
    response.resonance = empathic_state.resonance;
    response.target_coherence = empathic_state.target_coherence;
    response.delay_scale = empathic_state.delay_scale;
    response.coherence_bias = empathic_state.coherence_bias;

    printf("empathic_echo: warmth=%.2f tension=%.2f harmony=%.2f resonance=%.2f\n",
           response.field.warmth,
           response.field.tension,
           response.field.harmony,
           response.resonance);

    if (empathic_state.trace) {
        printf("{ \"type\": \"%s\", \"warmth\": %.2f, \"tension\": %.2f, \"harmony\": %.2f }\n",
               EMPATHIC_EVENT_TAG,
               response.field.warmth,
               response.field.tension,
               response.field.harmony);
        printf("{\"type\":\"%s\",\"resonance\":%.2f}\n",
               EMPATHIC_ACK_TAG,
               response.resonance);
    }

    return response;
}

EmotionField empathic_field(void)
{
    return empathic_state.field;
}

float empathic_resonance(void)
{
    return empathic_state.resonance;
}

double empathic_delay_scale(void)
{
    if (!empathic_active()) {
        return 1.0;
    }
    double scale = (double)empathic_state.delay_scale;
    if (!isfinite(scale) || scale <= 0.0) {
        return 1.0;
    }
    return scale;
}

float empathic_apply_coherence(float base_value)
{
    if (!empathic_active()) {
        return clamp_unit(isfinite(base_value) ? base_value : 0.0f);
    }
    float adjusted = clamp_unit((isfinite(base_value) ? base_value : 0.0f) + empathic_state.coherence_bias);
    empathic_state.last_coherence = adjusted;
    return adjusted;
}

float empathic_coherence_value(float fallback)
{
    if (!empathic_active()) {
        return clamp_unit(isfinite(fallback) ? fallback : 0.0f);
    }
    if (empathic_state.last_coherence >= 0.0f && empathic_state.last_coherence <= 1.0f) {
        return empathic_state.last_coherence;
    }
    return clamp_unit((isfinite(fallback) ? fallback : 0.0f) + empathic_state.coherence_bias);
}

float empathic_target_level(void)
{
    if (!empathic_active()) {
        return clamp_unit(empathic_state.initialized ? empathic_state.target_coherence : 0.80f);
    }
    return clamp_unit(empathic_state.target_coherence);
}
