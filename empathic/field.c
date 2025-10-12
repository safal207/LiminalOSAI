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

#define RECOGNITION_WINDOW_MIN EMPATHIC_RECOGNITION_WINDOW_MIN
#define RECOGNITION_WINDOW_MAX EMPATHIC_RECOGNITION_WINDOW_MAX
#define RECOGNITION_WINDOW_DEFAULT EMPATHIC_RECOGNITION_WINDOW_DEFAULT

typedef struct {
    float tension[RECOGNITION_WINDOW_MAX];
    float warmth[RECOGNITION_WINDOW_MAX];
    float harmony[RECOGNITION_WINDOW_MAX];
    int window_size;
    int count;
    int index;
} MicroPatternBuffer;

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
    bool recognition_enabled;
    bool anticipation_trace;
    int trend_window;
    float anticipation_signal;
    bool calm_predicted;
    bool anxiety_predicted;
    MicroPatternBuffer recognition_buffer;
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

static void recognition_reset_buffer(void)
{
    memset(&empathic_state.recognition_buffer, 0, sizeof(empathic_state.recognition_buffer));
    empathic_state.recognition_buffer.window_size = empathic_state.trend_window > 0 ? empathic_state.trend_window : RECOGNITION_WINDOW_DEFAULT;
    if (empathic_state.recognition_buffer.window_size < RECOGNITION_WINDOW_MIN) {
        empathic_state.recognition_buffer.window_size = RECOGNITION_WINDOW_MIN;
    } else if (empathic_state.recognition_buffer.window_size > RECOGNITION_WINDOW_MAX) {
        empathic_state.recognition_buffer.window_size = RECOGNITION_WINDOW_MAX;
    }
    empathic_state.recognition_buffer.count = 0;
    empathic_state.recognition_buffer.index = 0;
    empathic_state.anticipation_signal = 0.5f;
    empathic_state.calm_predicted = false;
    empathic_state.anxiety_predicted = false;
}

static void recognition_push(float tension, float warmth, float harmony)
{
    MicroPatternBuffer *buffer = &empathic_state.recognition_buffer;
    int window = buffer->window_size;
    if (window < RECOGNITION_WINDOW_MIN) {
        window = RECOGNITION_WINDOW_MIN;
        buffer->window_size = window;
    } else if (window > RECOGNITION_WINDOW_MAX) {
        window = RECOGNITION_WINDOW_MAX;
        buffer->window_size = window;
    }

    buffer->tension[buffer->index] = tension;
    buffer->warmth[buffer->index] = warmth;
    buffer->harmony[buffer->index] = harmony;

    buffer->index = (buffer->index + 1) % window;
    if (buffer->count < window) {
        buffer->count += 1;
    }
}

static int recognition_start_index(const MicroPatternBuffer *buffer, int samples)
{
    int index = buffer->index - samples;
    int window = buffer->window_size > 0 ? buffer->window_size : RECOGNITION_WINDOW_DEFAULT;
    if (window <= 0) {
        return 0;
    }
    while (index < 0) {
        index += window;
    }
    return index % window;
}

static float recognition_trend(const float *values, const MicroPatternBuffer *buffer)
{
    int window = buffer->window_size;
    if (window < RECOGNITION_WINDOW_MIN) {
        window = RECOGNITION_WINDOW_MIN;
    }
    int samples = buffer->count < window ? buffer->count : window;
    if (samples < 2) {
        return 0.0f;
    }

    int index = recognition_start_index(buffer, samples);
    float previous = values[index];
    float sum = 0.0f;
    for (int i = 1; i < samples; ++i) {
        index = (index + 1) % window;
        float current = values[index];
        sum += (current - previous);
        previous = current;
    }
    return sum / (float)samples;
}

static void prepare_softening(void)
{
    float tension_target = clamp_unit(empathic_state.field.tension * 0.92f);
    empathic_state.field.tension = clamp_unit(blend(empathic_state.field.tension, tension_target, 0.35f));

    float warmth_target = clamp_unit(empathic_state.field.warmth + 0.04f);
    empathic_state.field.warmth = clamp_unit(blend(empathic_state.field.warmth, warmth_target, 0.25f));
}

static void encourage_expansion(void)
{
    float harmony_target = clamp_unit(empathic_state.field.harmony + 0.05f);
    empathic_state.field.harmony = clamp_unit(blend(empathic_state.field.harmony, harmony_target, 0.30f));

    float warmth_target = clamp_unit(empathic_state.field.warmth + 0.03f);
    empathic_state.field.warmth = clamp_unit(blend(empathic_state.field.warmth, warmth_target, 0.20f));
}

static void recognition_update(void)
{
    if (!empathic_state.recognition_enabled) {
        return;
    }

    recognition_push(empathic_state.field.tension, empathic_state.field.warmth, empathic_state.field.harmony);

    MicroPatternBuffer *buffer = &empathic_state.recognition_buffer;
    if (buffer->count < 2) {
        empathic_state.anticipation_signal = 0.5f;
        empathic_state.calm_predicted = false;
        empathic_state.anxiety_predicted = false;
        return;
    }

    float tension_trend = recognition_trend(buffer->tension, buffer);
    float warmth_trend = recognition_trend(buffer->warmth, buffer);
    float harmony_trend = recognition_trend(buffer->harmony, buffer);

    float anticipation = clamp_unit(0.5f + (warmth_trend - tension_trend + harmony_trend) / 3.0f);
    bool calm = anticipation > 0.70f;
    bool anxious = anticipation < 0.30f;

    bool previous_calm = empathic_state.calm_predicted;
    bool previous_anxious = empathic_state.anxiety_predicted;

    empathic_state.anticipation_signal = anticipation;
    empathic_state.calm_predicted = calm;
    empathic_state.anxiety_predicted = anxious;

    if (anxious) {
        prepare_softening();
    } else if (calm) {
        encourage_expansion();
    }

    if (empathic_state.anticipation_trace) {
        printf("recognition_field: anticipation=%.2f warm_trend=%.3f tension_trend=%.3f harmony_trend=%.3f window=%d\n",
               anticipation,
               warmth_trend,
               tension_trend,
               harmony_trend,
               buffer->window_size);
    }

    if ((calm && !previous_calm) || (anxious && !previous_anxious)) {
        printf("recognition_field: anticipation=%.2f %s\n",
               anticipation,
               calm ? "calm_predicted" : "anxiety_predicted");
    }
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
    empathic_state.recognition_enabled = false;
    empathic_state.anticipation_trace = false;
    empathic_state.trend_window = RECOGNITION_WINDOW_DEFAULT;
    recognition_reset_buffer();
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
    response.anticipation = empathic_state.anticipation_signal;
    response.calm_predicted = empathic_state.recognition_enabled ? empathic_state.calm_predicted : false;
    response.anxiety_predicted = empathic_state.recognition_enabled ? empathic_state.anxiety_predicted : false;

    if (!empathic_active()) {
        if (empathic_state.initialized) {
            empathic_state.target_coherence = clamp_unit(base_target);
            empathic_state.delay_scale = 1.0f;
            empathic_state.coherence_bias = 0.0f;
        }
        response.target_coherence = clamp_unit(base_target);
        response.delay_scale = 1.0f;
        response.coherence_bias = 0.0f;
        response.anticipation = empathic_state.recognition_enabled ? empathic_state.anticipation_signal : 0.5f;
        response.calm_predicted = false;
        response.anxiety_predicted = false;
        return response;
    }

    if (!isfinite(base_target)) {
        base_target = 0.80f;
    }

    update_field(alignment_hint, resonance_hint);
    recognition_update();

    float resonance_center = clamp_unit(resonance_hint);
    empathic_state.resonance = clamp_unit(0.55f + (empathic_state.field.empathy - 0.5f) * 0.45f + (resonance_center - 0.5f) * 0.30f);

    float warmth_delta = (empathic_state.field.warmth - 0.5f) * 0.2f * empathic_state.gain;
    empathic_state.target_coherence = clamp_unit(base_target + warmth_delta);

    float tension_delta = (empathic_state.field.tension - 0.5f) * 0.3f * empathic_state.gain;
    empathic_state.delay_scale = clamp_range(1.0f + tension_delta, 0.7f, 1.35f);

    float harmony_delta = (empathic_state.field.harmony - 0.5f) * 0.05f * empathic_state.gain;
    empathic_state.coherence_bias = clamp_range(harmony_delta, -0.15f, 0.15f);

    if (empathic_state.recognition_enabled) {
        if (empathic_state.anxiety_predicted) {
            empathic_state.delay_scale = clamp_range(empathic_state.delay_scale * 1.05f, 0.70f, 1.35f);
            empathic_state.target_coherence = clamp_unit(empathic_state.target_coherence - 0.04f);
        } else if (empathic_state.calm_predicted) {
            empathic_state.delay_scale = clamp_range(empathic_state.delay_scale * 0.95f, 0.70f, 1.35f);
            empathic_state.target_coherence = clamp_unit(empathic_state.target_coherence + 0.03f);
            empathic_state.coherence_bias = clamp_range(empathic_state.coherence_bias + 0.02f, -0.15f, 0.15f);
        }
    }

    response.field = empathic_state.field;
    response.resonance = empathic_state.resonance;
    response.target_coherence = empathic_state.target_coherence;
    response.delay_scale = empathic_state.delay_scale;
    response.coherence_bias = empathic_state.coherence_bias;
    response.anticipation = empathic_state.anticipation_signal;
    response.calm_predicted = empathic_state.calm_predicted;
    response.anxiety_predicted = empathic_state.anxiety_predicted;

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

void empathic_recognition_enable(bool enable)
{
    empathic_state.recognition_enabled = enable;
    recognition_reset_buffer();
}

void empathic_recognition_trace(bool enable)
{
    empathic_state.anticipation_trace = enable;
}

void empathic_set_trend_window(int window)
{
    if (window < RECOGNITION_WINDOW_MIN) {
        window = RECOGNITION_WINDOW_MIN;
    } else if (window > RECOGNITION_WINDOW_MAX) {
        window = RECOGNITION_WINDOW_MAX;
    }
    empathic_state.trend_window = window;
    recognition_reset_buffer();
}

float empathic_anticipation(void)
{
    return clamp_unit(empathic_state.anticipation_signal);
}

bool empathic_calm_prediction(void)
{
    return empathic_state.recognition_enabled && empathic_state.calm_predicted;
}

bool empathic_anxiety_prediction(void)
{
    return empathic_state.recognition_enabled && empathic_state.anxiety_predicted;
}
