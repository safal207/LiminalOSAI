#include "metabolic.h"

#include "awareness.h"
#include "dream.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#ifndef METABOLIC_TRACE_PATH
#define METABOLIC_TRACE_PATH "metabolic_trace.log"
#endif

typedef enum {
    METABOLIC_MODE_BALANCED = 0,
    METABOLIC_MODE_REST,
    METABOLIC_MODE_CREATIVE
} metabolic_mode;

static struct {
    bool enabled;
    bool trace_enabled;
    float rest_threshold;
    float creative_threshold;
    float awareness_scale;
    float stability_shift;
    double delay_scale;
    metabolic_mode mode;
    MetabolicFlow flow;
    FILE *trace_file;
} metabolic_state_data;

static float clamp01(float value)
{
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

static const char *mode_name(metabolic_mode mode)
{
    switch (mode) {
    case METABOLIC_MODE_REST:
        return "rest";
    case METABOLIC_MODE_CREATIVE:
        return "creative";
    case METABOLIC_MODE_BALANCED:
    default:
        return "balanced";
    }
}

static void close_trace_file(void)
{
    if (metabolic_state_data.trace_file) {
        fclose(metabolic_state_data.trace_file);
        metabolic_state_data.trace_file = NULL;
    }
}

static void ensure_trace_file(void)
{
    if (!metabolic_state_data.trace_enabled || metabolic_state_data.trace_file) {
        return;
    }

    metabolic_state_data.trace_file = fopen(METABOLIC_TRACE_PATH, "a");
    if (!metabolic_state_data.trace_file) {
        perror("metabolic trace");
    }
}

static void emit_trace_line(void)
{
    if (!metabolic_state_data.trace_enabled || !metabolic_state_data.enabled) {
        return;
    }

    const MetabolicFlow *flow = &metabolic_state_data.flow;
    printf("meta_echo: in=%.2f out=%.2f bal=%+.2f vit=%.2f\n",
           flow->intake,
           flow->output,
           flow->balance,
           flow->vitality);

    ensure_trace_file();
    if (!metabolic_state_data.trace_file) {
        return;
    }

    fprintf(metabolic_state_data.trace_file,
            "{\"intake\":%.4f,\"output\":%.4f,\"balance\":%.4f,\"vitality\":%.4f,\"mode\":\"%s\"}\n",
            flow->intake,
            flow->output,
            flow->balance,
            flow->vitality,
            mode_name(metabolic_state_data.mode));
    fflush(metabolic_state_data.trace_file);
}

static void set_mode(metabolic_mode mode)
{
    if (!metabolic_state_data.enabled) {
        metabolic_state_data.mode = METABOLIC_MODE_BALANCED;
        metabolic_state_data.awareness_scale = 1.0f;
        metabolic_state_data.stability_shift = 0.0f;
        metabolic_state_data.delay_scale = 1.0;
        return;
    }

    if (metabolic_state_data.mode == mode) {
        return;
    }

    metabolic_state_data.mode = mode;

    switch (mode) {
    case METABOLIC_MODE_REST:
        printf("🌙 entering rest mode...\n");
        metabolic_state_data.awareness_scale = 0.7f;
        metabolic_state_data.stability_shift = 0.10f;
        metabolic_state_data.delay_scale = 1.35;
        awareness_set_coherence_scale(1.20);
        dream_enable(true);
        break;
    case METABOLIC_MODE_CREATIVE:
        printf("☀️ entering creative mode...\n");
        metabolic_state_data.awareness_scale = 1.20f;
        metabolic_state_data.stability_shift = 0.05f;
        metabolic_state_data.delay_scale = 0.85;
        awareness_set_coherence_scale(0.85);
        break;
    case METABOLIC_MODE_BALANCED:
    default:
        printf("🌬️ metabolic flow steady.\n");
        metabolic_state_data.awareness_scale = 1.0f;
        metabolic_state_data.stability_shift = 0.0f;
        metabolic_state_data.delay_scale = 1.0;
        awareness_set_coherence_scale(1.0);
        break;
    }
}

void metabolic_init(void)
{
    memset(&metabolic_state_data, 0, sizeof(metabolic_state_data));
    metabolic_state_data.enabled = false;
    metabolic_state_data.trace_enabled = false;
    metabolic_state_data.rest_threshold = 0.30f;
    metabolic_state_data.creative_threshold = 0.90f;
    metabolic_state_data.awareness_scale = 1.0f;
    metabolic_state_data.stability_shift = 0.0f;
    metabolic_state_data.delay_scale = 1.0;
    metabolic_state_data.mode = METABOLIC_MODE_BALANCED;
    metabolic_state_data.flow.intake = 0.0f;
    metabolic_state_data.flow.output = 0.0f;
    metabolic_state_data.flow.balance = 0.0f;
    metabolic_state_data.flow.vitality = 0.75f;
    metabolic_state_data.flow.recovery_rate = 0.05f;
    close_trace_file();
}

void metabolic_enable(bool enable)
{
    metabolic_state_data.enabled = enable;
    if (!enable) {
        set_mode(METABOLIC_MODE_BALANCED);
    }
}

void metabolic_enable_trace(bool enable)
{
    metabolic_state_data.trace_enabled = enable;
    if (!enable) {
        close_trace_file();
    }
}

void metabolic_set_thresholds(float rest_threshold, float creative_threshold)
{
    metabolic_state_data.rest_threshold = clamp01(rest_threshold);
    metabolic_state_data.creative_threshold = clamp01(creative_threshold);
    if (metabolic_state_data.creative_threshold < metabolic_state_data.rest_threshold) {
        metabolic_state_data.creative_threshold = metabolic_state_data.rest_threshold;
    }
}

static float sanitize(float value)
{
    if (!isfinite(value)) {
        return 0.0f;
    }
    return value;
}

void metabolic_step(float intake, float output)
{
    if (!metabolic_state_data.enabled) {
        return;
    }

    MetabolicFlow *flow = &metabolic_state_data.flow;
    float intake_clean = sanitize(intake);
    float output_clean = sanitize(output);

    if (metabolic_state_data.mode == METABOLIC_MODE_CREATIVE) {
        output_clean += 0.10f;
    } else if (metabolic_state_data.mode == METABOLIC_MODE_REST) {
        output_clean -= 0.05f;
    }

    if (output_clean < 0.0f) {
        output_clean = 0.0f;
    }

    flow->intake = intake_clean;
    flow->output = output_clean;
    flow->balance = flow->intake - flow->output;

    float balanced = tanhf(flow->balance);
    float delta = flow->recovery_rate * balanced;
    if (!isfinite(delta)) {
        delta = 0.0f;
    }
    flow->vitality += delta;

    /* Gentle relaxation towards a sustainable midpoint. */
    const float equilibrium = 0.65f;
    float restore = (equilibrium - flow->vitality) * (flow->recovery_rate * 0.5f);
    if (!isfinite(restore)) {
        restore = 0.0f;
    }
    flow->vitality += restore;

    if (flow->vitality < 0.0f) {
        flow->vitality = 0.0f;
    } else if (flow->vitality > 1.0f) {
        flow->vitality = 1.0f;
    }

    if (flow->vitality > metabolic_state_data.creative_threshold) {
        float excess = flow->vitality - metabolic_state_data.creative_threshold;
        flow->vitality -= excess * 0.7f;
    }
    if (flow->vitality < metabolic_state_data.rest_threshold) {
        float deficit = metabolic_state_data.rest_threshold - flow->vitality;
        flow->vitality += deficit * 0.4f;
    }

    emit_trace_line();

    if (flow->vitality < metabolic_state_data.rest_threshold) {
        set_mode(METABOLIC_MODE_REST);
    } else if (flow->vitality > metabolic_state_data.creative_threshold) {
        set_mode(METABOLIC_MODE_CREATIVE);
    } else {
        set_mode(METABOLIC_MODE_BALANCED);
    }
}

const MetabolicFlow *metabolic_state(void)
{
    if (!metabolic_state_data.enabled) {
        return NULL;
    }
    return &metabolic_state_data.flow;
}

float metabolic_adjust_awareness(float awareness_level)
{
    if (!metabolic_state_data.enabled) {
        return awareness_level;
    }

    float scaled = sanitize(awareness_level) * metabolic_state_data.awareness_scale;
    return clamp01(scaled);
}

float metabolic_adjust_stability(float stability)
{
    if (!metabolic_state_data.enabled) {
        return stability;
    }

    float adjusted = sanitize(stability) + metabolic_state_data.stability_shift;
    return clamp01(adjusted);
}

float metabolic_delay_scale(void)
{
    if (!metabolic_state_data.enabled) {
        return 1.0f;
    }
    return (float)metabolic_state_data.delay_scale;
}

void metabolic_shutdown(void)
{
    close_trace_file();
}
