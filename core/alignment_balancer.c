#include "alignment_balancer.h"

#include "council.h"
#include "dream.h"

#include <math.h>
#include <stdbool.h>
#include <stddef.h>

static AlignmentBalance balancer_state;
static float base_threshold = 0.90f;
static float base_target = 0.80f;
static bool balancer_ready = false;

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

static float clamp01(float value)
{
    return clamp_range(value, 0.0f, 1.0f);
}

void alignment_balancer_init(float base_dream_threshold, float base_coherence_target)
{
    balancer_ready = true;
    base_threshold = clamp_range(base_dream_threshold, 0.40f, 0.98f);
    base_target = clamp_range(base_coherence_target, 0.50f, 0.98f);

    balancer_state.pid_scale = 1.0f;
    balancer_state.dream_threshold = base_threshold;
    balancer_state.coherence_target = base_target;
    balancer_state.dream_sync = 0.5f;
    balancer_state.council_signal = 0.0f;
    balancer_state.dream_signal = 0.0f;
}

void alignment_balancer_set_base(float base_dream_threshold, float base_coherence_target)
{
    base_threshold = clamp_range(base_dream_threshold, 0.40f, 0.98f);
    base_target = clamp_range(base_coherence_target, 0.50f, 0.98f);
    if (!balancer_ready) {
        alignment_balancer_init(base_threshold, base_target);
        return;
    }
    balancer_state.dream_threshold = base_threshold;
    balancer_state.coherence_target = base_target;
}

static float compute_sleep_pressure(const DreamState *dream, float awareness_level)
{
    float awareness_pressure = clamp_range((0.35f - awareness_level) * 2.4f, -1.0f, 1.0f);

    float dream_signal = 0.0f;
    if (dream) {
        float intensity = dream->dream_intensity;
        if (dream->active) {
            dream_signal = clamp_range((intensity - 0.5f) * 2.0f, -1.0f, 1.0f);
        } else {
            float readiness = dream->entry_threshold;
            if (dream->aligned_threshold > 0.0f) {
                readiness = dream->aligned_threshold;
            }
            dream_signal = clamp_range((readiness - 0.7f) * -1.5f, -1.0f, 1.0f);
        }
    }

    float combined = (dream_signal + awareness_pressure) * 0.5f;
    if (combined < -1.0f) {
        combined = -1.0f;
    } else if (combined > 1.0f) {
        combined = 1.0f;
    }
    return combined;
}

const AlignmentBalance *alignment_balancer_update(const InnerCouncil *council,
                                                  const DreamState *dream,
                                                  float awareness_level,
                                                  float previous_coherence,
                                                  float current_target)
{
    if (!balancer_ready) {
        alignment_balancer_init(base_threshold, base_target);
    }

    float council_signal = 0.0f;
    if (council) {
        council_signal = clamp_range(council->final_decision, -1.0f, 1.0f);
    }

    float sleep_pressure = compute_sleep_pressure(dream, clamp01(awareness_level));
    float coherence_drift = clamp_range((base_target - previous_coherence) * 1.2f, -1.0f, 1.0f);

    float pid_target = 1.0f + council_signal * 0.12f - sleep_pressure * 0.10f - coherence_drift * 0.04f;
    pid_target = clamp_range(pid_target, 0.45f, 1.75f);

    float reference_target = isfinite(current_target) ? current_target : base_target;
    reference_target = clamp_range(reference_target, 0.50f, 0.98f);
    float desired_target = reference_target + council_signal * 0.05f - sleep_pressure * 0.05f;
    desired_target = clamp_range(desired_target, 0.55f, 0.96f);

    float threshold_target = base_threshold + council_signal * 0.05f - sleep_pressure * 0.08f;
    threshold_target = clamp_range(threshold_target, 0.45f, 0.97f);

    float sync_target = clamp01(0.5f + sleep_pressure * 0.30f - council_signal * 0.15f);

    const float smoothing = 0.55f;
    balancer_state.pid_scale = clamp_range(balancer_state.pid_scale * smoothing + pid_target * (1.0f - smoothing),
                                           0.45f,
                                           1.75f);
    balancer_state.coherence_target = clamp_range(balancer_state.coherence_target * smoothing + desired_target * (1.0f - smoothing),
                                                  0.55f,
                                                  0.96f);
    balancer_state.dream_threshold = clamp_range(balancer_state.dream_threshold * smoothing + threshold_target * (1.0f - smoothing),
                                                 0.45f,
                                                 0.97f);
    balancer_state.dream_sync = balancer_state.dream_sync * smoothing + sync_target * (1.0f - smoothing);
    balancer_state.dream_sync = clamp01(balancer_state.dream_sync);

    balancer_state.council_signal = council_signal;
    balancer_state.dream_signal = sleep_pressure;

    return &balancer_state;
}

const AlignmentBalance *alignment_balancer_state(void)
{
    if (!balancer_ready) {
        return NULL;
    }
    return &balancer_state;
}
