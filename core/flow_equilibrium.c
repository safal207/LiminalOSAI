#include "flow_equilibrium.h"

#include <limits.h>
#include <math.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#define FLOW_EQUILIBRIUM_LOG_PATH "logs/flow_equilibrium.log"

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

static void ensure_logs_directory(void)
{
#if defined(_WIN32)
    _mkdir("logs");
#else
    struct stat st;
    if (stat("logs", &st) != 0) {
        mkdir("logs", 0777);
    }
#endif
}

static void flow_equilibrium_reset(FlowEquilibrium *fee)
{
    if (!fee) {
        return;
    }
    fee->impulse = 0.0f;
    fee->observation = 0.0f;
    fee->choice = 0.0f;
    fee->balance = 0.0f;
    fee->last_observation = NAN;
    fee->stable_count = 0;
}

void flow_equilibrium_init(FlowEquilibrium *fee, float alpha, float gamma)
{
    if (!fee) {
        return;
    }
    memset(fee, 0, sizeof(*fee));
    fee->alpha = clamp_range(alpha, 0.0f, 1.0f);
    fee->gamma = clamp_range(gamma, 0.0f, 1.0f);
    fee->log = NULL;
    fee->enabled = false;
    flow_equilibrium_reset(fee);
}

void flow_equilibrium_enable(FlowEquilibrium *fee, bool enabled)
{
    if (!fee) {
        return;
    }
    if (enabled && !fee->log) {
        ensure_logs_directory();
        fee->log = fopen(FLOW_EQUILIBRIUM_LOG_PATH, "a");
    }
    if (!enabled && fee->log) {
        fflush(fee->log);
        fclose(fee->log);
        fee->log = NULL;
    }
    if (!enabled) {
        flow_equilibrium_reset(fee);
    }
    fee->enabled = enabled;
}

void flow_equilibrium_finalize(FlowEquilibrium *fee)
{
    if (!fee) {
        return;
    }
    flow_equilibrium_enable(fee, false);
}

bool flow_equilibrium_is_enabled(const FlowEquilibrium *fee)
{
    return fee && fee->enabled;
}

FlowEquilibriumResult flow_equilibrium_update(FlowEquilibrium *fee,
                                              float impulse,
                                              float observation,
                                              float choice,
                                              uint32_t cycle)
{
    FlowEquilibriumResult result = { 1.0f, 0.0f, 0.0f, 0.0f };
    if (!fee || !fee->enabled) {
        return result;
    }

    float alpha = clamp_range(fee->alpha, 0.0f, 1.0f);
    float gamma = clamp_range(fee->gamma, 0.0f, 1.0f);

    float impulse_clean = clamp_unit(impulse);
    float observation_clean = clamp_unit(observation);
    float choice_clean = clamp_unit(choice);

    float blend = alpha > 0.0f ? alpha : 0.5f;
    float keep = 1.0f - blend;

    fee->impulse = keep * fee->impulse + blend * impulse_clean;
    fee->observation = keep * fee->observation + blend * observation_clean;
    fee->choice = keep * fee->choice + blend * choice_clean;

    float balance = fee->impulse - fee->observation;
    fee->balance = balance;

    if (balance > 0.05f) {
        result.tempo_scale = clamp_range(1.0f - balance * 0.5f, 0.7f, 1.0f);
    } else if (balance < -0.08f) {
        float boost = clamp_range(-balance * 0.25f, 0.0f, 0.15f);
        result.impulse_boost += boost;
    }

    float obs_delta = 0.0f;
    if (isfinite(fee->last_observation)) {
        obs_delta = fabsf(observation_clean - fee->last_observation);
    }
    if (!isfinite(fee->last_observation) || obs_delta > 0.02f) {
        fee->stable_count = 0;
    } else {
        if (fee->stable_count < INT_MAX) {
            fee->stable_count += 1;
        }
    }
    fee->last_observation = observation_clean;

    if (fee->stable_count >= 3) {
        float soft_impulse = gamma * (0.5f + 0.5f * fee->choice);
        result.impulse_boost += clamp_range(soft_impulse, 0.0f, 0.3f);
        result.observation_relief = clamp_range(gamma * (1.0f - observation_clean), 0.0f, 0.4f);
        fee->stable_count = 1;
    }

    result.impulse_boost = clamp_range(result.impulse_boost, 0.0f, 0.35f);
    result.choice_delta = clamp_range((fee->choice - 0.5f) * 0.25f, -0.2f, 0.2f);

    if (fee->log) {
        fprintf(fee->log,
                "{\"cycle\":%u,\"impulse\":%.4f,\"observation\":%.4f,\"choice\":%.4f,\"balance\":%.4f,"
                "\"tempo_scale\":%.4f,\"impulse_boost\":%.4f,\"choice_delta\":%.4f,\"observation_relief\":%.4f}\n",
                cycle,
                fee->impulse,
                fee->observation,
                fee->choice,
                balance,
                result.tempo_scale,
                result.impulse_boost,
                result.choice_delta,
                result.observation_relief);
        fflush(fee->log);
    }

    return result;
}
