#include "trs_adapt.h"

#include <math.h>

static float clampf(float value, float min_value, float max_value)
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

static float sanitize_positive(float value)
{
    if (!isfinite(value) || value < 0.0f) {
        return 0.0f;
    }
    return value;
}

void trs_adapt_init(TRSAdapt *a,
                    float alpha_min,
                    float alpha_max,
                    float target_delta,
                    float k_p,
                    float k_i,
                    float k_d,
                    float initial_alpha)
{
    if (!a) {
        return;
    }

    float min_clamped = clampf(alpha_min, 0.0f, 1.0f);
    float max_clamped = clampf(alpha_max, 0.0f, 1.0f);
    if (min_clamped > max_clamped) {
        float tmp = min_clamped;
        min_clamped = max_clamped;
        max_clamped = tmp;
    }

    a->alpha_min = min_clamped;
    a->alpha_max = max_clamped;
    a->target_delta = sanitize_positive(target_delta);
    a->k_p = isfinite(k_p) ? k_p : 0.4f;
    a->k_i = isfinite(k_i) ? k_i : 0.05f;
    a->k_d = isfinite(k_d) ? k_d : 0.1f;
    a->err_prev = 0.0f;
    a->err_i = 0.0f;
    float initial = clampf(initial_alpha, a->alpha_min, a->alpha_max);
    a->last_alpha = initial;
    a->last_err = 0.0f;
    a->low_delta_count = 0;
}

float trs_adapt_update(TRSAdapt *a, float delta)
{
    if (!a) {
        return 0.0f;
    }

    float safe_delta = sanitize_positive(delta);

    if (safe_delta > 0.15f) {
        a->err_prev = safe_delta - a->target_delta;
        a->err_i = clampf(a->err_i + a->err_prev, -0.05f, 0.05f);
        a->last_alpha = a->alpha_max;
        a->last_err = a->err_prev;
        a->low_delta_count = 0;
        return a->last_alpha;
    }

    if (safe_delta < 0.002f) {
        if (a->low_delta_count < 1000000) {
            a->low_delta_count += 1;
        }
    } else {
        a->low_delta_count = 0;
    }

    float err = safe_delta - a->target_delta;
    a->err_i = clampf(a->err_i + err, -0.05f, 0.05f);
    float err_d = err - a->err_prev;

    float adjustment = a->k_p * err + a->k_i * a->err_i + a->k_d * err_d;
    if (!isfinite(adjustment)) {
        adjustment = 0.0f;
    }

    float next_alpha = a->last_alpha + adjustment;

    if (a->low_delta_count >= 20) {
        next_alpha -= 0.01f;
    }

    next_alpha = clampf(next_alpha, a->alpha_min, a->alpha_max);

    a->err_prev = err;
    a->last_alpha = next_alpha;
    a->last_err = err;

    return next_alpha;
}
