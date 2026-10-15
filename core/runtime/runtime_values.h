#ifndef LIMINAL_RUNTIME_VALUES_H
#define LIMINAL_RUNTIME_VALUES_H

#include <math.h>

/* Preserve the runtime's existing value and fallback semantics. Strict input
 * validation belongs to kernel_cli_guard, before these helpers are used. */
static inline float clamp_unit(float value)
{
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

static inline float clamp_range(float value, float min_value, float max_value)
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

static inline float sanitize_positive(float value, float fallback)
{
    if (!isfinite(value) || value <= 0.0f) {
        return fallback;
    }
    return value;
}

static inline void normalize_bounds(float *min_value, float *max_value,
                                    float default_min, float default_max)
{
    if (!min_value || !max_value) {
        return;
    }
    float min_sanitized = sanitize_positive(*min_value, default_min);
    float max_sanitized = sanitize_positive(*max_value, default_max);
    if (min_sanitized > max_sanitized) {
        float tmp = min_sanitized;
        min_sanitized = max_sanitized;
        max_sanitized = tmp;
    }
    *min_value = min_sanitized;
    *max_value = max_sanitized;
}

#endif /* LIMINAL_RUNTIME_VALUES_H */
