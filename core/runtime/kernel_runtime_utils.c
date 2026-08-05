#include "kernel_runtime_utils.h"

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

const char *kernel_match_prefix(const char *argument, const char *prefix)
{
    if (!argument || !prefix) {
        return NULL;
    }

    size_t prefix_length = strlen(prefix);
    if (strncmp(argument, prefix, prefix_length) != 0) {
        return NULL;
    }

    return argument + prefix_length;
}

bool kernel_parse_finite_float(const char *text, float *value_out)
{
    if (!text || !*text || !value_out) {
        return false;
    }

    errno = 0;
    char *end = NULL;
    float parsed = strtof(text, &end);
    if (errno == ERANGE || end == text || *end != '\0' || !isfinite(parsed)) {
        return false;
    }

    *value_out = parsed;
    return true;
}

bool kernel_parse_u64(const char *text, uint64_t *value_out)
{
    if (!text || !*text || !value_out || *text == '-') {
        return false;
    }

    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno == ERANGE || end == text || *end != '\0') {
        return false;
    }

    if (parsed > UINT64_MAX) {
        return false;
    }

    *value_out = (uint64_t)parsed;
    return true;
}

bool kernel_parse_positive_u32(const char *text, uint32_t *value_out)
{
    uint64_t parsed = 0;
    if (!kernel_parse_u64(text, &parsed) || parsed == 0 || parsed > UINT32_MAX) {
        return false;
    }

    *value_out = (uint32_t)parsed;
    return true;
}

float kernel_clamp_unit(float value, float fallback)
{
    if (!isfinite(value)) {
        value = fallback;
    }
    if (!isfinite(value)) {
        value = 0.0f;
    }
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

double kernel_sanitize_scale(double scale)
{
    if (!isfinite(scale) || scale <= 0.0) {
        return 1.0;
    }
    return scale;
}

double kernel_apply_delay_scales(double base_delay,
                                 const double *scales,
                                 size_t scale_count,
                                 double fallback_delay,
                                 double minimum_delay,
                                 double maximum_delay)
{
    if (!isfinite(fallback_delay) || fallback_delay <= 0.0) {
        fallback_delay = 0.1;
    }
    if (!isfinite(base_delay) || base_delay <= 0.0) {
        base_delay = fallback_delay;
    }
    if (!isfinite(minimum_delay) || minimum_delay <= 0.0) {
        minimum_delay = fallback_delay;
    }
    if (!isfinite(maximum_delay) || maximum_delay < minimum_delay) {
        maximum_delay = minimum_delay;
    }

    double result = base_delay;
    for (size_t index = 0; index < scale_count; ++index) {
        double scale = scales ? scales[index] : 1.0;
        result *= kernel_sanitize_scale(scale);
        if (!isfinite(result) || result <= 0.0) {
            result = fallback_delay;
            break;
        }
    }

    if (!isfinite(result) || result <= 0.0) {
        result = fallback_delay;
    }
    if (result < minimum_delay) {
        result = minimum_delay;
    } else if (result > maximum_delay) {
        result = maximum_delay;
    }
    return result;
}

bool kernel_parse_phase_shift(const char *argument,
                              const char *prefix,
                              char *module_out,
                              size_t module_capacity,
                              float *degrees_out)
{
    if (!module_out || module_capacity == 0 || !degrees_out) {
        return false;
    }

    const char *rest = kernel_match_prefix(argument, prefix);
    if (!rest || !*rest) {
        return false;
    }

    const char *marker = strstr(rest, "deg=");
    if (!marker || marker == rest) {
        return false;
    }

    size_t module_length = (size_t)(marker - rest);
    if (module_length >= module_capacity) {
        return false;
    }

    const char *value_text = marker + 4;
    float degrees = 0.0f;
    if (!kernel_parse_finite_float(value_text, &degrees)) {
        return false;
    }

    memcpy(module_out, rest, module_length);
    module_out[module_length] = '\0';
    *degrees_out = degrees;
    return true;
}
