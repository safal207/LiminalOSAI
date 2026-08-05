#ifndef LIMINAL_KERNEL_RUNTIME_UTILS_H
#define LIMINAL_KERNEL_RUNTIME_UTILS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Return a pointer to the value after prefix, or NULL when it does not match. */
const char *kernel_match_prefix(const char *argument, const char *prefix);

/* Strict parsers: consume the full string and reject overflow, NaN, and infinity. */
bool kernel_parse_finite_float(const char *text, float *value_out);
bool kernel_parse_i64(const char *text, int64_t *value_out);
bool kernel_parse_u64(const char *text, uint64_t *value_out);
bool kernel_parse_positive_u32(const char *text, uint32_t *value_out);

/* Numeric safety helpers used by pulse timing and option validation. */
float kernel_clamp_unit(float value, float fallback);
double kernel_sanitize_scale(double scale);
double kernel_apply_delay_scales(double base_delay,
                                 const double *scales,
                                 size_t scale_count,
                                 double fallback_delay,
                                 double minimum_delay,
                                 double maximum_delay);

/* Parse --phase-shift-<module>deg=<finite number>. */
bool kernel_parse_phase_shift(const char *argument,
                              const char *prefix,
                              char *module_out,
                              size_t module_capacity,
                              float *degrees_out);

#endif /* LIMINAL_KERNEL_RUNTIME_UTILS_H */
