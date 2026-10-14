#include "kernel_cli_guard.h"
#include "kernel_runtime_utils.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    KERNEL_CLI_FINITE_FLOAT = 0,
    KERNEL_CLI_SIGNED_INTEGER,
    KERNEL_CLI_SIGNED_INT,
    KERNEL_CLI_UNSIGNED_INTEGER,
    KERNEL_CLI_UNSIGNED_U32,
    KERNEL_CLI_POSITIVE_U32,
    KERNEL_CLI_UNSIGNED_U32_BASE0
} kernel_cli_value_kind;

typedef struct {
    const char *prefix;
    kernel_cli_value_kind kind;
} kernel_cli_numeric_rule;

/* These rules do not replace either runtime's option semantics. */
static const kernel_cli_numeric_rule COMMON_NUMERIC_RULES[] = {
    {"--limit=", KERNEL_CLI_UNSIGNED_INTEGER},
    {"--kiss-warmup=", KERNEL_CLI_SIGNED_INTEGER},
    {"--kiss-refrac=", KERNEL_CLI_SIGNED_INTEGER},
    {"--gate-warmup=", KERNEL_CLI_SIGNED_INTEGER},
    {"--gate-refrac=", KERNEL_CLI_SIGNED_INTEGER},
    {"--trs-warmup=", KERNEL_CLI_SIGNED_INTEGER},
    {"--ant2-gain=", KERNEL_CLI_FINITE_FLOAT},
    {"--allow-align=", KERNEL_CLI_FINITE_FLOAT},
    {"--qel-retro=", KERNEL_CLI_FINITE_FLOAT},
    {"--astro-rate=", KERNEL_CLI_FINITE_FLOAT},
    {"--astro-tone=", KERNEL_CLI_FINITE_FLOAT},
    {"--astro-mem=", KERNEL_CLI_FINITE_FLOAT},
    {"--kiss-alpha=", KERNEL_CLI_FINITE_FLOAT},
    {"--gate-open=", KERNEL_CLI_FINITE_FLOAT},
    {"--gate-close=", KERNEL_CLI_FINITE_FLOAT},
    {"--gate-hyst=", KERNEL_CLI_FINITE_FLOAT},
    {"--gate-bias=", KERNEL_CLI_FINITE_FLOAT},
    {"--vse-temp=", KERNEL_CLI_FINITE_FLOAT},
    {"--vse-intent=", KERNEL_CLI_FINITE_FLOAT},
    {"--vse-importance=", KERNEL_CLI_FINITE_FLOAT},
    {"--vse-allow=", KERNEL_CLI_FINITE_FLOAT},
    {"--vse-lambda-p=", KERNEL_CLI_FINITE_FLOAT},
    {"--vse-lambda-x=", KERNEL_CLI_FINITE_FLOAT},
    {"--allow-hold=", KERNEL_CLI_FINITE_FLOAT},
    {"--allow=", KERNEL_CLI_FINITE_FLOAT},
    {"--empathy-gain=", KERNEL_CLI_FINITE_FLOAT},
    {"--recognition-threshold=", KERNEL_CLI_FINITE_FLOAT},
    {"--entangle-ctx=", KERNEL_CLI_UNSIGNED_U32_BASE0},
    {"--amp-min=", KERNEL_CLI_FINITE_FLOAT},
    {"--amp-max=", KERNEL_CLI_FINITE_FLOAT},
    {"--tempo-min=", KERNEL_CLI_FINITE_FLOAT},
    {"--tempo-max=", KERNEL_CLI_FINITE_FLOAT},
    {"--trs-alpha=", KERNEL_CLI_FINITE_FLOAT},
    {"--trs-alpha-min=", KERNEL_CLI_FINITE_FLOAT},
    {"--trs-alpha-max=", KERNEL_CLI_FINITE_FLOAT},
    {"--trs-target-delta=", KERNEL_CLI_FINITE_FLOAT},
    {"--trs-kp=", KERNEL_CLI_FINITE_FLOAT},
    {"--trs-ki=", KERNEL_CLI_FINITE_FLOAT},
    {"--trs-kd=", KERNEL_CLI_FINITE_FLOAT},
};

static const kernel_cli_numeric_rule PULSE_NUMERIC_RULES[] = {
    {"--scan-interval=", KERNEL_CLI_POSITIVE_U32},
    {"--phases=", KERNEL_CLI_SIGNED_INTEGER},
    {"--target=", KERNEL_CLI_FINITE_FLOAT},
    {"--group-target=", KERNEL_CLI_FINITE_FLOAT},
    {"--council-threshold=", KERNEL_CLI_FINITE_FLOAT},
    {"--dream-threshold=", KERNEL_CLI_FINITE_FLOAT},
    {"--resonance-gain=", KERNEL_CLI_FINITE_FLOAT},
    {"--mirror-soft=", KERNEL_CLI_FINITE_FLOAT},
};

static const kernel_cli_numeric_rule SUBSTRATE_NUMERIC_RULES[] = {
    {"--lip-port=", KERNEL_CLI_UNSIGNED_INTEGER},
    {"--lip-interval=", KERNEL_CLI_UNSIGNED_INTEGER},
    {"--erb-pre=", KERNEL_CLI_SIGNED_INTEGER},
    {"--erb-post=", KERNEL_CLI_SIGNED_INTEGER},
    {"--erb-spike=", KERNEL_CLI_FINITE_FLOAT},
    {"--erb-replay-speed=", KERNEL_CLI_FINITE_FLOAT},
    {"--tune-trials=", KERNEL_CLI_SIGNED_INTEGER},
    {"--tune-refine=", KERNEL_CLI_SIGNED_INTEGER},
    {"--tune-max-runs=", KERNEL_CLI_SIGNED_INTEGER},
    {"--tune-seed=", KERNEL_CLI_SIGNED_INT},
    {"--tune-count=", KERNEL_CLI_SIGNED_INTEGER},
    {"--flow-alpha=", KERNEL_CLI_FINITE_FLOAT},
    {"--flow-gamma=", KERNEL_CLI_FINITE_FLOAT},
    {"--dream-cycles=", KERNEL_CLI_SIGNED_INTEGER},
    {"--dream-rate=", KERNEL_CLI_FINITE_FLOAT},
    {"--dream-decay=", KERNEL_CLI_FINITE_FLOAT},
    {"--bridge-plasticity=", KERNEL_CLI_FINITE_FLOAT},
    {"--bridge-retention=", KERNEL_CLI_FINITE_FLOAT},
    {"--bridge-recovery=", KERNEL_CLI_FINITE_FLOAT},
    {"--erb-replay=idx:", KERNEL_CLI_UNSIGNED_U32},
    {"--tune-source=idx:", KERNEL_CLI_UNSIGNED_U32},
};

static bool unsigned_u32_base0_is_valid(const char *value)
{
    if (!value || !*value) {
        return false;
    }
    const char *digits = value;
    while (isspace((unsigned char)*digits)) {
        ++digits;
    }
    if (*digits == '-') {
        return false;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(value, &end, 0);
    return errno != ERANGE && end != value && *end == '\0' && parsed <= UINT32_MAX;
}

static bool value_is_valid(const char *value, kernel_cli_value_kind kind)
{
    float float_value = 0.0f;
    int64_t signed_value = 0;
    uint64_t unsigned_value = 0;
    uint32_t positive_value = 0;

    if (kind == KERNEL_CLI_UNSIGNED_INTEGER || kind == KERNEL_CLI_UNSIGNED_U32 ||
        kind == KERNEL_CLI_POSITIVE_U32) {
        if (!value) {
            return false;
        }
        const char *digits = value;
        while (isspace((unsigned char)*digits)) {
            ++digits;
        }
        if (*digits == '-') {
            return false;
        }
    }

    switch (kind) {
        case KERNEL_CLI_FINITE_FLOAT:
            return kernel_parse_finite_float(value, &float_value);
        case KERNEL_CLI_SIGNED_INTEGER:
            return kernel_parse_i64(value, &signed_value);
        case KERNEL_CLI_SIGNED_INT:
            return kernel_parse_i64(value, &signed_value) &&
                   signed_value >= INT_MIN && signed_value <= INT_MAX;
        case KERNEL_CLI_UNSIGNED_INTEGER:
            return kernel_parse_u64(value, &unsigned_value);
        case KERNEL_CLI_UNSIGNED_U32:
            return kernel_parse_u64(value, &unsigned_value) && unsigned_value <= UINT32_MAX;
        case KERNEL_CLI_POSITIVE_U32:
            return kernel_parse_positive_u32(value, &positive_value);
        case KERNEL_CLI_UNSIGNED_U32_BASE0:
            return unsigned_u32_base0_is_valid(value);
    }
    return false;
}

static bool validate_rules(const char *argument,
                           const kernel_cli_numeric_rule *rules,
                           size_t count)
{
    for (size_t index = 0; index < count; ++index) {
        const char *value = kernel_match_prefix(argument, rules[index].prefix);
        if (value && !value_is_valid(value, rules[index].kind)) {
            return false;
        }
    }
    return true;
}

/* A component is consumed fully up to its delimiter. Preserve the legacy
 * composite parsers' leading and final whitespace, but not numeric suffixes. */
static bool component_is_valid(const char *value, const char *limit,
                               bool integer, bool trailing_space)
{
    if (!value || value == limit) {
        return false;
    }
    errno = 0;
    char *end = NULL;
    if (integer) {
        long parsed = strtol(value, &end, 10);
        if (errno == ERANGE || parsed < INT_MIN || parsed > INT_MAX) {
            return false;
        }
    } else {
        float parsed = strtof(value, &end);
        if (errno == ERANGE || !isfinite(parsed)) {
            return false;
        }
    }
    if (end == value || end > limit) {
        return false;
    }
    if (trailing_space) {
        while (end < limit && isspace((unsigned char)*end)) {
            ++end;
        }
    }
    return end == limit;
}

static bool range_is_valid(const char *value, bool integer)
{
    const char *separator = strchr(value, ':');
    return separator &&
           component_is_valid(value, separator, integer, false) &&
           component_is_valid(separator + 1, value + strlen(value), integer, true);
}

static bool named_components_are_valid(const char *value)
{
    /* Both legacy parsers copy into char[128]. Reject truncation rather than
     * validating a suffix which the runtime cannot consume. Empty comma fields,
     * partial lists, duplicate keys and ignored unknown keys remain compatible. */
    if (!*value || strlen(value) >= 128U) {
        return false;
    }
    bool have_component = false;
    const char *token = value;
    while (*token) {
        if (*token == ',') {
            ++token;
            continue;
        }
        const char *limit = strchr(token, ',');
        if (!limit) {
            limit = token + strlen(token);
        }
        const char *name = token;
        while (name < limit && isspace((unsigned char)*name)) {
            ++name;
        }
        const char *colon = memchr(name, ':', (size_t)(limit - name));
        if (!colon || colon == name ||
            !component_is_valid(colon + 1, limit, false, true)) {
            return false;
        }
        have_component = true;
        token = limit;
    }
    return have_component;
}

static bool validate_composites(const char *argument, kernel_cli_profile profile)
{
    const char *value = kernel_match_prefix(argument, "--affinity-cfg=");
    if (!value) {
        value = kernel_match_prefix(argument, "--kiss-thr=");
    }
    if (value) {
        return named_components_are_valid(value);
    }
    if (profile == KERNEL_CLI_SUBSTRATE) {
        value = kernel_match_prefix(argument, "--tune-alpha=");
        if (!value) {
            value = kernel_match_prefix(argument, "--tune-align=");
        }
        if (value) {
            return range_is_valid(value, false);
        }
        value = kernel_match_prefix(argument, "--tune-warm=");
        return !value || range_is_valid(value, true);
    }
    value = kernel_match_prefix(argument, "--vitality-threshold=");
    if (value) {
        const char *separator = strpbrk(value, ":,");
        const char *limit = value + strlen(value);
        return component_is_valid(value, separator ? separator : limit, false,
                                  !separator) &&
               (!separator || component_is_valid(separator + 1, limit, false, true));
    }
    value = kernel_match_prefix(argument, "--phase-shift=");
    if (value) {
        const char *separator = strchr(value, ':');
        return separator && separator != value && (size_t)(separator - value) < 32U &&
               component_is_valid(separator + 1, value + strlen(value), false, true);
    }
    return true;
}

bool kernel_cli_validate_argument(const char *argument, kernel_cli_profile profile)
{
    if (!argument || (profile != KERNEL_CLI_PULSE && profile != KERNEL_CLI_SUBSTRATE)) {
        return false;
    }
    const char *name = profile == KERNEL_CLI_PULSE ? "pulse_kernel" : "liminal_core";
    if (profile == KERNEL_CLI_PULSE &&
        (kernel_match_prefix(argument, "--cm-snapshot-interval=") ||
         kernel_match_prefix(argument, "--phase-shift-"))) {
        fprintf(stderr,
                "%s: option is unavailable until production parser migration: '%s'\n",
                name, argument);
        return false;
    }
    /* Both runtimes retain their case-insensitive named allowance pulse. */
    const char *allow = kernel_match_prefix(argument, "--allow=");
    if (allow &&
        (allow[0] == 'n' || allow[0] == 'N') &&
        (allow[1] == 'o' || allow[1] == 'O') &&
        (allow[2] == 'w' || allow[2] == 'W') && allow[3] == '\0') {
        return true;
    }
    const kernel_cli_numeric_rule *rules = profile == KERNEL_CLI_PULSE
                                              ? PULSE_NUMERIC_RULES
                                              : SUBSTRATE_NUMERIC_RULES;
    size_t count = profile == KERNEL_CLI_PULSE
                       ? sizeof(PULSE_NUMERIC_RULES) / sizeof(PULSE_NUMERIC_RULES[0])
                       : sizeof(SUBSTRATE_NUMERIC_RULES) / sizeof(SUBSTRATE_NUMERIC_RULES[0]);
    if (!validate_rules(argument, COMMON_NUMERIC_RULES,
                        sizeof(COMMON_NUMERIC_RULES) / sizeof(COMMON_NUMERIC_RULES[0])) ||
        !validate_rules(argument, rules, count) ||
        !validate_composites(argument, profile)) {
        fprintf(stderr, "%s: invalid numeric value in argument '%s'\n", name, argument);
        return false;
    }
    return true;
}

bool kernel_cli_validate_arguments(int argc, char *const argv[], kernel_cli_profile profile)
{
    if (argc < 0 || (argc > 0 && !argv)) {
        return false;
    }
    for (int index = 1; index < argc; ++index) {
        if (!kernel_cli_validate_argument(argv[index], profile)) {
            return false;
        }
    }
    return true;
}
