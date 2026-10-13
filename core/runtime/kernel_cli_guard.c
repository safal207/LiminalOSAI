#include "kernel_cli_guard.h"
#include "kernel_runtime_utils.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    KERNEL_CLI_FINITE_FLOAT = 0,
    KERNEL_CLI_SIGNED_INTEGER,
    KERNEL_CLI_UNSIGNED_INTEGER,
    KERNEL_CLI_POSITIVE_U32,
    KERNEL_CLI_UNSIGNED_BASE0
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
    {"--tune-seed=", KERNEL_CLI_SIGNED_INTEGER},
    {"--tune-count=", KERNEL_CLI_SIGNED_INTEGER},
    {"--entangle-ctx=", KERNEL_CLI_UNSIGNED_BASE0},
    {"--flow-alpha=", KERNEL_CLI_FINITE_FLOAT},
    {"--flow-gamma=", KERNEL_CLI_FINITE_FLOAT},
    {"--allow=", KERNEL_CLI_FINITE_FLOAT},
    {"--dream-cycles=", KERNEL_CLI_SIGNED_INTEGER},
    {"--dream-rate=", KERNEL_CLI_FINITE_FLOAT},
    {"--dream-decay=", KERNEL_CLI_FINITE_FLOAT},
    {"--bridge-plasticity=", KERNEL_CLI_FINITE_FLOAT},
    {"--bridge-retention=", KERNEL_CLI_FINITE_FLOAT},
    {"--bridge-recovery=", KERNEL_CLI_FINITE_FLOAT},
    {"--empathy-gain=", KERNEL_CLI_FINITE_FLOAT},
    {"--recognition-threshold=", KERNEL_CLI_FINITE_FLOAT},
    {"--erb-replay=idx:", KERNEL_CLI_UNSIGNED_INTEGER},
    {"--tune-source=idx:", KERNEL_CLI_UNSIGNED_INTEGER},
};

static bool unsigned_base0_is_valid(const char *value)
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
    return errno != ERANGE && end != value && *end == '\0' && parsed <= UINT64_MAX;
}

static bool value_is_valid(const char *value, kernel_cli_value_kind kind)
{
    float float_value = 0.0f;
    int64_t signed_value = 0;
    uint64_t unsigned_value = 0;
    uint32_t positive_value = 0;

    if (kind == KERNEL_CLI_UNSIGNED_INTEGER || kind == KERNEL_CLI_POSITIVE_U32) {
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
        case KERNEL_CLI_UNSIGNED_INTEGER:
            return kernel_parse_u64(value, &unsigned_value);
        case KERNEL_CLI_POSITIVE_U32:
            return kernel_parse_positive_u32(value, &positive_value);
        case KERNEL_CLI_UNSIGNED_BASE0:
            return unsigned_base0_is_valid(value);
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
    /* The substrate's named allowance pulse remains a valid nonnumeric option. */
    const char *allow = kernel_match_prefix(argument, "--allow=");
    if (profile == KERNEL_CLI_SUBSTRATE && allow &&
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
        !validate_rules(argument, rules, count)) {
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
