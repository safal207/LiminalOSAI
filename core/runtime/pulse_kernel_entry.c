#include "kernel_runtime_utils.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef enum {
    KERNEL_CLI_FINITE_FLOAT = 0,
    KERNEL_CLI_SIGNED_INTEGER,
    KERNEL_CLI_UNSIGNED_INTEGER,
    KERNEL_CLI_POSITIVE_U32
} kernel_cli_value_kind;

typedef struct {
    const char *prefix;
    kernel_cli_value_kind kind;
} kernel_cli_numeric_rule;

/*
 * This is a narrow production guard, not a second kernel-options parser.
 * It validates syntax and finiteness before the existing runtime parser applies
 * its established clamping/default semantics. Unknown and non-numeric options
 * continue to be handled by the existing production parser.
 */
static const kernel_cli_numeric_rule KERNEL_NUMERIC_RULES[] = {
    {"--limit=", KERNEL_CLI_UNSIGNED_INTEGER},
    {"--scan-interval=", KERNEL_CLI_POSITIVE_U32},
    {"--phases=", KERNEL_CLI_SIGNED_INTEGER},
    {"--kiss-warmup=", KERNEL_CLI_SIGNED_INTEGER},
    {"--kiss-refrac=", KERNEL_CLI_SIGNED_INTEGER},
    {"--gate-warmup=", KERNEL_CLI_SIGNED_INTEGER},
    {"--gate-refrac=", KERNEL_CLI_SIGNED_INTEGER},
    {"--trs-warmup=", KERNEL_CLI_SIGNED_INTEGER},

    {"--target=", KERNEL_CLI_FINITE_FLOAT},
    {"--group-target=", KERNEL_CLI_FINITE_FLOAT},
    {"--council-threshold=", KERNEL_CLI_FINITE_FLOAT},
    {"--dream-threshold=", KERNEL_CLI_FINITE_FLOAT},
    {"--resonance-gain=", KERNEL_CLI_FINITE_FLOAT},
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
    {"--mirror-soft=", KERNEL_CLI_FINITE_FLOAT},
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
    {"--trs-kd=", KERNEL_CLI_FINITE_FLOAT}
};

int pulse_kernel_core_main(int argc, char **argv);

static bool kernel_cli_value_is_valid(const char *value, kernel_cli_value_kind kind)
{
    float float_value = 0.0f;
    int64_t signed_value = 0;
    uint64_t unsigned_value = 0;
    uint32_t positive_value = 0;

    switch (kind) {
        case KERNEL_CLI_FINITE_FLOAT:
            return kernel_parse_finite_float(value, &float_value);
        case KERNEL_CLI_SIGNED_INTEGER:
            return kernel_parse_i64(value, &signed_value);
        case KERNEL_CLI_UNSIGNED_INTEGER:
            return kernel_parse_u64(value, &unsigned_value);
        case KERNEL_CLI_POSITIVE_U32:
            return kernel_parse_positive_u32(value, &positive_value);
    }

    return false;
}

static bool kernel_reject_known_silent_noop(const char *argument)
{
    if (!argument) {
        return false;
    }

    if (kernel_match_prefix(argument, "--cm-snapshot-interval=") ||
        kernel_match_prefix(argument, "--phase-shift-")) {
        fprintf(stderr,
                "pulse_kernel: option is unavailable until production parser migration: '%s'\n",
                argument);
        return false;
    }

    return true;
}

static bool kernel_validate_numeric_argument(const char *argument)
{
    if (!argument) {
        return false;
    }

    for (size_t index = 0;
         index < sizeof(KERNEL_NUMERIC_RULES) / sizeof(KERNEL_NUMERIC_RULES[0]);
         ++index) {
        const kernel_cli_numeric_rule *rule = &KERNEL_NUMERIC_RULES[index];
        const char *value = kernel_match_prefix(argument, rule->prefix);
        if (!value) {
            continue;
        }

        if (!kernel_cli_value_is_valid(value, rule->kind)) {
            fprintf(stderr,
                    "pulse_kernel: invalid numeric value in argument '%s'\n",
                    argument);
            return false;
        }
        return true;
    }

    return true;
}

int main(int argc, char **argv)
{
    if (argc < 0 || (argc > 0 && !argv)) {
        fputs("pulse_kernel: invalid process arguments\n", stderr);
        return 2;
    }

    for (int index = 1; index < argc; ++index) {
        if (!kernel_reject_known_silent_noop(argv[index]) ||
            !kernel_validate_numeric_argument(argv[index])) {
            return 2;
        }
    }

    return pulse_kernel_core_main(argc, argv);
}
