#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel_runtime_utils.h"
#include "kernel_sequence.h"

static void test_prefix_matching(void)
{
    const char *value = kernel_match_prefix("--target=0.8", "--target=");
    assert(value != NULL);
    assert(strcmp(value, "0.8") == 0);
    assert(kernel_match_prefix("--targets=0.8", "--target=") == NULL);
    assert(kernel_match_prefix(NULL, "--target=") == NULL);
}

static void test_finite_float_parser(void)
{
    float value = 0.0f;
    assert(kernel_parse_finite_float("0.75", &value));
    assert(fabsf(value - 0.75f) < 0.0001f);
    assert(kernel_parse_finite_float("-12.5", &value));
    assert(!kernel_parse_finite_float("nan", &value));
    assert(!kernel_parse_finite_float("inf", &value));
    assert(!kernel_parse_finite_float("0.5garbage", &value));
    assert(!kernel_parse_finite_float("", &value));
}

static void test_integer_parsers(void)
{
    uint64_t wide = 0;
    uint32_t positive = 0;
    assert(kernel_parse_u64("0", &wide) && wide == 0);
    assert(kernel_parse_u64("18446744073709551615", &wide));
    assert(!kernel_parse_u64("-1", &wide));
    assert(!kernel_parse_u64("12x", &wide));
    assert(kernel_parse_positive_u32("4294967295", &positive));
    assert(positive == UINT32_MAX);
    assert(!kernel_parse_positive_u32("0", &positive));
    assert(!kernel_parse_positive_u32("4294967296", &positive));
}

static void test_phase_shift_parser(void)
{
    char module[32];
    float degrees = 0.0f;
    assert(kernel_parse_phase_shift("--phase-shift-awarenessdeg=-22.5",
                                    "--phase-shift-",
                                    module,
                                    sizeof(module),
                                    &degrees));
    assert(strcmp(module, "awareness") == 0);
    assert(fabsf(degrees + 22.5f) < 0.0001f);

    assert(!kernel_parse_phase_shift("--phase-shift-awareness=10",
                                     "--phase-shift-",
                                     module,
                                     sizeof(module),
                                     &degrees));
    assert(!kernel_parse_phase_shift("--phase-shift-awarenessdeg=nan",
                                     "--phase-shift-",
                                     module,
                                     sizeof(module),
                                     &degrees));

    char tiny_module[4];
    assert(!kernel_parse_phase_shift("--phase-shift-awarenessdeg=10",
                                     "--phase-shift-",
                                     tiny_module,
                                     sizeof(tiny_module),
                                     &degrees));
}

static void test_numeric_safety(void)
{
    assert(fabsf(kernel_clamp_unit(NAN, 0.4f) - 0.4f) < 0.0001f);
    assert(kernel_clamp_unit(-2.0f, 0.4f) == 0.0f);
    assert(kernel_clamp_unit(2.0f, 0.4f) == 1.0f);
    assert(kernel_sanitize_scale(NAN) == 1.0);
    assert(kernel_sanitize_scale(-1.0) == 1.0);
    assert(kernel_sanitize_scale(0.5) == 0.5);

    const double scales[] = {2.0, NAN, -4.0, 0.5};
    double delay = kernel_apply_delay_scales(0.1, scales, 4, 0.1, 0.03, 0.25);
    assert(fabs(delay - 0.1) < 0.000001);

    const double huge[] = {1000.0};
    delay = kernel_apply_delay_scales(0.1, huge, 1, 0.1, 0.03, 0.25);
    assert(fabs(delay - 0.25) < 0.000001);
}

static void test_minimal_sequence(void)
{
    kernel_sequence_options options = {0};
    kernel_stage stages[KERNEL_STAGE_COUNT];
    size_t count = kernel_plan_sequence(&options, stages, KERNEL_STAGE_COUNT);
    assert(count == 2);
    assert(stages[0] == KERNEL_STAGE_AWARENESS);
    assert(stages[1] == KERNEL_STAGE_GATE);
    assert(kernel_sequence_is_canonical(stages, count));
}

static void test_dependency_and_order(void)
{
    kernel_sequence_options options = {
        .anticipation = true,
        .collective = true,
        .affinity = true,
        .mirror = true,
        .introspect = true,
        .astro = true,
        .kiss = true,
        .vse = true,
        .dream = true
    };
    kernel_stage stages[KERNEL_STAGE_COUNT];
    size_t count = kernel_plan_sequence(&options, stages, KERNEL_STAGE_COUNT);
    assert(count == KERNEL_STAGE_COUNT);
    assert(kernel_sequence_is_canonical(stages, count));
    assert(stages[KERNEL_STAGE_INTROSPECT] == KERNEL_STAGE_INTROSPECT);
    assert(stages[KERNEL_STAGE_HARMONY] == KERNEL_STAGE_HARMONY);
    assert(stages[count - 1] == KERNEL_STAGE_DREAM);

    char formatted[256];
    kernel_format_sequence(stages, count, formatted, sizeof(formatted));
    assert(strstr(formatted, "awareness -> collective") != NULL);
    assert(strstr(formatted, "introspect -> harmony") != NULL);
    assert(strstr(formatted, "gate -> vse -> dream") != NULL);
}

static void test_capacity_is_respected(void)
{
    kernel_sequence_options options = {
        .anticipation = true,
        .collective = true,
        .dream = true
    };
    kernel_stage stages[2];
    size_t count = kernel_plan_sequence(&options, stages, 2);
    assert(count == 2);
    assert(stages[0] == KERNEL_STAGE_ANTICIPATION);
    assert(stages[1] == KERNEL_STAGE_AWARENESS);
}

static void test_canonical_validator(void)
{
    const kernel_stage duplicate[] = {KERNEL_STAGE_AWARENESS, KERNEL_STAGE_AWARENESS};
    const kernel_stage reversed[] = {KERNEL_STAGE_GATE, KERNEL_STAGE_AWARENESS};
    assert(!kernel_sequence_is_canonical(duplicate, 2));
    assert(!kernel_sequence_is_canonical(reversed, 2));
}

int main(void)
{
    test_prefix_matching();
    test_finite_float_parser();
    test_integer_parsers();
    test_phase_shift_parser();
    test_numeric_safety();
    test_minimal_sequence();
    test_dependency_and_order();
    test_capacity_is_respected();
    test_canonical_validator();
    puts("kernel runtime contract tests: PASS");
    return 0;
}
