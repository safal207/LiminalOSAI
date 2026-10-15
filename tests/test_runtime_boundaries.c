#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pulse_loop.h"
#include "pulse_options.h"
#include "runtime_trace.h"
#include "soil.h"
#include "substrate_state.h"
#include "substrate_options.h"

typedef struct {
    char calls[64];
    size_t count;
} StageLog;

static void append_call(const void *context, char stage)
{
    StageLog *log = *(StageLog * const *)context;
    assert(log->count + 1 < sizeof(log->calls));
    log->calls[log->count++] = stage;
    log->calls[log->count] = '\0';
}

static void inhale(const void *context) { append_call(context, 'I'); }
static void reflect(const void *context) { append_call(context, 'R'); }
static void exhale(const void *context) { append_call(context, 'E'); }
static void delay(const void *context) { append_call(context, 'D'); }

static void completed(const void *context, uint64_t pulse_number)
{
    append_call(context, 'C');
    assert(pulse_number > 0 && pulse_number < 10);
    append_call(context, (char)('0' + pulse_number));
}

static void test_pulse_stage_and_observation_order(void)
{
    StageLog log = {{0}, 0};
    StageLog *live_log = &log;
    PulseLoop loop = {
        .context = &live_log,
        .limit = 3,
        .inhale = inhale,
        .reflect = reflect,
        .exhale = exhale,
        .delay = delay,
        .completed = completed
    };
    assert(pulse_loop_run(&loop) == 3);
    assert(strcmp(log.calls, "IREDC1IREDC2IREDC3") == 0);

    log.count = 0;
    log.calls[0] = '\0';
    loop.limit = 1;
    loop.completed = NULL;
    assert(pulse_loop_run(&loop) == 1);
    assert(strcmp(log.calls, "IRED") == 0);
}

static void test_state_is_caller_owned_and_retains_cycle_boundary(void)
{
    liminal_state state;
    memset(&state, 0, sizeof(state));
    substrate_state_init(&state);
    assert(state.cycles == 0);
    assert(state.breath_rate == 0.72f);
    assert(state.resonance == 0.5f);
    assert(state.sync_quality == 0.5f);
    assert(!state.adaptive_profile && !state.human_affinity_active);

    state.breath_position = 0.9f;
    substrate_state_pulse(&state, 0.25f);
    assert(state.cycles == 1);
    assert(fabsf(state.breath_position - 0.08f) < 0.000001f);
    assert(fabsf(state.sync_quality - 0.524f) < 0.000001f);

    state.memory_trace = 0.8f;
    substrate_state_reflect(&state);
    assert(fabsf(state.resonance - 0.62f) < 0.000001f);
    state.vitality = 0.995f;
    substrate_state_rest(&state);
    assert(state.vitality == 1.0f);
    assert(fabsf(state.breath_rate - 0.7164f) < 0.000001f);
    substrate_state_remember(&state, 9.0f);
    assert(state.memory_trace == 1.0f);

    liminal_state independent;
    substrate_state_init(&independent);
    assert(independent.cycles == 0 && independent.memory_trace == 0.0f);
    assert(state.cycles == 1 && state.memory_trace == 1.0f);
}

static void read_output(FILE *stream, char *buffer, size_t capacity)
{
    assert(fseek(stream, 0, SEEK_SET) == 0);
    size_t count = fread(buffer, 1, capacity - 1, stream);
    assert(!ferror(stream));
    buffer[count] = '\0';
}

static void test_trace_retains_format_and_does_not_mutate_state(void)
{
    liminal_state state;
    memset(&state, 0, sizeof(state));
    substrate_state_init(&state);
    unsigned char snapshot[sizeof(state)];
    memcpy(snapshot, &state, sizeof(state));
    FILE *stream = tmpfile();
    assert(stream);
    substrate_trace_analysis(stream, &state, false, false, NULL);
    assert(ftell(stream) == 0);
    substrate_trace_analysis(stream, &state, true, false, NULL);
    substrate_trace_shutdown(stream, &state, true, true);
    assert(memcmp(&state, snapshot, sizeof(state)) == 0);
    char output[1024];
    read_output(stream, output, sizeof(output));
    assert(strcmp(output,
        "trace_event: { \"cycle\": 0, \"coherence\": 0.5000, \"resonance\": 0.5000, "
        "\"sync_quality\": 0.5000, \"anticipation_level\": 0.5000, \"micro_pattern\": 0.5000, "
        "\"prediction_trend\": 0.5000, \"dream_sync\": 0.5000 }\n"
        "[shutdown] cycles=0 resonance=0.500 memory=0.000 vitality=0.600\n") == 0);
    assert(fclose(stream) == 0);

    soil_init();
    stream = tmpfile();
    assert(stream);
    runtime_print_soil_traces(stream);
    read_output(stream, output, sizeof(output));
    assert(strcmp(output, "Memory Soil is quiet.\n") == 0);
    assert(fclose(stream) == 0);
}

static void test_value_option_prefixes(void)
{
    char *pulse_argv[] = {"pulse_kernel", "--cm-snapshot-interval=37",
        "--council-threshold=0.6", "--trs-target-delta=0.125", "--emotional-source=text"};
    kernel_options pulse = pulse_options_parse(5, pulse_argv);
    char *substrate_argv[] = {"liminal_core", "--erb-replay-speed=2.5",
        "--trs-target-delta=0.25", "--bridge-plasticity=0.4",
        "--bridge-retention=0.35", "--bridge-recovery=0.12", "--emotional-source=sensor"};
    substrate_config substrate = substrate_options_parse(7, substrate_argv);
    unsigned int incorrect = 0;
    incorrect += pulse.cm_snapshot_interval != 37;
    incorrect += fabsf(pulse.council_threshold - 0.6f) > 0.000001f;
    incorrect += fabsf(pulse.trs_target_delta - 0.125f) > 0.000001f;
    incorrect += pulse.emotional_source != EMPATHIC_SOURCE_TEXT;
    incorrect += fabsf(substrate.erb_replay_speed - 2.5f) > 0.000001f;
    incorrect += fabsf(substrate.trs_target_delta - 0.25f) > 0.000001f;
    incorrect += fabsf(substrate.bridge_plasticity - 0.4f) > 0.000001f;
    incorrect += fabsf(substrate.bridge_retention - 0.35f) > 0.000001f;
    incorrect += fabsf(substrate.bridge_recovery - 0.12f) > 0.000001f;
    incorrect += substrate.emotional_source != EMPATHIC_SOURCE_SENSOR;
    if (incorrect) {
        fprintf(stderr, "%u value options did not reach their configuration fields\n", incorrect);
    }
    assert(incorrect == 0);
    assert(pulse.trs_enabled && pulse.trs_adapt_enabled);
    assert(substrate.trs_enabled && substrate.trs_adapt_enabled);
}

static void test_emotional_source_empty_and_fallback(void)
{
    char empty[] = "--emotional-source=";
    char *argv[] = {"runtime", empty};
    assert(pulse_options_parse(2, argv).emotional_source == EMPATHIC_SOURCE_AUDIO);
    assert(substrate_options_parse(2, argv).emotional_source == EMPATHIC_SOURCE_AUDIO);
    char *repeated[] = {"runtime", "--emotional-source=text", "--emotional-source=sensor",
        "--emotional-source=unrecognized"};
    assert(pulse_options_parse(3, repeated).emotional_source == EMPATHIC_SOURCE_SENSOR);
    assert(substrate_options_parse(3, repeated).emotional_source == EMPATHIC_SOURCE_SENSOR);
    assert(pulse_options_parse(4, repeated).emotional_source == EMPATHIC_SOURCE_AUDIO);
    assert(substrate_options_parse(4, repeated).emotional_source == EMPATHIC_SOURCE_AUDIO);
}

int main(void)
{
    test_pulse_stage_and_observation_order();
    test_state_is_caller_owned_and_retains_cycle_boundary();
    test_trace_retains_format_and_does_not_mutate_state();
    test_value_option_prefixes();
    test_emotional_source_empty_and_fallback();
    puts("runtime boundary tests passed");
    return 0;
}
