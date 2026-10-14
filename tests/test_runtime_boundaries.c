#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pulse_loop.h"
#include "runtime_trace.h"
#include "soil.h"
#include "substrate_state.h"

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

int main(void)
{
    test_pulse_stage_and_observation_order();
    test_state_is_caller_owned_and_retains_cycle_boundary();
    test_trace_retains_format_and_does_not_mutate_state();
    puts("runtime boundary tests passed");
    return 0;
}
