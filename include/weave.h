#ifndef LIMINAL_INCLUDE_WEAVE_H
#define LIMINAL_INCLUDE_WEAVE_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WEAVE_MODULE_PULSE = 0,
    WEAVE_MODULE_SOIL,
    WEAVE_MODULE_REFLECTION,
    WEAVE_MODULE_AWARENESS,
    WEAVE_MODULE_COUNCIL,
    WEAVE_MODULE_COUNT
} WeaveModule;

typedef struct {
    int phase_count;
    int current_phase;
    float phase_time[16];
    float sync_quality;
    float latency_avg;
} ClockGrid;

void weave_init(int phases);
void weave_next_phase(void);
void weave_measure_sync(void);

size_t weave_module_count(void);
int weave_module_lookup(const char *name);
const char *weave_module_label(size_t index);

void weave_set_phase_shift(size_t module_index, float degrees);
const ClockGrid *weave_clock(void);
int weave_current_phase_index(void);
float weave_current_drift(void);
float weave_current_latency(void);
float weave_sync_quality(void);
void weave_trace_line(char *buffer, size_t size);
bool weave_should_emit_echo(void);
void weave_mark_echo_emitted(void);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_INCLUDE_WEAVE_H */
