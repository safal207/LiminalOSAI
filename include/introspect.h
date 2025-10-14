#ifndef LIMINAL_INTROSPECT_H
#define LIMINAL_INTROSPECT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct introspect_state {
    bool enabled;
    bool harmony_enabled;
    bool harmony_line_open;
    uint64_t cycle_index;
    double amp_sum;
    double tempo_sum;
    uint32_t sample_count;
    FILE *stream;
    double last_harmony;
} State;

typedef struct introspect_metrics {
    float amp;
    float tempo;
    float consent;
    float influence;
    float bond_coh;
    float error_margin;
    float harmony;
} Metrics;

void introspect_state_init(State *state);
void introspect_enable(State *state, bool enabled);
void introspect_enable_harmony(State *state, bool enabled);
void introspect_finalize(State *state);
void introspect_tick(State *state, const Metrics *metrics);

#endif /* LIMINAL_INTROSPECT_H */
