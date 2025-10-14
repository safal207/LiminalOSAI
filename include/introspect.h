#ifndef LIMINAL_INTROSPECT_H
#define LIMINAL_INTROSPECT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct introspect_state {
    bool enabled;
    uint64_t cycle_index;
    double amp_sum;
    double tempo_sum;
    uint32_t sample_count;
    FILE *stream;
} State;

typedef struct introspect_metrics {
    float amp;
    float tempo;
    float consent;
    float influence;
    float bond_coh;
    float error_margin;
} Metrics;

void introspect_state_init(State *state);
void introspect_enable(State *state, bool enabled);
void introspect_finalize(State *state);
void introspect_tick(State *state, const Metrics *metrics);

#endif /* LIMINAL_INTROSPECT_H */
