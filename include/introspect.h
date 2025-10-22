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
    double pending_amp;
    double pending_tempo;
    double pending_consent;
    double pending_influence;
    double pending_dream;
    bool pending_has_dream;
} introspect_state;

typedef struct introspect_metrics {
    float amp;
    float tempo;
    float consent;
    float influence;
    float harmony;
    float dream;
} introspect_metrics;

void introspect_state_init(introspect_state *state);
void introspect_enable(introspect_state *state, bool enabled);
void introspect_enable_harmony(introspect_state *state, bool enabled);
void introspect_finalize(introspect_state *state);
void introspect_tick(introspect_state *state, const introspect_metrics *metrics);
void introspect_commit(introspect_state *state, double harmony);

#endif /* LIMINAL_INTROSPECT_H */
