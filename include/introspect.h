#ifndef LIMINAL_INTROSPECT_H
#define LIMINAL_INTROSPECT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef enum {
    DREAM_COUPLER_PHASE_REST = 0,
    DREAM_COUPLER_PHASE_DREAM,
    DREAM_COUPLER_PHASE_WAKE
} DreamCouplerPhase;

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
    DreamCouplerPhase dream_phase;
    DreamCouplerPhase next_dream_phase;
    bool has_dream_preview;
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
void introspect_tick(State *state, Metrics *metrics);
void introspect_configure_trs(bool enabled,
                              float alpha,
                              int warmup,
                              bool adapt_enabled,
                              float alpha_min,
                              float alpha_max,
                              float target_delta,
                              float k_p,
                              float k_i,
                              float k_d,
                              bool dry_run);
void introspect_set_dream_preview(State *state, DreamCouplerPhase phase, bool active);

#endif /* LIMINAL_INTROSPECT_H */
