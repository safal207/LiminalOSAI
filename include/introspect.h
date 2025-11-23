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

typedef struct introspect_state introspect_state;
typedef struct introspect_metrics introspect_metrics;

struct introspect_state {
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
    double pending_amp;
    double pending_tempo;
    double pending_consent;
    double pending_influence;
    double pending_dream;
    bool pending_has_dream;
};

struct introspect_metrics {
    float amp;
    float tempo;
    float consent;
    float influence;
    float bond_coh;
    float error_margin;
    float harmony;
    int kiss;
};

typedef introspect_state State;
typedef introspect_metrics Metrics;

void introspect_state_init(introspect_state *state);
void introspect_enable(introspect_state *state, bool enabled);
void introspect_enable_harmony(introspect_state *state, bool enabled);
void introspect_finalize(introspect_state *state);
void introspect_tick(introspect_state *state, introspect_metrics *metrics);
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
void introspect_configure_erb(bool enabled, int pre, int post, float spike_thr, bool dry_run);
void introspect_set_dream_preview(State *state, DreamCouplerPhase phase, bool active);
float introspect_get_last_trs_delta(void);
float introspect_get_last_trs_alpha(void);
float introspect_get_last_trs_error(void);
bool introspect_apply_trs_tune(float alpha, int warmup);

#endif /* LIMINAL_INTROSPECT_H */
