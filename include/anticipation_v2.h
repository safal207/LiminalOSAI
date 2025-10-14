#ifndef LIMINAL_ANTICIPATION_V2_H
#define LIMINAL_ANTICIPATION_V2_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float ema_coh;
    float ema_delay;
    float drift_coh;
    float drift_del;
    float gain;
    float mae;
} Ant2;

#define ANT2_FEEDBACK_WINDUP_THRESHOLD 0.06f

void ant2_init(Ant2 *state, float initial_gain);
void ant2_set_trace(bool enable);
float ant2_feedforward(Ant2 *state,
                       float target_coherence,
                       float actual_coherence,
                       float actual_delay_norm,
                       float bond_influence,
                       float *predicted_coherence,
                       float *predicted_delay,
                       float *ff_out);
void ant2_feedback_adjust(Ant2 *state,
                          float feedback_delta_rel,
                          float windup_threshold);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_ANTICIPATION_V2_H */
