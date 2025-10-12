#ifndef LIMINAL_INCLUDE_ALIGNMENT_BALANCER_H
#define LIMINAL_INCLUDE_ALIGNMENT_BALANCER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "council.h"
#include "dream.h"

typedef struct AlignmentBalance {
    float pid_scale;
    float dream_threshold;
    float coherence_target;
    float dream_sync;
    float council_signal;
    float dream_signal;
} AlignmentBalance;

void alignment_balancer_init(float base_dream_threshold, float base_coherence_target);
void alignment_balancer_set_base(float base_dream_threshold, float base_coherence_target);
const AlignmentBalance *alignment_balancer_update(const InnerCouncil *council,
                                                  const DreamState *dream,
                                                  float awareness_level,
                                                  float previous_coherence,
                                                  float current_target);
const AlignmentBalance *alignment_balancer_state(void);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_INCLUDE_ALIGNMENT_BALANCER_H */
