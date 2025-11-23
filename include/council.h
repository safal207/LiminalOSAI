#ifndef LIMINAL_COUNCIL_H
#define LIMINAL_COUNCIL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct InnerCouncil {
    float reflection_vote;
    float awareness_vote;
    float coherence_vote;
    float health_vote;
    float anticipation_vote;
    float anticipation_field_vote;
    float anticipation_level_vote;
    float anticipation_micro_vote;
    float anticipation_trend_vote;
    float final_decision;
} InnerCouncil;

void council_init(void);
void council_summon(void);
InnerCouncil council_update(float reflection_stability,
                            float awareness_level,
                            float coherence_level,
                            float health_drift,
                            float anticipation_field,
                            float anticipation_level,
                            float anticipation_micro,
                            float anticipation_trend,
                            float decision_threshold);
const InnerCouncil *council_state(void);


#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_COUNCIL_H */
