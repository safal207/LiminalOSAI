#ifndef COUNCIL_H
#define COUNCIL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float reflection_vote;
    float awareness_vote;
    float coherence_vote;
    float health_vote;
    float final_decision;
} InnerCouncil;

void council_init(void);
void council_summon(void);
InnerCouncil council_update(float reflection_stability,
                            float awareness_level,
                            float coherence_level,
                            float health_drift,
                            float decision_threshold);
const InnerCouncil *council_state(void);


#ifdef __cplusplus
}
#endif

#endif /* COUNCIL_H */
