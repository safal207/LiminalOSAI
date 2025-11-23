#ifndef LIMINAL_DREAM_COUPLER_H
#define LIMINAL_DREAM_COUPLER_H

#include "introspect.h"

#ifdef __cplusplus
extern "C" {
#endif

DreamCouplerPhase dream_coupler_evaluate(const Metrics *metrics);
void dream_couple(State *state, Metrics *metrics);
const char *dream_coupler_phase_name(DreamCouplerPhase phase);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_DREAM_COUPLER_H */
