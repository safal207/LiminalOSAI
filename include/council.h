#ifndef COUNCIL_H
#define COUNCIL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char name[16];
    float bias_energy;
    float bias_resonance;
    float vote;
} CouncilAgent;

typedef struct {
    CouncilAgent agents[3];
    float decision;
    float variance;
} CouncilOutcome;

void council_init(void);
void council_summon(void);
CouncilOutcome council_consult(float energy_avg,
                               float resonance_avg,
                               float stability,
                               size_t symbol_count);

#ifdef __cplusplus
}
#endif

#endif /* COUNCIL_H */
