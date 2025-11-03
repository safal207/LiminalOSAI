#ifndef LIMINAL_FLOW_EQUILIBRIUM_H
#define LIMINAL_FLOW_EQUILIBRIUM_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FlowEquilibrium {
    bool enabled;
    float alpha;
    float gamma;
    float impulse;
    float observation;
    float choice;
    float balance;
    float last_observation;
    int stable_count;
    FILE *log;
} FlowEquilibrium;

typedef struct {
    float tempo_scale;
    float impulse_boost;
    float choice_delta;
    float observation_relief;
} FlowEquilibriumResult;

void flow_equilibrium_init(FlowEquilibrium *fee, float alpha, float gamma);
void flow_equilibrium_enable(FlowEquilibrium *fee, bool enabled);
void flow_equilibrium_finalize(FlowEquilibrium *fee);
FlowEquilibriumResult flow_equilibrium_update(FlowEquilibrium *fee,
                                              float impulse,
                                              float observation,
                                              float choice,
                                              uint32_t cycle);
bool flow_equilibrium_is_enabled(const FlowEquilibrium *fee);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_FLOW_EQUILIBRIUM_H */
