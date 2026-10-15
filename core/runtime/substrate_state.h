#ifndef LIMINAL_SUBSTRATE_STATE_H
#define LIMINAL_SUBSTRATE_STATE_H

#include <stdbool.h>
#include <stdint.h>

/* Caller-owned cycle state. These transitions perform no I/O or allocation. */
typedef struct {
    float breath_rate;
    float breath_position;
    float memory_trace;
    float resonance;
    float sync_quality;
    float vitality;
    float phase_offset;
    uint32_t cycles;
    bool adaptive_profile;
    bool human_affinity_active;
} liminal_state;

void substrate_state_init(liminal_state *state);
void substrate_state_remember(liminal_state *state, float imprint);
void substrate_state_rest(liminal_state *state);
void substrate_state_reflect(liminal_state *state);
void substrate_state_pulse(liminal_state *state, float delta);

#endif /* LIMINAL_SUBSTRATE_STATE_H */
