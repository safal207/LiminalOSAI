#ifndef LIMINAL_SYNAPTIC_BRIDGE_H
#define LIMINAL_SYNAPTIC_BRIDGE_H

#include "dream_replay.h"
#include "astro_sync.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float plasticity;
    float retention;
    float fatigue;
    float recovery;
} SynapticBridge;

void bridge_init(SynapticBridge *b);
void bridge_update(SynapticBridge *b,
                   const DreamReplay *d,
                   Harmony *h,
                   Astro *a);
float bridge_stability(const SynapticBridge *b);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_SYNAPTIC_BRIDGE_H */
