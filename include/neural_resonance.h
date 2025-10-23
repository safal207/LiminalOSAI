#ifndef LIMINAL_NEURAL_RESONANCE_H
#define LIMINAL_NEURAL_RESONANCE_H

#include <stdbool.h>

#include "dream_replay.h"
#include "astro_sync.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float alignment;
    float stability;
    float resonance_flow;
    float phase_offset;
} SynapticBridge;

typedef struct {
    float freq_hz;
    float coherence;
    float amplitude;
    float phase_shift;
} NeuralResonance;

void resonance_init(NeuralResonance *n);
void resonance_update(NeuralResonance *n,
                      const Harmony *h,
                      const Astro *a,
                      const DreamReplay *d,
                      const SynapticBridge *b);
float resonance_stability(const NeuralResonance *n);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_NEURAL_RESONANCE_H */
