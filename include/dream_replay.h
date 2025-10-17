#ifndef LIMINAL_DREAM_REPLAY_H
#define LIMINAL_DREAM_REPLAY_H

#include <stdbool.h>

#include "astro_sync.h"
#include "trs_filter.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float baseline;
    float amplitude;
    float coherence;
} Harmony;

typedef struct {
    float replay_rate;
    float blend_factor;
    float decay;
    float rem;
    int cycles;
    bool consolidate_mode;
    float memory_projection;
    float last_gain;
} DreamReplay;

void dream_init(DreamReplay *d);
void dream_tick(DreamReplay *d,
                const Astro *astro,
                const Harmony *h,
                const TRS *t);
float dream_feedback(const DreamReplay *d);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_DREAM_REPLAY_H */
