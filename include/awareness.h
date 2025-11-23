#ifndef LIMINAL_AWARENESS_H
#define LIMINAL_AWARENESS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float awareness_level;
    float self_coherence;
    float drift;
} AwarenessState;

void awareness_init(void);
void awareness_set_auto_tune(bool enable);
bool awareness_auto_tune_enabled(void);
AwarenessState awareness_state(void);
bool awareness_update(float resonance_avg, float stability);
void awareness_emit_dialogue(float variance);
double awareness_adjust_delay(double base_seconds);
double awareness_cycle_duration(void);
void awareness_set_coherence_scale(double scale);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_AWARENESS_H */
