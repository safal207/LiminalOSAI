#ifndef LIMINAL_INCLUDE_ANTICIPATION_V2_H
#define LIMINAL_INCLUDE_ANTICIPATION_V2_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool enabled;
    bool trace;
    float gain;
    float ema_coh;
    float ema_delay;
    float drift;
    float mae;
    float last_prediction;
    unsigned long cycle_count;
    unsigned int stable_count;
    bool initialized;
} AnticipationV2;

void ant2_init(AnticipationV2 *state);
void ant2_set_enabled(AnticipationV2 *state, bool enabled);
void ant2_set_gain(AnticipationV2 *state, float gain);
void ant2_set_trace(AnticipationV2 *state, bool trace);
float ant2_step(AnticipationV2 *state,
                float group_coherence,
                float delay_normalized,
                float influence,
                const char *memory_path);
void ant2_feedback(AnticipationV2 *state, float feedback_delta);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_INCLUDE_ANTICIPATION_V2_H */
