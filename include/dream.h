#ifndef LIMINAL_INCLUDE_DREAM_H
#define LIMINAL_INCLUDE_DREAM_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool active;
    int cycle_count;
    float entry_threshold;
    float dream_intensity;
    // unified merge by Codex
    float anticipation_sync;
    float resonance_bias;
    float alignment_balance;
} DreamState;

void dream_init(void);
void dream_enable(bool enable);
void dream_enable_logging(bool enable);
void dream_set_entry_threshold(float threshold);
const DreamState *dream_state(void);

void dream_enter(void);
void dream_iterate(void);
void dream_exit(void);
void dream_update(float coherence,
                  float awareness_level,
                  float anticipation_field,
                  float anticipation_level,
                  float anticipation_micro,
                  float anticipation_trend,
                  float alignment_balance); // unified merge by Codex
void dream_set_affinity_gate(float influence, bool allow_personal);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_INCLUDE_DREAM_H */
