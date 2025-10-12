#ifndef LIMINAL_INCLUDE_DREAM_H
#define LIMINAL_INCLUDE_DREAM_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DREAM_PHASE_ENTRY = 0,
    DREAM_PHASE_SYNTHESIS,
    DREAM_PHASE_RELEASE,
    DREAM_PHASE_COUNT
} DreamPhase;

typedef struct {
    float level;
    float micro_pattern;
    float trend;
} DreamAnticipation;

typedef struct {
    bool active;
    int cycle_count;
    float entry_threshold;
    float dream_intensity;
    DreamPhase phase;
    DreamAnticipation anticipation_current;
    DreamAnticipation anticipation_phase[DREAM_PHASE_COUNT];
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
                  float anticipation_level,
                  float anticipation_micro_pattern,
                  float anticipation_trend);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_INCLUDE_DREAM_H */
