#ifndef LIMINAL_INCLUDE_DREAM_H
#define LIMINAL_INCLUDE_DREAM_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct AlignmentBalance;

typedef struct DreamState {
    bool active;
    int cycle_count;
    float entry_threshold;
    float dream_intensity;
    float aligned_threshold;
    float sync_ratio;
} DreamState;

void dream_init(void);
void dream_enable(bool enable);
void dream_enable_logging(bool enable);
void dream_set_entry_threshold(float threshold);
const DreamState *dream_state(void);

void dream_enter(void);
void dream_iterate(void);
void dream_exit(void);
void dream_update(float coherence, float awareness_level, const struct AlignmentBalance *alignment);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_INCLUDE_DREAM_H */
