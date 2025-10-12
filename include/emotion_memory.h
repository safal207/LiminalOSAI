#ifndef LIMINAL_INCLUDE_EMOTION_MEMORY_H
#define LIMINAL_INCLUDE_EMOTION_MEMORY_H

#include <stdbool.h>
#include <stdint.h>

#include "empathic.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EMOTION_SIGNATURE_SIZE 32

typedef struct {
    float warmth_avg;
    float tension_avg;
    float harmony_avg;
    float resonance_avg;
    uint64_t timestamp;
    char signature[EMOTION_SIGNATURE_SIZE];
} EmotionTrace;

void emotion_memory_configure(bool enable,
                              bool trace,
                              const char *path,
                              float recognition_threshold);
void emotion_memory_update(EmotionField field);
bool emotion_memory_recognized(void);
float emotion_memory_resonance_boost(void);
const EmotionTrace *emotion_memory_last_trace(void);
void emotion_memory_finalize(void);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_INCLUDE_EMOTION_MEMORY_H */
