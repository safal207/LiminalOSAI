#ifndef LIMINAL_INCLUDE_EMPATHIC_H
#define LIMINAL_INCLUDE_EMPATHIC_H

#include <stdbool.h>

typedef enum {
    EMPATHIC_SOURCE_AUDIO = 0,
    EMPATHIC_SOURCE_TEXT,
    EMPATHIC_SOURCE_SENSOR
} EmpathicSource;

typedef struct {
    float warmth;
    float tension;
    float harmony;
    float empathy;
} EmotionField;

typedef struct {
    EmotionField field;
    float resonance;
    float target_coherence;
    float delay_scale;
    float coherence_bias;
} EmpathicResponse;

void empathic_init(EmpathicSource source, bool trace, float gain);
void empathic_enable(bool enable);
bool empathic_active(void);
EmpathicResponse empathic_step(float base_target, float alignment_hint, float resonance_hint);
EmotionField empathic_field(void);
float empathic_resonance(void);
double empathic_delay_scale(void);
float empathic_apply_coherence(float base_value);
float empathic_coherence_value(float fallback);
float empathic_target_level(void);

#endif /* LIMINAL_INCLUDE_EMPATHIC_H */
