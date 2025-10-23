#ifndef LIMINAL_EMPATHIC_H
#define LIMINAL_EMPATHIC_H

#include <stdbool.h>

#define EMPATHIC_RECOGNITION_WINDOW_MIN 10
#define EMPATHIC_RECOGNITION_WINDOW_MAX 240
#define EMPATHIC_RECOGNITION_WINDOW_DEFAULT 100

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
    float anticipation;
} EmotionField;

typedef struct {
    EmotionField field;
    float resonance;
    float target_coherence;
    float delay_scale;
    float coherence_bias;
    float anticipation_level;
    float micro_pattern_signal;
    float prediction_trend;
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
void empathic_recognition_enable(bool enable);
void empathic_recognition_trace(bool enable);
void empathic_set_trend_window(int window);
float empathic_anticipation(void);
bool empathic_calm_prediction(void);
bool empathic_anxiety_prediction(void);

#endif /* LIMINAL_EMPATHIC_H */
