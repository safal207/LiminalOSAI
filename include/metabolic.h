#ifndef LIMINAL_METABOLIC_H
#define LIMINAL_METABOLIC_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float intake;
    float output;
    float balance;
    float vitality;
    float recovery_rate;
} MetabolicFlow;

void metabolic_init(void);
void metabolic_enable(bool enable);
void metabolic_enable_trace(bool enable);
void metabolic_set_thresholds(float rest_threshold, float creative_threshold);
void metabolic_step(float intake, float output);
const MetabolicFlow *metabolic_state(void);
float metabolic_adjust_awareness(float awareness_level);
float metabolic_adjust_stability(float stability);
float metabolic_delay_scale(void);
void metabolic_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_METABOLIC_H */
