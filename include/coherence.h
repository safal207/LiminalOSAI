#ifndef LIMINAL_INCLUDE_COHERENCE_H
#define LIMINAL_INCLUDE_COHERENCE_H

#include <stdbool.h>

typedef struct {
    float energy_smooth;
    float resonance_smooth;
    float stability_avg;
    float awareness_level;
    float coherence;
    float target_level;
    float pid_scale;
} CoherenceField;

void coherence_init(void);
void coherence_set_target(float target);
float coherence_target(void);
void coherence_enable_logging(bool enable);
const CoherenceField *coherence_update(float energy_avg,
                                       float resonance_avg,
                                       float stability_avg,
                                       float awareness_level);
const CoherenceField *coherence_state(void);
double coherence_delay_scale(void);
void coherence_register_delay(double seconds);
double coherence_last_delay(void);
float coherence_adjustment(void);
void coherence_set_pid_scale(float scale);

#endif /* LIMINAL_INCLUDE_COHERENCE_H */
