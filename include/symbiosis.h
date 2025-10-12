#ifndef LIMINAL_INCLUDE_SYMBIOSIS_H
#define LIMINAL_INCLUDE_SYMBIOSIS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SYMBIOSIS_SOURCE_KEYBOARD = 0,
    SYMBIOSIS_SOURCE_AUDIO,
    SYMBIOSIS_SOURCE_SENSOR
} SymbiosisSource;

typedef struct {
    float beat_rate;
    float amplitude;
    float coherence;
} HumanPulse;

void symbiosis_init(SymbiosisSource source, bool trace, float resonance_gain);
void symbiosis_enable(bool enable);
bool symbiosis_active(void);
HumanPulse symbiosis_step(float liminal_frequency);
float symbiosis_alignment(void);
float symbiosis_resonance_level(void);
float symbiosis_phase_shift(void);
double symbiosis_delay_scale(void);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_INCLUDE_SYMBIOSIS_H */
