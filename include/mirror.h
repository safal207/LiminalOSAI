#ifndef LIMINAL_MIRROR_H
#define LIMINAL_MIRROR_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float gain_amp;
    float gain_tempo;
} MirrorGains;

void mirror_reset(void);
void mirror_set_softness(float softness);
void mirror_set_trace(bool enable);
void mirror_enable(bool enable);
MirrorGains mirror_update(float influence, float energy, float calm, float tempo, float consent);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_MIRROR_H */
