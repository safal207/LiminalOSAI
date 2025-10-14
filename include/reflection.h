#ifndef LIMINAL_REFLECTION_H
#define LIMINAL_REFLECTION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t timestamp;
    float energy_avg;
    float resonance_avg;
    float stability;
    char note[64];
} Reflection;

void reflect_log(float energy, float resonance, float stability, const char *note);
void reflect_dump(int n);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_REFLECTION_H */
