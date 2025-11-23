#ifndef LIMINAL_ASTRO_SYNC_H
#define LIMINAL_ASTRO_SYNC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float tone;
    float memory;
    float drift;
    float k_tone;
    float k_relax;
    float k_mem;
    float k_decay;
    float ca_phase;
    float ca_rate;
    float tempo;
    float last_stability;
    float last_agitation;
    float last_wave;
    float last_gain;
} Astro;

typedef struct {
    uint32_t signature;
    float tone_avg;
    float memory_avg;
    float ca_rate;
    float stability_avg;
    uint64_t timestamp;
} AstroMemory;

void astro_init(Astro *a);
void astro_set_tone(Astro *a, float tone);
void astro_set_memory(Astro *a, float memory);
void astro_set_ca_rate(Astro *a, float rate);
void astro_update(Astro *a,
                  float harm_sm,
                  float coh_group,
                  float trs_delta,
                  float consent,
                  float influence);
float astro_modulate_feedback(const Astro *a);

AstroMemory astro_memory_make(uint32_t signature,
                              float tone_avg,
                              float memory_avg,
                              float ca_rate,
                              float stability_avg,
                              uint64_t timestamp);
size_t astro_memory_load(const char *path, AstroMemory *entries, size_t max_entries);
bool astro_memory_append(const char *path, const AstroMemory *snapshot);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_ASTRO_SYNC_H */
