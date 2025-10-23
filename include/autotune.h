#ifndef LIMINAL_AUTOTUNE_H
#define LIMINAL_AUTOTUNE_H

#include <stdbool.h>
#include <stddef.h>

#include "erb.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float trs_alpha_min;
    float trs_alpha_max;
    int trs_warmup_min;
    int trs_warmup_max;
    float allow_align_min;
    float allow_align_max;
    int trials;
    int local_refine;
} TuneSpace;

typedef struct {
    float trs_alpha;
    int trs_warmup;
    float allow_align;
} TuneConfig;

typedef struct {
    float loss;
    float delta_mean;
    float harm_mean;
    float consent_mean;
    float misalign_rate;
    TuneConfig cfg;
} TuneResult;

void tune_default_space(TuneSpace *space);
TuneResult autotune_on_episode(const Episode *episode, const TuneSpace *space, int seed);
TuneResult autotune_on_erb(const ERB *erb, int select_n, const TuneSpace *space, int seed);
bool apply_tune_config(const TuneConfig *cfg);
float autotune_get_last_allow_align(void);
size_t autotune_get_ranked_results(TuneResult *out, size_t capacity);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_AUTOTUNE_H */
