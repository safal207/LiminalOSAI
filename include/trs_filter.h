#ifndef LIMINAL_TRS_FILTER_H
#define LIMINAL_TRS_FILTER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float alpha;
    float sm_influence;
    float sm_harmony;
    float sm_consent;
    int warmup;
} TRS;

void trs_init(TRS *t, float alpha);
void trs_reset(TRS *t);
void trs_step(TRS *t,
              float raw_influence,
              float raw_harmony,
              float raw_consent,
              float *out_influence,
              float *out_harmony,
              float *out_consent,
              float *out_delta);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_TRS_FILTER_H */
