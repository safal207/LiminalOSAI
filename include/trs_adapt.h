#ifndef LIMINAL_TRS_ADAPT_H
#define LIMINAL_TRS_ADAPT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float alpha_min;
    float alpha_max;
    float target_delta;
    float k_p;
    float k_i;
    float k_d;
    float err_prev;
    float err_i;
    float last_alpha;
    float last_err;
    int low_delta_count;
} TRSAdapt;

void trs_adapt_init(TRSAdapt *a,
                    float alpha_min,
                    float alpha_max,
                    float target_delta,
                    float k_p,
                    float k_i,
                    float k_d,
                    float initial_alpha);

float trs_adapt_update(TRSAdapt *a, float delta);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_TRS_ADAPT_H */
