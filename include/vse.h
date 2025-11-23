#ifndef LIMINAL_VSE_H
#define LIMINAL_VSE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float p;
    float value;
    float cost;
    float pendulum;
} VNode;

typedef struct {
    float intent;
    float importance;
    float allowance;
    float temp;
} VSECfg;

typedef struct {
    float excess;
    float bias;
} VSEState;

void vse_init(VSECfg cfg);
void vse_set_graph(const VNode *nodes, int n);
int vse_pick(VSEState *st);
void vse_feedback(VSEState *st, float outcome);
void vse_set_temperature(float temp);
void vse_set_intent(float intent);
void vse_set_importance(float importance);
void vse_set_allowance(float allowance);
void vse_schedule_allowance(float delta);
void vse_set_allowance_hold(float hold);
void vse_set_lambda(float lambda_p, float lambda_x);
void vse_enable_trace(int enabled);
VSECfg vse_current_cfg(void);
void vse_finalize(void);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_VSE_H */
