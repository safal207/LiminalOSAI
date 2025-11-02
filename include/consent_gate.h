#ifndef LIMINAL_CONSENT_GATE_H
#define LIMINAL_CONSENT_GATE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  float thr_consent;
  float thr_trust;
  float thr_presence;
  float thr_harmony;
  float open_bias;
  int warmup_cycles;
  int refractory;
  int tick;
  int refr_countdown;
  int is_open;
  float score;
} ConsentGate;

void consent_gate_init(ConsentGate* g);
void consent_gate_set_thresholds(ConsentGate* g, float c, float t, float p, float h);
void consent_gate_set_hysteresis(ConsentGate* g, float open_bias, int warmup, int refractory);
int consent_gate_update(ConsentGate* g,
                        float consent,
                        float trust,
                        float presence,
                        float harmony,
                        int kiss);
float consent_gate_score(const ConsentGate* g);
int consent_gate_is_open(const ConsentGate* g);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_CONSENT_GATE_H */
