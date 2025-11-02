#ifndef LIMINAL_CONSENT_GATE_H
#define LIMINAL_CONSENT_GATE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CONSENT_GATE_REASON_MAX 32

typedef struct {
    float consent;
    float trust;
    float harmony;
    float presence;
    float kiss;
    float score;
    float threshold_open;
    float threshold_close;
    float hysteresis;
    float open_bias;
    uint16_t warmup_cycles;
    uint16_t warmup_remaining;
    uint16_t refractory_cycles;
    uint16_t refractory_remaining;
    bool open;
    bool nan_guard;
    char last_reason[CONSENT_GATE_REASON_MAX];
} ConsentGate;

void consent_gate_init(ConsentGate *gate);
void consent_gate_set_thresholds(ConsentGate *gate, float open_threshold, float close_threshold);
void consent_gate_set_hysteresis(ConsentGate *gate, float hysteresis);
void consent_gate_update(ConsentGate *gate, float consent, float trust, float harmony, float presence, float kiss);
float consent_gate_score(const ConsentGate *gate);
bool consent_gate_is_open(const ConsentGate *gate);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_CONSENT_GATE_H */
