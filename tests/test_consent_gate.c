#include "consent_gate.h"

#include <assert.h>
#include <math.h>

int main(void)
{
    ConsentGate gate;
    consent_gate_init(&gate);
    consent_gate_set_thresholds(&gate, 0.7f, 0.7f, 0.7f, 0.7f);
    consent_gate_set_hysteresis(&gate, 0.0f, 2, 2);

    int event = 0;
    event = consent_gate_update(&gate, 0.95f, 0.95f, 0.95f, 0.95f, 1);
    assert(event == 0);
    event = consent_gate_update(&gate, 0.95f, 0.95f, 0.95f, 0.95f, 1);
    assert(event == 1);
    assert(consent_gate_is_open(&gate) == 1);
    assert(consent_gate_score(&gate) > 0.7f);

    event = consent_gate_update(&gate, NAN, 0.8f, 0.8f, 0.8f, 0);
    assert(event == -1);
    assert(consent_gate_is_open(&gate) == 0);

    return 0;
}
