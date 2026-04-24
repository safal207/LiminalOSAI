#include "anticipation_v2.h"

#include <assert.h>
#include <math.h>

int main(void)
{
    Ant2 state;
    ant2_init(&state, 0.4f);
    ant2_set_trace(false);

    float pred_coh = 0.0f;
    float pred_delay = 0.0f;
    float ff = 0.0f;
    float scale = ant2_feedforward(&state,
                                   0.85f,
                                   0.60f,
                                   1.10f,
                                   0.75f,
                                   &pred_coh,
                                   &pred_delay,
                                   &ff);

    assert(isfinite(scale));
    assert(scale > 0.8f && scale < 1.2f);
    assert(isfinite(pred_coh));
    assert(isfinite(pred_delay));
    assert(ff >= -0.04f && ff <= 0.04f);

    float gain_before = state.gain;
    ant2_feedback_adjust(&state, 0.20f, ANT2_FEEDBACK_WINDUP_THRESHOLD);
    assert(state.gain <= gain_before);
    assert(state.gain >= 0.0f && state.gain <= 1.0f);

    return 0;
}
