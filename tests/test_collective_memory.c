#include "collective_memory.h"

#include <assert.h>
#include <math.h>

int main(void)
{
    CMemRing ring;
    cm_ring_reset(&ring);
    cm_set_snapshot_interval(2);

    for (int i = 0; i < CM_WINDOW; ++i) {
        cm_ring_push(&ring, 0.6f, 0.02f);
    }

    assert(ring.filled == CM_WINDOW);
    assert(cm_should_snapshot(&ring));

    CMemTrace trace = cm_build_snapshot(&ring, 0xABCD1234u);
    assert(trace.signature == 0xABCD1234u);
    assert(trace.group_coh_avg > 0.5f && trace.group_coh_avg < 0.7f);
    assert(trace.volatility >= 0.0f && trace.volatility < 0.02f);
    assert(cm_last_volatility() >= 0.0f);

    float sim_same = cm_signature_similarity(0xAA55AA55u, 0xAA55AA55u);
    float sim_diff = cm_signature_similarity(0x00000000u, 0xFFFFFFFFu);
    assert(fabsf(sim_same - 1.0f) < 1e-6f);
    assert(sim_diff <= 0.01f);

    return 0;
}
