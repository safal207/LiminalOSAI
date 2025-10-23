#include "harmony.h"

#include "introspect.h"

#include <math.h>

static double sanitize_metric(double value)
{
    if (!isfinite(value)) {
        return 0.0;
    }
    return value;
}

void harmony_sync(struct introspect_state *state, struct introspect_metrics *metrics)
{
    if (!state || !metrics) {
        return;
    }

    if (!state->enabled || !state->harmony_enabled) {
        return;
    }
    double amp = sanitize_metric(metrics->amp);
    double tempo = sanitize_metric(metrics->tempo);
    double influence = sanitize_metric(metrics->influence);
    double consent = sanitize_metric(metrics->consent);

    double diff = fabs(amp - tempo);
    double harmony = 0.7 * influence + 0.3 * consent;
    if (diff < 0.1 && influence > 0.6) {
        harmony = 1.0;
    }

    if (!isfinite(harmony)) {
        harmony = 0.0;
    }
    if (harmony < 0.0) {
        harmony = 0.0;
    } else if (harmony > 1.0) {
        harmony = 1.0;
    }

    metrics->harmony = (float)harmony;
    state->last_harmony = harmony;
}
