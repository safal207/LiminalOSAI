#include "consent_gate.h"

#include <math.h>

static int
is_invalid_signal(float v)
{
    return !isfinite(v);
}

static float
max_threshold(const ConsentGate* g)
{
    float max = g->thr_consent;
    if (g->thr_trust > max) {
        max = g->thr_trust;
    }
    if (g->thr_presence > max) {
        max = g->thr_presence;
    }
    if (g->thr_harmony > max) {
        max = g->thr_harmony;
    }
    return max;
}

static void
close_gate(ConsentGate* g, int* event)
{
    if (g->is_open) {
        g->is_open = 0;
        g->refr_countdown = g->refractory;
        if (event) {
            *event = -1;
        }
    } else if (g->refr_countdown < g->refractory) {
        g->refr_countdown = g->refractory;
    }
}

void
consent_gate_init(ConsentGate* g)
{
    if (!g) {
        return;
    }

    g->thr_consent = 0.70f;
    g->thr_trust = 0.80f;
    g->thr_presence = 0.70f;
    g->thr_harmony = 0.85f;
    g->open_bias = 0.0f;
    g->warmup_cycles = 10;
    g->refractory = 5;
    g->tick = 0;
    g->refr_countdown = 0;
    g->is_open = 0;
    g->score = 0.0f;
}

void
consent_gate_set_thresholds(ConsentGate* g, float c, float t, float p, float h)
{
    if (!g) {
        return;
    }
    g->thr_consent = c;
    g->thr_trust = t;
    g->thr_presence = p;
    g->thr_harmony = h;
}

void
consent_gate_set_hysteresis(ConsentGate* g, float open_bias, int warmup, int refractory)
{
    if (!g) {
        return;
    }
    g->open_bias = open_bias;
    g->warmup_cycles = warmup;
    g->refractory = refractory;
    if (g->refr_countdown > g->refractory) {
        g->refr_countdown = g->refractory;
    }
}

int
consent_gate_update(ConsentGate* g,
                    float consent,
                    float trust,
                    float presence,
                    float harmony,
                    int kiss)
{
    if (!g) {
        return 0;
    }

    g->tick += 1;

    int event = 0;
    int refractory_active = g->refr_countdown > 0;

    if (is_invalid_signal(consent) || is_invalid_signal(trust) ||
        is_invalid_signal(presence) || is_invalid_signal(harmony)) {
        g->score = 0.0f;
        close_gate(g, &event);
        return event;
    }

    float kiss_level = kiss ? 1.0f : 0.0f;
    float score = 0.30f * consent + 0.30f * trust + 0.20f * harmony +
                  0.15f * presence + 0.05f * kiss_level;
    if (score < 0.0f) {
        score = 0.0f;
    } else if (score > 1.0f) {
        score = 1.0f;
    }
    g->score = score;

    float max_thr_value = max_threshold(g);
    float open_threshold = max_thr_value + g->open_bias;
    float close_threshold = max_thr_value - 0.05f;

    int warmup_ready = g->tick >= g->warmup_cycles;
    int hard_block = consent < 0.3f;
    int failsafe = (trust < 0.5f) && (presence < 0.5f);

    if (hard_block || failsafe) {
        close_gate(g, &event);
    } else {
        if (g->is_open) {
            if (score < close_threshold || refractory_active) {
                close_gate(g, &event);
            }
        } else if (!refractory_active && warmup_ready && (score >= open_threshold)) {
            g->is_open = 1;
            g->refr_countdown = 0;
            event = 1;
        }
    }

    if (g->refr_countdown > 0) {
        g->refr_countdown -= 1;
        if (g->refr_countdown < 0) {
            g->refr_countdown = 0;
        }
    }

    return event;
}

float
consent_gate_score(const ConsentGate* g)
{
    if (!g) {
        return 0.0f;
    }
    return g->score;
}

int
consent_gate_is_open(const ConsentGate* g)
{
    if (!g) {
        return 0;
    }
    return g->is_open;
}
