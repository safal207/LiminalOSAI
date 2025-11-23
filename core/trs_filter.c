#include "trs_filter.h"

#include <math.h>

static float sanitize_value(float value)
{
    if (!isfinite(value)) {
        return 0.0f;
    }
    return value;
}

static float clamp_alpha(float alpha)
{
    if (!isfinite(alpha)) {
        return 0.3f;
    }
    if (alpha < 0.0f) {
        return 0.0f;
    }
    if (alpha > 1.0f) {
        return 1.0f;
    }
    return alpha;
}

void trs_init(TRS *t, float alpha)
{
    if (!t) {
        return;
    }
    t->alpha = clamp_alpha(alpha);
    t->sm_influence = 0.0f;
    t->sm_harmony = 0.0f;
    t->sm_consent = 0.0f;
    t->warmup = 5;
}

void trs_reset(TRS *t)
{
    if (!t) {
        return;
    }
    t->sm_influence = 0.0f;
    t->sm_harmony = 0.0f;
    t->sm_consent = 0.0f;
    t->warmup = 5;
}

void trs_step(TRS *t,
              float raw_influence,
              float raw_harmony,
              float raw_consent,
              float *out_influence,
              float *out_harmony,
              float *out_consent,
              float *out_delta)
{
    if (!t) {
        return;
    }

    float influence = sanitize_value(raw_influence);
    float harmony = sanitize_value(raw_harmony);
    float consent = sanitize_value(raw_consent);

    if (!isfinite(t->alpha)) {
        t->alpha = 0.3f;
    }

    float alpha = clamp_alpha(t->alpha);
    if (alpha == 0.0f && t->warmup <= 0) {
        t->sm_influence = influence;
        t->sm_harmony = harmony;
        t->sm_consent = consent;
    } else if (t->warmup > 0) {
        t->sm_influence = influence;
        t->sm_harmony = harmony;
        t->sm_consent = consent;
        t->warmup -= 1;
    } else {
        float one_minus = 1.0f - alpha;
        t->sm_influence = alpha * influence + one_minus * t->sm_influence;
        t->sm_harmony = alpha * harmony + one_minus * t->sm_harmony;
        t->sm_consent = alpha * consent + one_minus * t->sm_consent;
    }

    if (out_influence) {
        *out_influence = t->sm_influence;
    }
    if (out_harmony) {
        *out_harmony = t->sm_harmony;
    }
    if (out_consent) {
        *out_consent = t->sm_consent;
    }
    if (out_delta) {
        float di = fabsf(t->sm_influence - influence);
        float dh = fabsf(t->sm_harmony - harmony);
        float dc = fabsf(t->sm_consent - consent);
        float delta = di;
        if (dh > delta) {
            delta = dh;
        }
        if (dc > delta) {
            delta = dc;
        }
        *out_delta = delta;
    }
}
