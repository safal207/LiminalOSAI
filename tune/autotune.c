#include "autotune.h"

#include "introspect.h"
#include "trs_filter.h"

#include <float.h>
#include <math.h>
#include <string.h>

#define AUTOTUNE_WEIGHT_DELTA 0.7f
#define AUTOTUNE_WEIGHT_HARM  0.2f
#define AUTOTUNE_WEIGHT_ALIGN 0.1f
#define AUTOTUNE_MAX_RANKED   16

typedef struct {
    unsigned int state;
} TuneRng;

static TuneResult g_ranked[AUTOTUNE_MAX_RANKED];
static size_t g_ranked_count = 0;
static float g_last_allow_align = 0.2f;

static void rng_seed(TuneRng *rng, unsigned int seed)
{
    if (!rng) {
        return;
    }
    if (seed == 0U) {
        seed = 0xA341316Cu;
    }
    rng->state = seed;
}

static float rng_uniform(TuneRng *rng)
{
    if (!rng) {
        return 0.0f;
    }
    rng->state = rng->state * 1664525u + 1013904223u;
    unsigned int value = (rng->state >> 8) & 0x00FFFFFFu;
    return (float)value / 16777216.0f;
}

static float clamp_float(float value, float min_value, float max_value)
{
    if (!isfinite(value)) {
        return min_value;
    }
    if (value < min_value) {
        return min_value;
    }
    if (value > max_value) {
        return max_value;
    }
    return value;
}

static float clamp_unit(float value)
{
    return clamp_float(value, 0.0f, 1.0f);
}

static void reset_ranked(void)
{
    g_ranked_count = 0;
}

static void record_candidate(const TuneResult *candidate)
{
    if (!candidate || !isfinite(candidate->loss)) {
        return;
    }
    if (g_ranked_count < AUTOTUNE_MAX_RANKED) {
        g_ranked[g_ranked_count] = *candidate;
        g_ranked_count += 1;
    } else if (candidate->loss < g_ranked[AUTOTUNE_MAX_RANKED - 1].loss) {
        g_ranked[AUTOTUNE_MAX_RANKED - 1] = *candidate;
    } else {
        return;
    }
    size_t start = (g_ranked_count == 0) ? 0 : g_ranked_count - 1;
    if (start >= AUTOTUNE_MAX_RANKED) {
        start = AUTOTUNE_MAX_RANKED - 1;
    }
    for (size_t i = start; i > 0; --i) {
        if (g_ranked[i].loss < g_ranked[i - 1].loss) {
            TuneResult tmp = g_ranked[i];
            g_ranked[i] = g_ranked[i - 1];
            g_ranked[i - 1] = tmp;
        } else {
            break;
        }
    }
    if (g_ranked_count > AUTOTUNE_MAX_RANKED) {
        g_ranked_count = AUTOTUNE_MAX_RANKED;
    }
}

static float sanitize_episode_value(float value, float fallback)
{
    if (!isfinite(value)) {
        return fallback;
    }
    return value;
}

static void evaluate_dataset(const Episode *const *episodes,
                             size_t episode_count,
                             const TuneConfig *cfg,
                             TuneResult *out)
{
    if (!out) {
        return;
    }
    TuneResult result;
    memset(&result, 0, sizeof(result));
    result.loss = FLT_MAX;
    if (!episodes || episode_count == 0 || !cfg) {
        if (out) {
            *out = result;
        }
        return;
    }

    double total_delta = 0.0;
    double total_harm = 0.0;
    double total_consent = 0.0;
    double total_misalign = 0.0;
    int total_ticks = 0;

    for (size_t i = 0; i < episode_count; ++i) {
        const Episode *ep = episodes[i];
        if (!ep || ep->len <= 0) {
            continue;
        }
        TRS state;
        trs_init(&state, clamp_float(cfg->trs_alpha, 0.0f, 1.0f));
        state.warmup = cfg->trs_warmup;
        if (state.warmup < 0) {
            state.warmup = 0;
        }
        if (state.warmup > 10) {
            state.warmup = 10;
        }

        for (int tick = 0; tick < ep->len; ++tick) {
            TickSnapshot snap = ep->seq[tick];
            float influence_raw = clamp_unit(sanitize_episode_value(snap.influence, 0.0f));
            float harmony_raw = clamp_unit(sanitize_episode_value(snap.harmony, influence_raw));
            float consent_raw = clamp_unit(sanitize_episode_value(snap.consent, 0.0f));

            float out_influence = influence_raw;
            float out_harmony = harmony_raw;
            float out_consent = consent_raw;
            float out_delta = 0.0f;
            trs_step(&state,
                     influence_raw,
                     harmony_raw,
                     consent_raw,
                     &out_influence,
                     &out_harmony,
                     &out_consent,
                     &out_delta);

            float clamped_inf = clamp_unit(out_influence);
            float clamped_harm = clamp_unit(out_harmony);
            float clamped_consent = clamp_unit(out_consent);
            float misalign = fabsf(clamped_consent - clamped_inf);

            total_delta += sanitize_episode_value(out_delta, 0.0f);
            total_harm += clamped_harm;
            total_consent += clamped_consent;
            if (misalign > cfg->allow_align) {
                total_misalign += 1.0;
            }
            total_ticks += 1;
        }
    }

    if (total_ticks > 0) {
        result.cfg = *cfg;
        result.delta_mean = (float)(total_delta / (double)total_ticks);
        result.harm_mean = (float)(total_harm / (double)total_ticks);
        result.consent_mean = (float)(total_consent / (double)total_ticks);
        result.misalign_rate = (float)(total_misalign / (double)total_ticks);
        if (!isfinite(result.delta_mean)) {
            result.delta_mean = 1.0f;
        }
        if (!isfinite(result.harm_mean)) {
            result.harm_mean = 0.0f;
        }
        if (!isfinite(result.consent_mean)) {
            result.consent_mean = 0.0f;
        }
        if (!isfinite(result.misalign_rate)) {
            result.misalign_rate = 1.0f;
        }
        result.delta_mean = clamp_float(result.delta_mean, 0.0f, 1.0f);
        result.harm_mean = clamp_float(result.harm_mean, 0.0f, 1.0f);
        result.consent_mean = clamp_float(result.consent_mean, 0.0f, 1.0f);
        result.misalign_rate = clamp_float(result.misalign_rate, 0.0f, 1.0f);
        result.loss = AUTOTUNE_WEIGHT_DELTA * result.delta_mean +
                      AUTOTUNE_WEIGHT_HARM * (1.0f - result.harm_mean) +
                      AUTOTUNE_WEIGHT_ALIGN * result.misalign_rate;
    }

    *out = result;
}

static TuneConfig sample_config(const TuneSpace *space, TuneRng *rng)
{
    TuneConfig cfg;
    if (!space) {
        cfg.trs_alpha = 0.3f;
        cfg.trs_warmup = 5;
        cfg.allow_align = 0.5f;
        return cfg;
    }
    float alpha_min = space->trs_alpha_min;
    float alpha_max = space->trs_alpha_max;
    if (alpha_max < alpha_min) {
        float tmp = alpha_max;
        alpha_max = alpha_min;
        alpha_min = tmp;
    }
    float align_min = space->allow_align_min;
    float align_max = space->allow_align_max;
    if (align_max < align_min) {
        float tmp = align_max;
        align_max = align_min;
        align_min = tmp;
    }
    int warm_min = space->trs_warmup_min;
    int warm_max = space->trs_warmup_max;
    if (warm_max < warm_min) {
        int tmp = warm_max;
        warm_max = warm_min;
        warm_min = tmp;
    }

    float alpha_span = alpha_max - alpha_min;
    float align_span = align_max - align_min;
    float alpha_rand = rng_uniform(rng);
    float align_rand = rng_uniform(rng);
    cfg.trs_alpha = clamp_float(alpha_min + alpha_span * alpha_rand, alpha_min, alpha_max);
    cfg.allow_align = clamp_float(align_min + align_span * align_rand, align_min, align_max);
    float warm_rand = rng_uniform(rng);
    int warm_span = warm_max - warm_min;
    if (warm_span < 0) {
        warm_span = 0;
    }
    cfg.trs_warmup = warm_min + (int)lroundf(warm_rand * (float)warm_span);
    if (cfg.trs_warmup < warm_min) {
        cfg.trs_warmup = warm_min;
    }
    if (cfg.trs_warmup > warm_max) {
        cfg.trs_warmup = warm_max;
    }
    return cfg;
}

static TuneConfig perturb_config(const TuneConfig *base, const TuneSpace *space, TuneRng *rng)
{
    TuneConfig cfg = *base;
    if (!space) {
        return cfg;
    }
    float alpha_min = fminf(space->trs_alpha_min, space->trs_alpha_max);
    float alpha_max = fmaxf(space->trs_alpha_min, space->trs_alpha_max);
    float align_min = fminf(space->allow_align_min, space->allow_align_max);
    float align_max = fmaxf(space->allow_align_min, space->allow_align_max);
    int warm_min = space->trs_warmup_min <= space->trs_warmup_max ? space->trs_warmup_min : space->trs_warmup_max;
    int warm_max = space->trs_warmup_min <= space->trs_warmup_max ? space->trs_warmup_max : space->trs_warmup_min;

    float alpha_span = alpha_max - alpha_min;
    float align_span = align_max - align_min;
    float alpha_step = alpha_span * 0.1f;
    float align_step = align_span * 0.1f;
    if (alpha_step <= 0.0f) {
        alpha_step = 0.02f;
    }
    if (align_step <= 0.0f) {
        align_step = 0.02f;
    }
    float alpha_jitter = (rng_uniform(rng) * 2.0f - 1.0f) * alpha_step;
    float align_jitter = (rng_uniform(rng) * 2.0f - 1.0f) * align_step;
    cfg.trs_alpha = clamp_float(cfg.trs_alpha + alpha_jitter, alpha_min, alpha_max);
    cfg.allow_align = clamp_float(cfg.allow_align + align_jitter, align_min, align_max);

    int warm_span = warm_max - warm_min;
    int warm_step = warm_span / 10;
    if (warm_step < 1) {
        warm_step = 1;
    }
    int warm_jitter = (int)lroundf((rng_uniform(rng) * 2.0f - 1.0f) * (float)warm_step);
    cfg.trs_warmup += warm_jitter;
    if (cfg.trs_warmup < warm_min) {
        cfg.trs_warmup = warm_min;
    }
    if (cfg.trs_warmup > warm_max) {
        cfg.trs_warmup = warm_max;
    }

    return cfg;
}

static TuneResult run_search(const Episode *const *episodes,
                             size_t episode_count,
                             const TuneSpace *space,
                             int seed)
{
    TuneResult best;
    memset(&best, 0, sizeof(best));
    best.loss = FLT_MAX;
    reset_ranked();
    if (!episodes || episode_count == 0 || !space) {
        return best;
    }

    TuneSpace domain = *space;
    if (domain.trials <= 0) {
        domain.trials = 50;
    }
    if (domain.local_refine < 0) {
        domain.local_refine = 0;
    }

    TuneRng rng;
    rng_seed(&rng, (unsigned int)seed);

    for (int i = 0; i < domain.trials; ++i) {
        TuneConfig cfg = sample_config(&domain, &rng);
        TuneResult candidate;
        evaluate_dataset(episodes, episode_count, &cfg, &candidate);
        record_candidate(&candidate);
        if (candidate.loss < best.loss) {
            best = candidate;
        }
    }

    size_t base_count = g_ranked_count < 3 ? g_ranked_count : 3;
    TuneResult bases[3];
    for (size_t i = 0; i < base_count; ++i) {
        bases[i] = g_ranked[i];
    }

    if (base_count > 0 && domain.local_refine > 0) {
        int total_refine = domain.local_refine;
        int per_base = total_refine / (int)base_count;
        if (per_base <= 0) {
            per_base = 1;
        }
        int generated = 0;
        for (size_t b = 0; b < base_count && generated < total_refine; ++b) {
            for (int r = 0; r < per_base && generated < total_refine; ++r) {
                TuneConfig cfg = perturb_config(&bases[b].cfg, &domain, &rng);
                TuneResult candidate;
                evaluate_dataset(episodes, episode_count, &cfg, &candidate);
                record_candidate(&candidate);
                if (candidate.loss < best.loss) {
                    best = candidate;
                }
                generated += 1;
            }
        }
    }

    return best;
}

void tune_default_space(TuneSpace *space)
{
    if (!space) {
        return;
    }
    space->trs_alpha_min = 0.1f;
    space->trs_alpha_max = 0.6f;
    space->trs_warmup_min = 0;
    space->trs_warmup_max = 6;
    space->allow_align_min = 0.4f;
    space->allow_align_max = 0.8f;
    space->trials = 60;
    space->local_refine = 10;
}

TuneResult autotune_on_episode(const Episode *episode, const TuneSpace *space, int seed)
{
    const Episode *list[1];
    size_t count = 0;
    if (episode) {
        list[0] = episode;
        count = 1;
    }
    return run_search((count > 0) ? list : NULL, count, space, seed);
}

TuneResult autotune_on_erb(const ERB *erb, int select_n, const TuneSpace *space, int seed)
{
    const Episode *episodes[ERB_MAX_EPISODES];
    size_t count = 0;
    if (erb) {
        int available = erb_count(erb);
        if (select_n > 0 && select_n < available) {
            available = select_n;
        }
        for (int i = 0; i < available && count < ERB_MAX_EPISODES; ++i) {
            const Episode *ep = erb_get(erb, i);
            if (ep) {
                episodes[count++] = ep;
            }
        }
    }
    return run_search((count > 0) ? episodes : NULL, count, space, seed);
}

bool apply_tune_config(const TuneConfig *cfg)
{
    if (!cfg) {
        return false;
    }
    g_last_allow_align = clamp_unit(cfg->allow_align);
    return introspect_apply_trs_tune(cfg->trs_alpha, cfg->trs_warmup);
}

float autotune_get_last_allow_align(void)
{
    return g_last_allow_align;
}

size_t autotune_get_ranked_results(TuneResult *out, size_t capacity)
{
    if (!out || capacity == 0) {
        return 0;
    }
    size_t count = g_ranked_count < capacity ? g_ranked_count : capacity;
    memcpy(out, g_ranked, count * sizeof(TuneResult));
    return count;
}
