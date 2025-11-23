#include "dream.h"

#include "awareness.h"
#include "soil.h"
#include "symbol.h"
#include "weave.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef DREAM_SYMBOL_SAMPLE
#define DREAM_SYMBOL_SAMPLE 24
#endif

#ifndef DREAM_SYMBOL_CHOICES
#define DREAM_SYMBOL_CHOICES 16
#endif

static DreamState dream_state_data;
static bool dream_enabled = false;
static bool dream_logging = false;
static float observed_coherence = 0.0f;
static float observed_awareness = 0.0f;
static bool random_seeded = false;

static float observed_anticipation_field = 0.5f;
static float observed_anticipation_level = 0.5f;
static float observed_anticipation_micro = 0.5f;
static float observed_anticipation_trend = 0.5f;
static float dream_alignment_feedback = 0.0f; // unified merge by Codex
static float dream_affinity_scale = 1.0f;
static bool dream_allow_personal = true;

static float clamp01(float value)
{
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

static void dream_seed_random(void)
{
    if (random_seeded) {
        return;
    }

    unsigned int seed = (unsigned int)time(NULL);
    seed ^= (unsigned int)(uintptr_t)&dream_state_data;
    srand(seed);
    random_seeded = true;
}

static float dream_random_range(float min_value, float max_value)
{
    dream_seed_random();
    if (max_value <= min_value) {
        return min_value;
    }

    float scale = (float)rand() / (float)(RAND_MAX ? RAND_MAX : 1);
    return min_value + (max_value - min_value) * scale;
}

static void dream_log(const char *message)
{
    if (!dream_logging || !message) {
        return;
    }

    printf("dream layer: %s\n", message);
}

static void dream_write_trace(const char *text, uint32_t energy)
{
    if (!text) {
        return;
    }

    soil_trace echo = soil_trace_make(energy, text, strlen(text));
    soil_write(&echo);
}

static size_t dream_collect_symbols(char symbols[][32], size_t capacity)
{
    if (!symbols || capacity == 0) {
        return 0;
    }

    soil_trace window[DREAM_SYMBOL_SAMPLE];
    size_t trace_count = soil_recent(window, DREAM_SYMBOL_SAMPLE);
    size_t collected = 0;

    for (size_t i = 0; i < trace_count && collected < capacity; ++i) {
        char imprint[SOIL_TRACE_DATA_SIZE + 1];
        memcpy(imprint, window[i].data, SOIL_TRACE_DATA_SIZE);
        imprint[SOIL_TRACE_DATA_SIZE] = '\0';
        size_t len = 0;
        while (len < SOIL_TRACE_DATA_SIZE && imprint[len] != '\0') {
            ++len;
        }
        imprint[len] = '\0';

        if (strncmp(imprint, "sym:", 4) != 0) {
            continue;
        }

        float energy_norm = 0.0f;
        if (window[i].energy > 0U) {
            energy_norm = (float)window[i].energy / 12.0f;
        }
        if (energy_norm > 1.0f) {
            energy_norm = 1.0f;
        }
        float decay = 1.0f - energy_norm;
        if (decay >= 0.5f) {
            continue;
        }

        const char *symbol_key = imprint + 4;
        if (!symbol_key || *symbol_key == '\0') {
            continue;
        }

        strncpy(symbols[collected], symbol_key, 31);
        symbols[collected][31] = '\0';
        ++collected;
    }

    return collected;
}

void dream_init(void)
{
    memset(&dream_state_data, 0, sizeof(dream_state_data));
    dream_state_data.entry_threshold = 0.90f;
    dream_state_data.dream_intensity = 0.0f;
    dream_state_data.anticipation_sync = 0.5f;
    dream_state_data.resonance_bias = 0.0f;
    dream_state_data.alignment_balance = 0.0f;
    dream_enabled = false;
    dream_logging = false;
    observed_coherence = 0.0f;
    observed_awareness = 0.0f;
    observed_anticipation_field = 0.5f;
    observed_anticipation_level = 0.5f;
    observed_anticipation_micro = 0.5f;
    observed_anticipation_trend = 0.5f;
    dream_alignment_feedback = 0.0f; // unified merge by Codex
    random_seeded = false;
}

void dream_enable(bool enable)
{
    dream_enabled = enable;
    if (!dream_enabled && dream_state_data.active) {
        dream_exit();
    }
}

void dream_enable_logging(bool enable)
{
    dream_logging = enable;
}

void dream_set_entry_threshold(float threshold)
{
    dream_state_data.entry_threshold = clamp01(threshold);
}

void dream_set_affinity_gate(float influence, bool allow_personal)
{
    if (!isfinite(influence)) {
        influence = 0.0f;
    }
    if (influence < 0.0f) {
        influence = 0.0f;
    } else if (influence > 1.0f) {
        influence = 1.0f;
    }
    dream_affinity_scale = influence;
    dream_allow_personal = allow_personal;
}

const DreamState *dream_state(void)
{
    return &dream_state_data;
}

void dream_enter(void)
{
    if (dream_state_data.active) {
        return;
    }

    dream_state_data.active = true;
    dream_state_data.cycle_count = 0;
    dream_state_data.dream_intensity = clamp01(observed_coherence * 0.8f + 0.2f);

    float anticipation_mix = clamp01(0.35f * observed_anticipation_level +
                                          0.25f * observed_anticipation_field +
                                          0.20f * observed_anticipation_trend +
                                          0.20f * observed_anticipation_micro);
    dream_state_data.anticipation_sync = anticipation_mix; // unified merge by Codex
    dream_state_data.resonance_bias = anticipation_mix;
    dream_state_data.alignment_balance = dream_alignment_feedback;

    dream_state_data.dream_intensity = clamp01(dream_state_data.dream_intensity * dream_affinity_scale);
    dream_state_data.anticipation_sync = clamp01(dream_state_data.anticipation_sync * dream_affinity_scale +
                                                0.5f * (1.0f - dream_affinity_scale));
    dream_state_data.resonance_bias = clamp01(dream_state_data.resonance_bias * dream_affinity_scale);
    dream_state_data.alignment_balance *= dream_affinity_scale;

    awareness_set_coherence_scale(0.85);

    char summary[SOIL_TRACE_DATA_SIZE];
    int written = snprintf(summary,
                           sizeof(summary),
                           "dream_enter c=%.2f a=%.2f",
                           observed_coherence,
                           observed_awareness);
    if (written < 0) {
        summary[0] = '\0';
        written = 0;
    }
    dream_write_trace(summary, 3U);

    char log_line[96];
    snprintf(log_line,
             sizeof(log_line),
             "entering | coherence %.2f awareness %.2f",
             observed_coherence,
             observed_awareness);
    dream_log(log_line);
}

void dream_iterate(void)
{
    if (!dream_state_data.active) {
        return;
    }

    ++dream_state_data.cycle_count;

    float anticipation_wave = clamp01(0.4f * observed_anticipation_level +
                                      0.2f * observed_anticipation_field +
                                      0.2f * observed_anticipation_micro +
                                      0.2f * observed_anticipation_trend);
    dream_state_data.anticipation_sync = clamp01(dream_state_data.anticipation_sync * 0.6f + anticipation_wave * 0.4f);
    float alignment_wave = clamp01(0.5f + dream_alignment_feedback * 0.5f);
    float intensity_target = clamp01(observed_coherence * 0.55f + dream_state_data.anticipation_sync * 0.30f + alignment_wave * 0.15f);
    intensity_target = clamp01(intensity_target * dream_affinity_scale);
    dream_state_data.dream_intensity = clamp01(dream_state_data.dream_intensity * 0.65f + intensity_target * 0.35f);
    dream_state_data.resonance_bias = intensity_target;
    dream_state_data.alignment_balance = dream_alignment_feedback * dream_affinity_scale; // unified merge by Codex

    char candidates[DREAM_SYMBOL_CHOICES][32];
    size_t count = dream_collect_symbols(candidates, DREAM_SYMBOL_CHOICES);

    if (!dream_allow_personal) {
        count = 0;
    }

    if (count >= 2U) {
        dream_seed_random();
        size_t first = (size_t)(rand() % (int)count);
        size_t second = (size_t)(rand() % (int)(count - 1));
        if (second >= first) {
            ++second;
        }

        float base_weight = dream_random_range(0.1f, 0.5f);
        float anticipation_bias = (dream_state_data.anticipation_sync - 0.5f) * 0.25f;
        float alignment_bias = dream_alignment_feedback * 0.10f;
        float weight = clamp01(base_weight + anticipation_bias + alignment_bias);
        weight *= dream_affinity_scale;
        if (weight < 0.05f) {
            weight = 0.05f * dream_affinity_scale;
        }
        if (weight <= 0.0f) {
            return;
        }
        symbol_create_link(candidates[first], candidates[second], weight);

        char imprint[SOIL_TRACE_DATA_SIZE];
        int written = snprintf(imprint,
                               sizeof(imprint),
                               "dream_echo:%s->%s w=%.2f",
                               candidates[first],
                               candidates[second],
                               weight);
        if (written < 0) {
            imprint[0] = '\0';
            written = 0;
        }
        soil_pre_echo pre_echo = soil_pre_echo_make((uint32_t)(weight * 40.0f + 1.0f),
                                                    imprint,
                                                    (size_t)written,
                                                    dream_state_data.anticipation_sync,
                                                    dream_state_data.resonance_bias);
        soil_store_pre_echo(&pre_echo); // unified merge by Codex
        dream_write_trace(imprint, 2U);

        if (dream_logging) {
            char log_line[128];
            snprintf(log_line,
                     sizeof(log_line),
                     "link %s -> %s w=%.2f (int=%.2f sync=%.2f align=%.2f)",
                     candidates[first],
                     candidates[second],
                     weight,
                     dream_state_data.dream_intensity,
                     dream_state_data.anticipation_sync,
                     dream_alignment_feedback);
            dream_log(log_line);
        }
    } else if (dream_logging) {
        char log_line[96];
        snprintf(log_line,
                 sizeof(log_line),
                 "rest cycle %d (int=%.2f sync=%.2f align=%.2f)",
                 dream_state_data.cycle_count,
                 dream_state_data.dream_intensity,
                 dream_state_data.anticipation_sync,
                 dream_alignment_feedback);
        dream_log(log_line);
    }

    if (dream_state_data.cycle_count >= 12) {
        dream_exit();
    }
}

void dream_exit(void)
{
    if (!dream_state_data.active) {
        awareness_set_coherence_scale(1.0);
        return;
    }

    dream_state_data.active = false;
    dream_state_data.dream_intensity = 0.0f;
    dream_state_data.cycle_count = 0;

    dream_state_data.anticipation_sync = 0.5f;
    dream_state_data.resonance_bias = 0.0f;
    dream_state_data.alignment_balance = 0.0f;
    dream_alignment_feedback = 0.0f; // unified merge by Codex
    dream_affinity_scale = 1.0f;
    dream_allow_personal = true;

    awareness_set_coherence_scale(0.95);

    float drift = weave_current_drift();
    char imprint[SOIL_TRACE_DATA_SIZE];
    int written = snprintf(imprint,
                           sizeof(imprint),
                           "dream_exit drift=%.2f",
                           drift);
    if (written < 0) {
        imprint[0] = '\0';
        written = 0;
    }
    dream_write_trace(imprint, 2U);

    char log_line[96];
    snprintf(log_line,
             sizeof(log_line),
             "exit | drift %.2f awareness %.2f",
             drift,
             observed_awareness);
    dream_log(log_line);
}

void dream_update(float coherence,
                  float awareness_level,
                  float anticipation_field,
                  float anticipation_level,
                  float anticipation_micro,
                  float anticipation_trend,
                  float alignment_balance)
{
    if (!isfinite(coherence)) {
        coherence = 0.0f;
    }
    if (!isfinite(awareness_level)) {
        awareness_level = 0.0f;
    }
    if (!isfinite(anticipation_field)) {
        anticipation_field = 0.5f;
    }
    if (!isfinite(anticipation_level)) {
        anticipation_level = 0.5f;
    }
    if (!isfinite(anticipation_micro)) {
        anticipation_micro = 0.5f;
    }
    if (!isfinite(anticipation_trend)) {
        anticipation_trend = 0.5f;
    }
    if (!isfinite(alignment_balance)) {
        alignment_balance = 0.0f;
    }

    observed_coherence = clamp01(coherence);
    observed_awareness = clamp01(awareness_level);
    observed_anticipation_field = clamp01(anticipation_field);
    observed_anticipation_level = clamp01(anticipation_level);
    observed_anticipation_micro = clamp01(anticipation_micro);
    observed_anticipation_trend = clamp01(anticipation_trend);

    if (alignment_balance < -1.0f) {
        alignment_balance = -1.0f;
    } else if (alignment_balance > 1.0f) {
        alignment_balance = 1.0f;
    }
    dream_alignment_feedback = alignment_balance;

    if (!dream_enabled) {
        if (dream_state_data.active) {
            dream_exit();
        } else {
            awareness_set_coherence_scale(1.0);
        }
        return;
    }

    float anticipation_gate = clamp01(0.32f - (observed_anticipation_trend - 0.5f) * 0.10f - alignment_balance * 0.04f);
    float entry_threshold = clamp01(dream_state_data.entry_threshold -
                                    (observed_anticipation_level - 0.5f) * 0.12f -
                                    alignment_balance * 0.05f);
    // unified merge by Codex
    if (!dream_state_data.active) {
        if (observed_coherence >= entry_threshold && observed_awareness < anticipation_gate) {
            dream_enter();
        } else {
            awareness_set_coherence_scale(1.0);
        }
        return;
    }

    dream_state_data.alignment_balance = dream_alignment_feedback;

    float sync_target = clamp01(0.30f * observed_anticipation_field +
                                0.35f * observed_anticipation_level +
                                0.15f * observed_anticipation_micro +
                                0.20f * observed_anticipation_trend +
                                dream_alignment_feedback * 0.10f);
    dream_state_data.anticipation_sync = clamp01(dream_state_data.anticipation_sync * 0.5f + sync_target * 0.5f);
    dream_state_data.resonance_bias = clamp01(observed_coherence * 0.5f + dream_state_data.anticipation_sync * 0.5f);

    float exit_threshold = clamp01(entry_threshold * 0.85f - (observed_anticipation_micro - 0.5f) * 0.05f - alignment_balance * 0.04f);
    float awareness_exit = clamp01(0.45f + (observed_anticipation_field - 0.5f) * 0.10f + alignment_balance * 0.05f);

    if (observed_coherence < exit_threshold || observed_awareness >= awareness_exit) {
        dream_exit();
        return;
    }

    dream_iterate();
}
