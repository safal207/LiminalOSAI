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
static float observed_anticipation_level = 0.5f;
static float observed_anticipation_micro = 0.5f;
static float observed_anticipation_trend = 0.5f;
static bool random_seeded = false;

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

static float clamp_range(float value, float min_value, float max_value)
{
    if (value < min_value) {
        return min_value;
    }
    if (value > max_value) {
        return max_value;
    }
    return value;
}

static DreamAnticipation dream_make_anticipation(float level, float micro_pattern, float trend)
{
    DreamAnticipation snapshot;
    snapshot.level = clamp01(level);
    snapshot.micro_pattern = clamp01(micro_pattern);
    snapshot.trend = clamp01(trend);
    return snapshot;
}

static DreamAnticipation dream_blend_anticipation(DreamAnticipation current,
                                                  DreamAnticipation sample,
                                                  float weight)
{
    if (weight <= 0.0f) {
        return current;
    }
    if (weight >= 1.0f) {
        return sample;
    }

    current.level = clamp01(current.level * (1.0f - weight) + sample.level * weight);
    current.micro_pattern = clamp01(current.micro_pattern * (1.0f - weight) + sample.micro_pattern * weight);
    current.trend = clamp01(current.trend * (1.0f - weight) + sample.trend * weight);
    return current;
}

static DreamPhase dream_phase_for_cycle(int cycle)
{
    if (cycle <= 2) {
        return DREAM_PHASE_ENTRY;
    }
    if (cycle <= 8) {
        return DREAM_PHASE_SYNTHESIS;
    }
    return DREAM_PHASE_RELEASE;
}

static const char *dream_phase_tag(DreamPhase phase)
{
    switch (phase) {
    case DREAM_PHASE_ENTRY:
        return "ent";
    case DREAM_PHASE_SYNTHESIS:
        return "syn";
    case DREAM_PHASE_RELEASE:
        return "rel";
    default:
        return "unk";
    }
}

static DreamAnticipation dream_observed_anticipation(void)
{
    return dream_make_anticipation(observed_anticipation_level,
                                   observed_anticipation_micro,
                                   observed_anticipation_trend);
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
    dream_state_data.phase = DREAM_PHASE_ENTRY;
    dream_state_data.anticipation_current = dream_make_anticipation(0.5f, 0.5f, 0.5f);
    for (size_t i = 0; i < DREAM_PHASE_COUNT; ++i) {
        dream_state_data.anticipation_phase[i] = dream_state_data.anticipation_current;
    }
    dream_enabled = false;
    dream_logging = false;
    observed_coherence = 0.0f;
    observed_awareness = 0.0f;
    observed_anticipation_level = 0.5f;
    observed_anticipation_micro = 0.5f;
    observed_anticipation_trend = 0.5f;
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
    dream_state_data.phase = DREAM_PHASE_ENTRY;
    dream_state_data.anticipation_current = dream_observed_anticipation();
    dream_state_data.anticipation_phase[DREAM_PHASE_ENTRY] =
        dream_blend_anticipation(dream_state_data.anticipation_phase[DREAM_PHASE_ENTRY],
                                 dream_state_data.anticipation_current,
                                 0.7f);
    dream_state_data.anticipation_phase[DREAM_PHASE_SYNTHESIS] =
        dream_blend_anticipation(dream_state_data.anticipation_phase[DREAM_PHASE_SYNTHESIS],
                                 dream_state_data.anticipation_current,
                                 0.25f);
    dream_state_data.anticipation_phase[DREAM_PHASE_RELEASE] =
        dream_blend_anticipation(dream_state_data.anticipation_phase[DREAM_PHASE_RELEASE],
                                 dream_state_data.anticipation_current,
                                 0.15f);

    float anticipation_focus = dream_state_data.anticipation_current.level * 0.5f +
                               dream_state_data.anticipation_current.trend * 0.3f +
                               dream_state_data.anticipation_current.micro_pattern * 0.2f;
    dream_state_data.dream_intensity = clamp01(observed_coherence * 0.6f + anticipation_focus * 0.4f);

    awareness_set_coherence_scale(0.85);

    char summary[SOIL_TRACE_DATA_SIZE];
    int written = snprintf(summary,
                           sizeof(summary),
                           "dream_enter c=%.2f a=%.2f ant=%.2f/%.2f/%.2f",
                           observed_coherence,
                           observed_awareness,
                           dream_state_data.anticipation_current.level,
                           dream_state_data.anticipation_current.micro_pattern,
                           dream_state_data.anticipation_current.trend);
    if (written < 0) {
        summary[0] = '\0';
        written = 0;
    }
    dream_write_trace(summary, 3U);

    char log_line[96];
    snprintf(log_line,
             sizeof(log_line),
             "entering | coherence %.2f awareness %.2f ant(%.2f/%.2f/%.2f)",
             observed_coherence,
             observed_awareness,
             dream_state_data.anticipation_current.level,
             dream_state_data.anticipation_current.micro_pattern,
             dream_state_data.anticipation_current.trend);
    dream_log(log_line);
}

void dream_iterate(void)
{
    if (!dream_state_data.active) {
        return;
    }

    ++dream_state_data.cycle_count;
    dream_state_data.phase = dream_phase_for_cycle(dream_state_data.cycle_count);

    DreamAnticipation sample = dream_observed_anticipation();
    float blend_rate = dream_state_data.phase == DREAM_PHASE_RELEASE ? 0.45f : 0.35f;
    dream_state_data.anticipation_current =
        dream_blend_anticipation(dream_state_data.anticipation_current, sample, blend_rate);
    dream_state_data.anticipation_phase[dream_state_data.phase] =
        dream_blend_anticipation(dream_state_data.anticipation_phase[dream_state_data.phase],
                                 dream_state_data.anticipation_current,
                                 dream_state_data.phase == DREAM_PHASE_RELEASE ? 0.55f : 0.45f);

    float anticipation_focus = dream_state_data.anticipation_current.level * 0.45f +
                               dream_state_data.anticipation_current.micro_pattern * 0.25f +
                               dream_state_data.anticipation_current.trend * 0.30f;
    dream_state_data.dream_intensity =
        clamp01(dream_state_data.dream_intensity * 0.60f + observed_coherence * 0.25f + anticipation_focus * 0.25f);

    char candidates[DREAM_SYMBOL_CHOICES][32];
    size_t count = dream_collect_symbols(candidates, DREAM_SYMBOL_CHOICES);

    if (count >= 2U) {
        dream_seed_random();
        size_t first = (size_t)(rand() % (int)count);
        size_t offset = 0U;
        if (count > 1U) {
            float offset_scale = dream_state_data.anticipation_current.micro_pattern * 0.8f + 0.1f;
            offset = (size_t)(offset_scale * (float)(count - 1U));
        }
        if (offset == 0U) {
            offset = 1U;
        }
        size_t second = (first + offset) % count;
        if (second == first) {
            second = (second + 1U) % count;
        }

        float weight_min = 0.12f + (dream_state_data.anticipation_current.trend - 0.5f) * 0.20f;
        float weight_max = 0.45f + (dream_state_data.anticipation_current.level - 0.5f) * 0.35f;
        weight_min = clamp_range(weight_min, 0.05f, 0.90f);
        weight_max = clamp_range(weight_max, weight_min + 0.05f, 0.95f);
        float weight = dream_random_range(weight_min, weight_max);

        symbol_create_link(candidates[first], candidates[second], weight);

        char imprint[SOIL_TRACE_DATA_SIZE];
        int written = snprintf(imprint,
                               sizeof(imprint),
                               "dream_echo:%s->%s w=%.2f %s af=%.2f",
                               candidates[first],
                               candidates[second],
                               weight,
                               dream_phase_tag(dream_state_data.phase),
                               anticipation_focus);
        if (written < 0) {
            imprint[0] = '\0';
            written = 0;
        }
        dream_write_trace(imprint, 2U);

        if (dream_logging) {
            char log_line[128];
            snprintf(log_line,
                     sizeof(log_line),
                     "link %s -> %s w=%.2f (int=%.2f phase=%s ant=%.2f/%.2f/%.2f)",
                     candidates[first],
                     candidates[second],
                     weight,
                     dream_state_data.dream_intensity,
                     dream_phase_tag(dream_state_data.phase),
                     dream_state_data.anticipation_current.level,
                     dream_state_data.anticipation_current.micro_pattern,
                     dream_state_data.anticipation_current.trend);
            dream_log(log_line);
        }
    } else if (dream_logging) {
        char log_line[96];
        snprintf(log_line,
                 sizeof(log_line),
                 "rest cycle %d (int=%.2f phase=%s ant=%.2f/%.2f/%.2f)",
                 dream_state_data.cycle_count,
                 dream_state_data.dream_intensity,
                 dream_phase_tag(dream_state_data.phase),
                 dream_state_data.anticipation_current.level,
                 dream_state_data.anticipation_current.micro_pattern,
                 dream_state_data.anticipation_current.trend);
        dream_log(log_line);
    }

    bool anticipation_release = false;
    if (dream_state_data.cycle_count >= 6) {
        DreamAnticipation release = dream_state_data.anticipation_phase[DREAM_PHASE_RELEASE];
        float release_metric = release.level * 0.4f + release.trend * 0.4f + release.micro_pattern * 0.2f;
        if (release_metric < 0.32f) {
            anticipation_release = true;
        }
    }
    if (!anticipation_release && dream_state_data.cycle_count >= 4) {
        DreamAnticipation sustain = dream_state_data.anticipation_phase[DREAM_PHASE_SYNTHESIS];
        float sustain_metric = sustain.level * 0.5f + sustain.trend * 0.5f;
        if (sustain_metric < 0.28f) {
            anticipation_release = true;
        }
    }

    if (dream_state_data.cycle_count >= 12 || anticipation_release) {
        dream_exit();
    }
}

void dream_exit(void)
{
    if (!dream_state_data.active) {
        awareness_set_coherence_scale(1.0);
        return;
    }

    DreamAnticipation release_state = dream_state_data.anticipation_phase[DREAM_PHASE_RELEASE];
    float release_focus = release_state.level * 0.4f + release_state.trend * 0.4f + release_state.micro_pattern * 0.2f;
    float release_scale = clamp_range(0.95f + (release_state.trend - 0.5f) * 0.08f, 0.85f, 1.05f);

    dream_state_data.active = false;
    dream_state_data.dream_intensity = 0.0f;
    dream_state_data.cycle_count = 0;
    dream_state_data.phase = DREAM_PHASE_ENTRY;
    dream_state_data.anticipation_current =
        dream_blend_anticipation(dream_state_data.anticipation_current, release_state, 0.5f);

    awareness_set_coherence_scale(release_scale);

    float drift = weave_current_drift();
    char imprint[SOIL_TRACE_DATA_SIZE];
    int written = snprintf(imprint,
                           sizeof(imprint),
                           "dream_exit drift=%.2f ant=%.2f",
                           drift,
                           release_focus);
    if (written < 0) {
        imprint[0] = '\0';
        written = 0;
    }
    dream_write_trace(imprint, 2U);

    char log_line[96];
    snprintf(log_line,
             sizeof(log_line),
             "exit | drift %.2f awareness %.2f ant(%.2f/%.2f/%.2f)",
             drift,
             observed_awareness,
             release_state.level,
             release_state.micro_pattern,
             release_state.trend);
    dream_log(log_line);
}

void dream_update(float coherence,
                  float awareness_level,
                  float anticipation_level,
                  float anticipation_micro_pattern,
                  float anticipation_trend)
{
    if (!isfinite(coherence)) {
        coherence = 0.0f;
    }
    if (!isfinite(awareness_level)) {
        awareness_level = 0.0f;
    }
    if (!isfinite(anticipation_level)) {
        anticipation_level = 0.5f;
    }
    if (!isfinite(anticipation_micro_pattern)) {
        anticipation_micro_pattern = 0.5f;
    }
    if (!isfinite(anticipation_trend)) {
        anticipation_trend = 0.5f;
    }

    observed_coherence = clamp01(coherence);
    observed_awareness = clamp01(awareness_level);
    observed_anticipation_level = clamp01(anticipation_level);
    observed_anticipation_micro = clamp01(anticipation_micro_pattern);
    observed_anticipation_trend = clamp01(anticipation_trend);

    DreamAnticipation sample = dream_observed_anticipation();

    if (!dream_enabled) {
        if (dream_state_data.active) {
            dream_exit();
        } else {
            awareness_set_coherence_scale(1.0);
        }
        return;
    }

    if (!dream_state_data.active) {
        awareness_set_coherence_scale(1.0);
        dream_state_data.anticipation_current =
            dream_blend_anticipation(dream_state_data.anticipation_current, sample, 0.25f);
        dream_state_data.anticipation_phase[DREAM_PHASE_ENTRY] =
            dream_blend_anticipation(dream_state_data.anticipation_phase[DREAM_PHASE_ENTRY], sample, 0.25f);

        float anticipation_gate = (sample.level + sample.micro_pattern + sample.trend) / 3.0f;
        float readiness = observed_coherence * 0.65f + anticipation_gate * 0.35f;
        if (readiness >= dream_state_data.entry_threshold && observed_awareness < 0.3f) {
            dream_enter();
        }
        return;
    }

    float coherence_limit = dream_state_data.entry_threshold * 0.82f;
    DreamAnticipation release = dream_state_data.anticipation_phase[DREAM_PHASE_RELEASE];
    float release_metric = release.level * 0.4f + release.trend * 0.4f + release.micro_pattern * 0.2f;
    float current_metric = sample.level * 0.4f + sample.trend * 0.4f + sample.micro_pattern * 0.2f;
    bool anticipation_drop = dream_state_data.cycle_count > 2 && current_metric < 0.28f && release_metric < 0.35f;

    if (observed_coherence < coherence_limit || observed_awareness >= 0.45f || anticipation_drop) {
        dream_exit();
        return;
    }

    dream_iterate();
}
