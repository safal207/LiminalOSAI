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
    dream_enabled = false;
    dream_logging = false;
    observed_coherence = 0.0f;
    observed_awareness = 0.0f;
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
    dream_state_data.dream_intensity = clamp01(observed_coherence * 0.8f + 0.2f);

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
    dream_state_data.dream_intensity = clamp01(dream_state_data.dream_intensity * 0.75f + observed_coherence * 0.25f);

    char candidates[DREAM_SYMBOL_CHOICES][32];
    size_t count = dream_collect_symbols(candidates, DREAM_SYMBOL_CHOICES);

    if (count >= 2U) {
        dream_seed_random();
        size_t first = (size_t)(rand() % (int)count);
        size_t second = (size_t)(rand() % (int)(count - 1));
        if (second >= first) {
            ++second;
        }

        float weight = dream_random_range(0.1f, 0.5f);
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
        dream_write_trace(imprint, 2U);

        if (dream_logging) {
            char log_line[128];
            snprintf(log_line,
                     sizeof(log_line),
                     "link %s -> %s w=%.2f (int=%.2f)",
                     candidates[first],
                     candidates[second],
                     weight,
                     dream_state_data.dream_intensity);
            dream_log(log_line);
        }
    } else if (dream_logging) {
        char log_line[96];
        snprintf(log_line,
                 sizeof(log_line),
                 "rest cycle %d (int=%.2f)",
                 dream_state_data.cycle_count,
                 dream_state_data.dream_intensity);
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

void dream_update(float coherence, float awareness_level)
{
    if (!isfinite(coherence)) {
        coherence = 0.0f;
    }
    if (!isfinite(awareness_level)) {
        awareness_level = 0.0f;
    }

    observed_coherence = clamp01(coherence);
    observed_awareness = clamp01(awareness_level);

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
        if (observed_coherence >= dream_state_data.entry_threshold && observed_awareness < 0.3f) {
            dream_enter();
        }
        return;
    }

    if (observed_coherence < dream_state_data.entry_threshold * 0.85f || observed_awareness >= 0.45f) {
        dream_exit();
        return;
    }

    dream_iterate();
}
