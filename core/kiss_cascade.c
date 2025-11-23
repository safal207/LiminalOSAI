#include "kiss.h"

#include "coherence.h"
#include "resonant.h"
#include "soil.h"

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#ifndef KISS_LOG_PATH
#define KISS_LOG_PATH "logs/kiss.log"
#endif

static float clamp_unit(float value)
{
    if (!isfinite(value)) {
        return 0.0f;
    }
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

static void ensure_logs_directory(void)
{
#if defined(_WIN32)
    _mkdir("logs");
#else
    struct stat st;
    if (stat("logs", &st) == 0) {
        return;
    }
    mkdir("logs", 0777);
#endif
}

static float kiss_alpha = 0.25f;
static float kiss_trust_threshold = 0.80f;
static float kiss_presence_threshold = 0.70f;
static float kiss_harmony_threshold = 0.85f;
static unsigned int kiss_warmup_cycles = 10U;
static unsigned int kiss_refractory_cycles = 5U;

static unsigned int warmup_remaining = 10U;
static unsigned int refractory_remaining = 0U;

static float ema_trust = 0.0f;
static float ema_presence = 0.0f;
static float ema_harmony = 0.0f;
static bool ema_initialized = false;
static uint64_t kiss_cycle = 0ULL;
static FILE *kiss_log_stream = NULL;

void kiss_init(void)
{
    kiss_alpha = 0.25f;
    kiss_trust_threshold = 0.80f;
    kiss_presence_threshold = 0.70f;
    kiss_harmony_threshold = 0.85f;
    kiss_warmup_cycles = 10U;
    kiss_refractory_cycles = 5U;
    warmup_remaining = kiss_warmup_cycles;
    refractory_remaining = 0U;
    ema_trust = 0.0f;
    ema_presence = 0.0f;
    ema_harmony = 0.0f;
    ema_initialized = false;
    kiss_cycle = 0ULL;
    if (kiss_log_stream) {
        fclose(kiss_log_stream);
        kiss_log_stream = NULL;
    }
}

void kiss_set_thresholds(float trust, float presence, float harmony)
{
    kiss_trust_threshold = clamp_unit(trust);
    kiss_presence_threshold = clamp_unit(presence);
    kiss_harmony_threshold = clamp_unit(harmony);
}

void kiss_set_warmup(uint8_t cycles)
{
    kiss_warmup_cycles = (unsigned int)cycles;
    warmup_remaining = kiss_warmup_cycles;
}

void kiss_set_refractory(uint8_t cycles)
{
    kiss_refractory_cycles = (unsigned int)cycles;
    if (refractory_remaining > kiss_refractory_cycles) {
        refractory_remaining = kiss_refractory_cycles;
    }
}

void kiss_set_alpha(float alpha)
{
    if (!isfinite(alpha) || alpha <= 0.0f) {
        kiss_alpha = 0.25f;
        return;
    }
    if (alpha > 1.0f) {
        alpha = 1.0f;
    }
    kiss_alpha = alpha;
}

static void kiss_log_event(float trust, float presence, float harmony, float awareness)
{
    ensure_logs_directory();
    if (!kiss_log_stream) {
        kiss_log_stream = fopen(KISS_LOG_PATH, "a");
        if (!kiss_log_stream) {
            return;
        }
    }

    if (fprintf(kiss_log_stream,
                "{\"t\":%" PRIu64 ",\"trust\":%.4f,\"presence\":%.4f,\"harmony\":%.4f,\"aw\":%.4f,\"fired\":true}\n",
                kiss_cycle,
                trust,
                presence,
                harmony,
                awareness) > 0) {
        fflush(kiss_log_stream);
    }
}

static void kiss_imprint_soil(float trust, float presence, float harmony, float awareness)
{
    char imprint[SOIL_TRACE_DATA_SIZE];
    int written = snprintf(imprint,
                           sizeof(imprint),
                           "kiss trust=%.2f pres=%.2f harm=%.2f aw=%.2f",
                           trust,
                           presence,
                           harmony,
                           awareness);
    if (written < 0) {
        return;
    }
    if (written >= (int)sizeof(imprint)) {
        written = (int)sizeof(imprint) - 1;
        imprint[written] = '\0';
    }
    soil_trace trace = soil_trace_make(3U, imprint, (size_t)written);
    soil_write(&trace);
}

bool kiss_update(float trust, float presence, float harmony, float awareness_scale)
{
    ++kiss_cycle;

    float trust_clamped = clamp_unit(trust);
    float presence_clamped = clamp_unit(presence);
    float harmony_clamped = clamp_unit(harmony);
    float awareness_clamped = clamp_unit(awareness_scale);

    if (!ema_initialized) {
        ema_trust = trust_clamped;
        ema_presence = presence_clamped;
        ema_harmony = harmony_clamped;
        ema_initialized = true;
    } else {
        float retain = 1.0f - kiss_alpha;
        ema_trust = kiss_alpha * trust_clamped + retain * ema_trust;
        ema_presence = kiss_alpha * presence_clamped + retain * ema_presence;
        ema_harmony = kiss_alpha * harmony_clamped + retain * ema_harmony;
    }

    if (warmup_remaining > 0U) {
        --warmup_remaining;
        return false;
    }

    if (refractory_remaining > 0U) {
        --refractory_remaining;
        return false;
    }

    bool fired = (ema_trust >= kiss_trust_threshold) &&
                 (ema_presence >= kiss_presence_threshold) &&
                 (ema_harmony >= kiss_harmony_threshold);

    if (!fired) {
        return false;
    }

    refractory_remaining = kiss_refractory_cycles;

    float awareness_signal = awareness_clamped;
    kiss_log_event(ema_trust, ema_presence, ema_harmony, awareness_signal);
    kiss_imprint_soil(ema_trust, ema_presence, ema_harmony, awareness_signal);
    bus_emit_wave(RES_KISS_BROADCAST, awareness_signal);

    float boost = 0.02f * awareness_signal;
    if (boost > 0.0f) {
        coherence_apply_kiss_boost(boost);
    }

    return true;
}
