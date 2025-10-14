#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#endif

#include "introspect.h"
#include "dream_coupler.h"
#include "trs_filter.h"

#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <time.h>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#ifndef INTROSPECT_LOG_PATH
#define INTROSPECT_LOG_PATH "logs/introspect_v1.log"
#endif

static const float TRS_ALPHA_DEFAULT = 0.3f;
static const int TRS_WARMUP_DEFAULT = 5;
static const uint64_t TRS_SYNC_INTERVAL = 5ULL;

static bool g_trs_enabled = false;
static bool g_trs_initialized = false;
static float g_trs_alpha = TRS_ALPHA_DEFAULT;
static int g_trs_warmup_target = TRS_WARMUP_DEFAULT;
static TRS g_trs_state;
static FILE *g_trs_sync_stream = NULL;

static double sanitize_value(double value)
{
    if (!isfinite(value)) {
        return 0.0;
    }
    return value;
}

static float clamp_trs_alpha_value(float value)
{
    if (!isfinite(value)) {
        return TRS_ALPHA_DEFAULT;
    }
    if (value < 0.05f) {
        return 0.05f;
    }
    if (value > 0.8f) {
        return 0.8f;
    }
    return value;
}

static int clamp_trs_warmup_value(int value)
{
    if (value < 0) {
        return 0;
    }
    if (value > 10) {
        return 10;
    }
    return value;
}

static double clamp_unit_value(double value)
{
    if (!isfinite(value)) {
        return 0.0;
    }
    if (value < 0.0) {
        return 0.0;
    }
    if (value > 1.0) {
        return 1.0;
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

static void format_timestamp(char *buffer, size_t size)
{
    if (!buffer || size == 0) {
        return;
    }
    time_t now = time(NULL);
    struct tm tm_now;
#if defined(_WIN32)
    gmtime_s(&tm_now, &now);
#else
    gmtime_r(&now, &tm_now);
#endif
    if (strftime(buffer, size, "%Y-%m-%dT%H:%M:%SZ", &tm_now) == 0) {
        if (size > 0) {
            buffer[0] = '\0';
        }
    }
}

void introspect_state_init(State *state)
{
    if (!state) {
        return;
    }
    state->enabled = false;
    state->harmony_enabled = false;
    state->harmony_line_open = false;
    state->cycle_index = 0;
    state->amp_sum = 0.0;
    state->tempo_sum = 0.0;
    state->sample_count = 0;
    state->stream = NULL;
    state->last_harmony = 0.0;
    state->dream_phase = DREAM_COUPLER_PHASE_REST;
    state->next_dream_phase = DREAM_COUPLER_PHASE_REST;
    state->has_dream_preview = false;
    if (g_trs_sync_stream) {
        fclose(g_trs_sync_stream);
        g_trs_sync_stream = NULL;
    }
    g_trs_initialized = false;
}

void introspect_enable(State *state, bool enabled)
{
    if (!state) {
        return;
    }
    state->enabled = enabled;
    if (!enabled) {
        state->harmony_line_open = false;
    }
}

void introspect_enable_harmony(State *state, bool enabled)
{
    if (!state) {
        return;
    }
    state->harmony_enabled = enabled;
    if (!enabled) {
        state->harmony_line_open = false;
        state->last_harmony = 0.0;
    }
}

void introspect_configure_trs(bool enabled, float alpha, int warmup)
{
    g_trs_enabled = enabled;
    g_trs_alpha = clamp_trs_alpha_value(alpha);
    g_trs_warmup_target = clamp_trs_warmup_value(warmup);
    g_trs_initialized = false;
    g_trs_state.alpha = g_trs_alpha;
    g_trs_state.sm_influence = 0.0f;
    g_trs_state.sm_harmony = 0.0f;
    g_trs_state.sm_consent = 0.0f;
    g_trs_state.warmup = g_trs_warmup_target;
    if (!g_trs_enabled && g_trs_sync_stream) {
        fclose(g_trs_sync_stream);
        g_trs_sync_stream = NULL;
    }
}

void introspect_finalize(State *state)
{
    if (!state) {
        return;
    }
    if (state->stream) {
        fclose(state->stream);
        state->stream = NULL;
    }
    state->amp_sum = 0.0;
    state->tempo_sum = 0.0;
    state->sample_count = 0;
    state->harmony_line_open = false;
    state->last_harmony = 0.0;
    state->dream_phase = DREAM_COUPLER_PHASE_REST;
    state->next_dream_phase = DREAM_COUPLER_PHASE_REST;
    state->has_dream_preview = false;
}

void introspect_set_dream_preview(State *state, DreamCouplerPhase phase, bool active)
{
    if (!state) {
        return;
    }
    state->next_dream_phase = phase;
    state->has_dream_preview = active;
    if (!active) {
        state->dream_phase = phase;
    }
}

void introspect_tick(State *state, Metrics *metrics)
{
    if (!state || !metrics || !state->enabled) {
        return;
    }

    if (!state->stream) {
        ensure_logs_directory();
        state->stream = fopen(INTROSPECT_LOG_PATH, "a");
        if (!state->stream) {
            state->enabled = false;
            return;
        }
    }

    state->amp_sum += sanitize_value(metrics->amp);
    state->tempo_sum += sanitize_value(metrics->tempo);
    if (state->sample_count < UINT32_MAX) {
        state->sample_count += 1U;
    }

    if (state->sample_count == 0U) {
        return;
    }

    ++state->cycle_index;
    double avg_amp = state->amp_sum / (double)state->sample_count;
    double avg_tempo = state->tempo_sum / (double)state->sample_count;

    char timestamp[32];
    format_timestamp(timestamp, sizeof(timestamp));

    if (state->has_dream_preview) {
        state->dream_phase = state->next_dream_phase;
        state->has_dream_preview = false;
    } else {
        state->next_dream_phase = state->dream_phase;
    }

    const char *dream_label = dream_coupler_phase_name(state->dream_phase);
    if (!dream_label) {
        dream_label = "REST";
    }

    double consent_raw = sanitize_value(metrics->consent);
    double influence_raw = sanitize_value(metrics->influence);
    double bond_coh = sanitize_value(metrics->bond_coh);
    double err = sanitize_value(metrics->error_margin);

    double harmony_input = sanitize_value(metrics->harmony);
    harmony_input = clamp_unit_value(harmony_input);
    double harmony_raw = harmony_input;
    if (g_trs_enabled) {
        harmony_raw = 0.7 * influence_raw + 0.3 * consent_raw;
        double diff = fabs(avg_amp - avg_tempo);
        if (diff < 0.1 && influence_raw > 0.6) {
            harmony_raw = 1.0;
        }
        harmony_raw = clamp_unit_value(harmony_raw);
    }

    double sm_consent = consent_raw;
    double sm_influence = influence_raw;
    double sm_harmony = harmony_raw;
    double trs_delta = 0.0;

    if (g_trs_enabled) {
        if (!g_trs_initialized) {
            trs_init(&g_trs_state, g_trs_alpha);
            g_trs_state.warmup = g_trs_warmup_target;
            g_trs_initialized = true;
        }
        float out_influence = (float)sm_influence;
        float out_harmony = (float)sm_harmony;
        float out_consent = (float)sm_consent;
        float out_delta = 0.0f;
        trs_step(&g_trs_state,
                 (float)influence_raw,
                 (float)harmony_raw,
                 (float)consent_raw,
                 &out_influence,
                 &out_harmony,
                 &out_consent,
                 &out_delta);
        sm_influence = clamp_unit_value(out_influence);
        sm_harmony = clamp_unit_value(out_harmony);
        sm_consent = clamp_unit_value(out_consent);
        trs_delta = sanitize_value(out_delta);
    }

    sm_consent = clamp_unit_value(sm_consent);
    sm_influence = clamp_unit_value(sm_influence);
    sm_harmony = clamp_unit_value(sm_harmony);

    metrics->influence = (float)sm_influence;
    metrics->consent = (float)sm_consent;
    if (g_trs_enabled) {
        metrics->harmony = (float)sm_harmony;
    } else {
        sm_harmony = harmony_input;
        harmony_raw = harmony_input;
        metrics->harmony = (float)harmony_input;
    }

    if (fprintf(state->stream,
                "{\"timestamp\":\"%s\",\"cycle\":%" PRIu64 ",\"amp\":%.4f,\"tempo\":%.4f,"
                "\"consent\":%.4f,\"influence\":%.4f,\"bond_coh\":%.4f,\"error_margin\":%.4f,"
                "\"harmony\":%.4f,\"dream\":\"%s\",\"inf_raw\":%.4f,\"inf_sm\":%.4f,"
                "\"harm_raw\":%.4f,\"harm_sm\":%.4f,\"cons_raw\":%.4f,\"cons_sm\":%.4f,\"trs_delta\":%.4f}\n",
                timestamp,
                state->cycle_index,
                sanitize_value(avg_amp),
                sanitize_value(avg_tempo),
                sm_consent,
                sm_influence,
                bond_coh,
                err,
                sm_harmony,
                dream_label,
                influence_raw,
                sm_influence,
                harmony_raw,
                sm_harmony,
                consent_raw,
                sm_consent,
                trs_delta) >= 0) {
        fflush(state->stream);
    }

    if (g_trs_enabled && TRS_SYNC_INTERVAL > 0 && (state->cycle_index % TRS_SYNC_INTERVAL) == 0ULL) {
        if (!g_trs_sync_stream) {
            ensure_logs_directory();
            g_trs_sync_stream = fopen("logs/trs_sync_v1.log", "a");
        }
        if (g_trs_sync_stream) {
            if (fprintf(g_trs_sync_stream,
                        "{\"tick\":%" PRIu64 ",\"harm_sm\":%.4f,\"delta\":%.4f}\n",
                        state->cycle_index,
                        sm_harmony,
                        trs_delta) >= 0) {
                fflush(g_trs_sync_stream);
            }
        }
    }

    state->harmony_line_open = false;
    state->last_harmony = sm_harmony;

    state->amp_sum = 0.0;
    state->tempo_sum = 0.0;
    state->sample_count = 0U;
}
