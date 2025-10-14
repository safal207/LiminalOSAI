#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#endif

#include "introspect.h"
#include "dream_coupler.h"
#include "trs_filter.h"
#include "trs_adapt.h"

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
static const float TRS_ADAPT_ALPHA_MIN_DEFAULT = 0.10f;
static const float TRS_ADAPT_ALPHA_MAX_DEFAULT = 0.60f;
static const float TRS_ADAPT_TARGET_DELTA_DEFAULT = 0.015f;
static const float TRS_ADAPT_KP_DEFAULT = 0.4f;
static const float TRS_ADAPT_KI_DEFAULT = 0.05f;
static const float TRS_ADAPT_KD_DEFAULT = 0.1f;

static bool g_trs_enabled = false;
static bool g_trs_initialized = false;
static float g_trs_alpha = TRS_ALPHA_DEFAULT;
static int g_trs_warmup_target = TRS_WARMUP_DEFAULT;
static TRS g_trs_state;
static FILE *g_trs_sync_stream = NULL;
static bool g_trs_adapt_enabled = false;
static float g_trs_alpha_min = TRS_ADAPT_ALPHA_MIN_DEFAULT;
static float g_trs_alpha_max = TRS_ADAPT_ALPHA_MAX_DEFAULT;
static float g_trs_target_delta = TRS_ADAPT_TARGET_DELTA_DEFAULT;
static float g_trs_kp = TRS_ADAPT_KP_DEFAULT;
static float g_trs_ki = TRS_ADAPT_KI_DEFAULT;
static float g_trs_kd = TRS_ADAPT_KD_DEFAULT;
static TRSAdapt g_trs_adapt;
static bool g_trs_adapt_initialized = false;
static FILE *g_trs_adapt_stream = NULL;

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

static float clamp_trs_adapt_alpha_value(float value, float fallback)
{
    if (!isfinite(value)) {
        return fallback;
    }
    if (value < 0.01f) {
        return 0.01f;
    }
    if (value > 0.95f) {
        return 0.95f;
    }
    return value;
}

static float clamp_trs_target_delta_value(float value)
{
    if (!isfinite(value)) {
        return TRS_ADAPT_TARGET_DELTA_DEFAULT;
    }
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 0.5f) {
        return 0.5f;
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
    if (g_trs_adapt_stream) {
        fclose(g_trs_adapt_stream);
        g_trs_adapt_stream = NULL;
    }
    g_trs_initialized = false;
    g_trs_adapt_initialized = false;
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

void introspect_configure_trs(bool enabled,
                              float alpha,
                              int warmup,
                              bool adapt_enabled,
                              float alpha_min,
                              float alpha_max,
                              float target_delta,
                              float k_p,
                              float k_i,
                              float k_d,
                              bool dry_run)
{
    float clamped_alpha = clamp_trs_alpha_value(alpha);
    int clamped_warmup = clamp_trs_warmup_value(warmup);
    float clamped_alpha_min = clamp_trs_adapt_alpha_value(alpha_min, TRS_ADAPT_ALPHA_MIN_DEFAULT);
    float clamped_alpha_max = clamp_trs_adapt_alpha_value(alpha_max, TRS_ADAPT_ALPHA_MAX_DEFAULT);
    if (clamped_alpha_min > clamped_alpha_max) {
        float tmp = clamped_alpha_min;
        clamped_alpha_min = clamped_alpha_max;
        clamped_alpha_max = tmp;
    }
    float clamped_target = clamp_trs_target_delta_value(target_delta);
    float kp_value = isfinite(k_p) ? k_p : TRS_ADAPT_KP_DEFAULT;
    float ki_value = isfinite(k_i) ? k_i : TRS_ADAPT_KI_DEFAULT;
    float kd_value = isfinite(k_d) ? k_d : TRS_ADAPT_KD_DEFAULT;
    bool adapt_active = adapt_enabled && enabled;

    if (dry_run) {
        printf("trs config: enabled=%s alpha=%.3f warmup=%d\n",
               enabled ? "yes" : "no",
               clamped_alpha,
               clamped_warmup);
        printf("trs adapt: enabled=%s alpha-range=[%.3f, %.3f] target-delta=%.4f kp=%.3f ki=%.3f kd=%.3f\n",
               adapt_enabled ? "yes" : "no",
               clamped_alpha_min,
               clamped_alpha_max,
               clamped_target,
               kp_value,
               ki_value,
               kd_value);
        return;
    }

    g_trs_enabled = enabled;
    g_trs_alpha = clamped_alpha;
    g_trs_warmup_target = clamped_warmup;
    g_trs_initialized = false;
    g_trs_state.alpha = g_trs_alpha;
    g_trs_state.sm_influence = 0.0f;
    g_trs_state.sm_harmony = 0.0f;
    g_trs_state.sm_consent = 0.0f;
    g_trs_state.warmup = g_trs_warmup_target;
    g_trs_adapt_enabled = adapt_active;
    g_trs_alpha_min = clamped_alpha_min;
    g_trs_alpha_max = clamped_alpha_max;
    g_trs_target_delta = clamped_target;
    g_trs_kp = kp_value;
    g_trs_ki = ki_value;
    g_trs_kd = kd_value;
    g_trs_adapt_initialized = false;
    if (!g_trs_enabled && g_trs_sync_stream) {
        fclose(g_trs_sync_stream);
        g_trs_sync_stream = NULL;
    }
    if (!g_trs_adapt_enabled && g_trs_adapt_stream) {
        fclose(g_trs_adapt_stream);
        g_trs_adapt_stream = NULL;
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
    if (g_trs_adapt_stream) {
        fclose(g_trs_adapt_stream);
        g_trs_adapt_stream = NULL;
    }
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

    double harmony_raw = 0.7 * influence_raw + 0.3 * consent_raw;
    double diff = fabs(avg_amp - avg_tempo);
    if (diff < 0.1 && influence_raw > 0.6) {
        harmony_raw = 1.0;
    }
    harmony_raw = clamp_unit_value(harmony_raw);

    double sm_consent = consent_raw;
    double sm_influence = influence_raw;
    double sm_harmony = harmony_raw;
    double trs_delta = 0.0;
    double trs_alpha_value = sanitize_value(g_trs_state.alpha);
    double trs_target_value = sanitize_value(g_trs_target_delta);
    double trs_err_value = 0.0;
    bool trs_adapt_active = g_trs_enabled && g_trs_adapt_enabled;

    if (g_trs_enabled) {
        if (!g_trs_initialized) {
            trs_init(&g_trs_state, g_trs_alpha);
            g_trs_state.warmup = g_trs_warmup_target;
            g_trs_initialized = true;
            g_trs_adapt_initialized = false;
        }
        if (trs_adapt_active && !g_trs_adapt_initialized) {
            trs_adapt_init(&g_trs_adapt,
                           g_trs_alpha_min,
                           g_trs_alpha_max,
                           g_trs_target_delta,
                           g_trs_kp,
                           g_trs_ki,
                           g_trs_kd,
                           g_trs_state.alpha);
            g_trs_adapt_initialized = true;
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
        if (trs_adapt_active && g_trs_adapt_initialized) {
            float new_alpha = trs_adapt_update(&g_trs_adapt, (float)trs_delta);
            if (!isfinite(new_alpha)) {
                new_alpha = g_trs_alpha_min;
            }
            g_trs_state.alpha = new_alpha;
            trs_alpha_value = sanitize_value(new_alpha);
            trs_err_value = sanitize_value(g_trs_adapt.last_err);
        } else {
            trs_alpha_value = sanitize_value(g_trs_state.alpha);
            trs_err_value = sanitize_value((float)(trs_delta - g_trs_target_delta));
        }
    } else {
        trs_alpha_value = sanitize_value(g_trs_alpha);
        trs_err_value = 0.0;
    }

    sm_consent = clamp_unit_value(sm_consent);
    sm_influence = clamp_unit_value(sm_influence);
    sm_harmony = clamp_unit_value(sm_harmony);

    metrics->influence = (float)sm_influence;
    metrics->consent = (float)sm_consent;
    metrics->harmony = (float)sm_harmony;

    if (fprintf(state->stream,
                "{\"timestamp\":\"%s\",\"cycle\":%" PRIu64 ",\"amp\":%.4f,\"tempo\":%.4f,"
                "\"consent\":%.4f,\"influence\":%.4f,\"bond_coh\":%.4f,\"error_margin\":%.4f,"
                "\"harmony\":%.4f,\"dream\":\"%s\",\"inf_raw\":%.4f,\"inf_sm\":%.4f,"
                "\"harm_raw\":%.4f,\"harm_sm\":%.4f,\"cons_raw\":%.4f,\"cons_sm\":%.4f,"
                "\"trs_delta\":%.4f,\"trs_alpha\":%.4f,\"trs_target\":%.4f,\"trs_err\":%.4f}\n",
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
                trs_delta,
                trs_alpha_value,
                trs_target_value,
                trs_err_value) >= 0) {
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

    if (trs_adapt_active && TRS_SYNC_INTERVAL > 0 && (state->cycle_index % TRS_SYNC_INTERVAL) == 0ULL) {
        if (!g_trs_adapt_stream) {
            ensure_logs_directory();
            g_trs_adapt_stream = fopen("logs/trs_adapt_v1.log", "a");
        }
        if (g_trs_adapt_stream) {
            if (fprintf(g_trs_adapt_stream,
                        "{\"tick\":%" PRIu64 ",\"alpha\":%.4f,\"delta\":%.4f,\"err\":%.4f,\"kp\":%.3f,\"ki\":%.3f,\"kd\":%.3f}\n",
                        state->cycle_index,
                        trs_alpha_value,
                        trs_delta,
                        trs_err_value,
                        g_trs_kp,
                        g_trs_ki,
                        g_trs_kd) >= 0) {
                fflush(g_trs_adapt_stream);
            }
        }
    }

    state->harmony_line_open = false;
    state->last_harmony = sm_harmony;

    state->amp_sum = 0.0;
    state->tempo_sum = 0.0;
    state->sample_count = 0U;
}
