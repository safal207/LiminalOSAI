#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <limits.h>
#include <float.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <direct.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#endif
#include "empathic.h"
#include "emotion_memory.h"
#include "council.h"
#include "affinity.h"
#include "anticipation_v2.h"
#include "introspect.h"
#include "harmony.h"
#include "dream_coupler.h"
#include "dream_replay.h"
#include "trs_filter.h"
#include "erb.h"
#include "autotune.h"
#include "astro_sync.h"
#include "synaptic_bridge.h"
#include "resonant.h"
#include "kiss.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#ifndef EMOTION_TRACE_PATH_MAX
#define EMOTION_TRACE_PATH_MAX 256
#endif

#define ERB_INDEX_PATH "logs/erb_index.jsonl"
#define TUNE_REPORT_PATH "logs/tune_report.jsonl"
#define TUNE_BEST_PATH "logs/tune_best.json"

#define ASTRO_TRACE_PATH "logs/astro_trace.jsonl"
#define ASTRO_MEMORY_PATH "soil/astro_memory.jsonl"
#define ASTRO_MEMORY_CAPACITY 64
#define ASTRO_STABLE_WINDOW 10
#define DREAM_REPLAY_LOG_PATH "logs/dream_replay.jsonl"
#define BRIDGE_SYNC_LOG_PATH "logs/bridge_sync.jsonl"

typedef struct {
    float breath_rate;
    float breath_position;
    float memory_trace;
    float resonance;
    float sync_quality;
    float vitality;
    float phase_offset;
    uint32_t cycles;
    bool adaptive_profile;
    bool human_affinity_active;
} liminal_state;

typedef struct {
    char type[24];
    float freq;
    float phase;
    char intent[24];
} lip_event;

typedef enum {
    ERB_REPLAY_NONE = 0,
    ERB_REPLAY_LATEST,
    ERB_REPLAY_INDEX,
    ERB_REPLAY_TAG,
    ERB_REPLAY_ALL
} ErbReplayMode;

typedef enum {
    TUNE_SOURCE_NONE = 0,
    TUNE_SOURCE_LATEST,
    TUNE_SOURCE_INDEX,
    TUNE_SOURCE_TAG,
    TUNE_SOURCE_ALL
} TuneSourceMode;

typedef struct {
    bool run_substrate;
    bool adaptive;
    bool trace;
    bool human_bridge;
    uint16_t lip_port;
    bool lip_test;
    bool lip_trace;
    unsigned int lip_interval_ms;
    char lip_host[128];
    bool empathic_enabled;
    bool empathic_trace;
    bool anticipation_trace;
    bool anticipation2_enabled;
    bool ant2_trace;
    float ant2_gain;
    EmpathicSource emotional_source;
    float empathy_gain;
    bool emotional_memory_enabled;
    bool memory_trace;
    float recognition_threshold;
    char emotion_trace_path[EMOTION_TRACE_PATH_MAX];
    unsigned int cycle_limit;
    bool affinity_enabled;
    bool bond_trace;
    Affinity affinity_config;
    float allow_align_consent;
    float mirror_amp_min;
    float mirror_amp_max;
    float mirror_tempo_min;
    float mirror_tempo_max;
    bool strict_order;
    bool dry_run;
    bool introspect_enabled;
    bool harmony_enabled;
    bool dream_enabled;
    bool dream_replay_enabled;
    bool astro_enabled;
    bool astro_trace;
    float astro_rate;
    float astro_tone_init;
    float astro_memory_init;
    bool astro_tone_set;
    bool astro_memory_set;
    int dream_replay_cycles;
    float dream_replay_rate;
    float dream_replay_decay;
    bool dream_replay_trace;
    bool bridge_enabled;
    float bridge_plasticity;
    float bridge_retention;
    float bridge_recovery;
    bool trs_enabled;
    float trs_alpha;
    int trs_warmup;
    bool trs_adapt_enabled;
    float trs_alpha_min;
    float trs_alpha_max;
    float trs_target_delta;
    float trs_kp;
    float trs_ki;
    float trs_kd;
    bool kiss_enabled;
    float kiss_trust_threshold;
    float kiss_presence_threshold;
    float kiss_harmony_threshold;
    int kiss_warmup_cycles;
    int kiss_refractory_cycles;
    float kiss_alpha;
    bool erb_enabled;
    int erb_pre;
    int erb_post;
    float erb_spike;
    ErbReplayMode erb_replay_mode;
    uint32_t erb_replay_idx;
    uint32_t erb_replay_tag_mask;
    float erb_replay_speed;
    bool tune_enabled;
    bool tune_apply;
    bool tune_report;
    int tune_trials;
    int tune_refine;
    int tune_max_runs;
    float tune_alpha_min;
    float tune_alpha_max;
    int tune_warm_min;
    int tune_warm_max;
    float tune_align_min;
    float tune_align_max;
    char tune_save_path[256];
    char tune_load_path[256];
    int tune_seed;
    int tune_select_n;
    TuneSourceMode tune_source_mode;
    uint32_t tune_source_idx;
    uint32_t tune_source_mask;
} substrate_config;

static bool substrate_affinity_enabled = false;
static Affinity substrate_affinity_profile = {0.0f, 0.0f, 0.0f};
static BondGate substrate_bond_gate = {0.0f, 0.0f, 0.0f, 0.0f};
static float substrate_explicit_consent = 0.2f;
static bool substrate_ant2_enabled = false;
static Ant2 substrate_ant2_state;
static const float SUBSTRATE_BASE_RATE = 0.72f;
static Astro substrate_astro;
static bool substrate_astro_enabled = false;
static bool substrate_astro_trace_enabled = false;
static bool substrate_kiss_enabled = false;
static FILE *substrate_astro_trace_stream = NULL;
static float substrate_astro_feedback = 1.0f;
static AstroMemory substrate_astro_cache[ASTRO_MEMORY_CAPACITY];
static size_t substrate_astro_count = 0;
static bool substrate_dream_replay_enabled = false;
static bool substrate_dream_replay_trace = false;
static DreamReplay substrate_dream_replay;
static FILE *substrate_dream_replay_stream = NULL;
static float substrate_dream_feedback = 1.0f;
static bool substrate_bridge_enabled = false;
static bool substrate_bridge_trace = false;
static SynapticBridge substrate_bridge;
static FILE *substrate_bridge_stream = NULL;
typedef struct {
    int consecutive;
    float tone_sum;
    float memory_sum;
    float stability_sum;
} AstroStableWindow;
static AstroStableWindow substrate_astro_window = {0, 0.0f, 0.0f, 0.0f};
typedef struct {
    uint32_t id;
    uint32_t tag_mask;
    int len;
    float delta_max;
    float alpha_mean;
} ErbIndexRecord;

#define ERB_MAX_INDEX_RECORDS 512
static const float MIRROR_GAIN_AMP_MIN_DEFAULT = 0.5f;
static const float MIRROR_GAIN_AMP_MAX_DEFAULT = 1.2f;
static const float MIRROR_GAIN_TEMPO_MIN_DEFAULT = 0.8f;
static const float MIRROR_GAIN_TEMPO_MAX_DEFAULT = 1.2f;
static State substrate_introspect_state;
static bool g_tune_profile_loaded = false;
static TuneConfig g_tune_profile;
static TuneResult g_tune_last_result;
static TuneResult g_tune_ranked_cache[8];
static size_t g_tune_ranked_count = 0;

static float sanitize_positive(float value, float fallback)
{
    if (!isfinite(value) || value <= 0.0f) {
        return fallback;
    }
    return value;
}

static void normalize_bounds(float *min_value, float *max_value, float default_min, float default_max)
{
    if (!min_value || !max_value) {
        return;
    }
    float min_sanitized = sanitize_positive(*min_value, default_min);
    float max_sanitized = sanitize_positive(*max_value, default_max);
    if (min_sanitized > max_sanitized) {
        float tmp = min_sanitized;
        min_sanitized = max_sanitized;
        max_sanitized = tmp;
    }
    *min_value = min_sanitized;
    *max_value = max_sanitized;
}

static size_t build_exhale_sequence(const substrate_config *cfg, const char **steps, size_t capacity)
{
    if (!cfg || !steps || capacity == 0) {
        return 0;
    }

    bool strict = cfg->strict_order;
    size_t count = 0;
    bool include_ant2 = strict || cfg->anticipation2_enabled;
    bool include_collective = strict;
    bool include_affinity = strict || cfg->affinity_enabled;
    bool include_mirror = strict;
    bool include_introspect = strict || cfg->introspect_enabled;
    bool include_harmony = strict || include_introspect || cfg->harmony_enabled || cfg->dream_enabled;
    bool include_astro = strict || cfg->astro_enabled;
    bool include_dream = cfg->dream_enabled;

    if (include_ant2 && count < capacity) {
        steps[count++] = "ant2";
    }
    if (count < capacity) {
        steps[count++] = "awareness";
    }
    if (include_collective && count < capacity) {
        steps[count++] = "collective";
    }
    if (include_affinity && count < capacity) {
        steps[count++] = "affinity";
    }
    if (include_mirror && count < capacity) {
        steps[count++] = "mirror";
    }
    if (include_introspect && count < capacity) {
        steps[count++] = "introspect";
    }
    if (include_harmony && count < capacity) {
        steps[count++] = "harmony";
    }
    if (include_astro && count < capacity) {
        steps[count++] = "astro";
    }
    if (include_dream && count < capacity) {
        steps[count++] = "dream";
    }

    return count;
}

static bool parse_float_range(const char *spec, float *out_min, float *out_max)
{
    if (!spec || !out_min || !out_max) {
        return false;
    }
    char *end = NULL;
    float min_value = strtof(spec, &end);
    if (end == spec || *end != ':') {
        return false;
    }
    const char *max_part = end + 1;
    float max_value = strtof(max_part, &end);
    if (end == max_part) {
        return false;
    }
    if (!isfinite(min_value) || !isfinite(max_value)) {
        return false;
    }
    *out_min = min_value;
    *out_max = max_value;
    return true;
}

static bool parse_int_range(const char *spec, int *out_min, int *out_max)
{
    if (!spec || !out_min || !out_max) {
        return false;
    }
    char *end = NULL;
    long min_value = strtol(spec, &end, 10);
    if (end == spec || *end != ':') {
        return false;
    }
    const char *max_part = end + 1;
    long max_value = strtol(max_part, &end, 10);
    if (end == max_part) {
        return false;
    }
    *out_min = (int)min_value;
    *out_max = (int)max_value;
    return true;
}

static void parse_kiss_thresholds(substrate_config *cfg, const char *value)
{
    if (!cfg || !value) {
        return;
    }

    char buffer[128];
    strncpy(buffer, value, sizeof(buffer) - 1U);
    buffer[sizeof(buffer) - 1U] = '\0';

    char *token = strtok(buffer, ",");
    while (token) {
        while (*token && isspace((unsigned char)*token)) {
            ++token;
        }
        char *colon = strchr(token, ':');
        if (colon && colon[1] != '\0') {
            *colon = '\0';
            const char *name = token;
            const char *val_text = colon + 1;
            while (*val_text && isspace((unsigned char)*val_text)) {
                ++val_text;
            }
            char *end = NULL;
            float parsed = strtof(val_text, &end);
            if (end != val_text && isfinite(parsed)) {
                if (parsed < 0.0f) {
                    parsed = 0.0f;
                } else if (parsed > 1.0f) {
                    parsed = 1.0f;
                }
                if (strcmp(name, "trust") == 0 || strcmp(name, "tr") == 0) {
                    cfg->kiss_trust_threshold = parsed;
                } else if (strcmp(name, "pres") == 0 || strcmp(name, "presence") == 0) {
                    cfg->kiss_presence_threshold = parsed;
                } else if (strcmp(name, "harm") == 0 || strcmp(name, "harmony") == 0) {
                    cfg->kiss_harmony_threshold = parsed;
                }
            }
        }
        token = strtok(NULL, ",");
    }
}

static bool extract_profile_float(const char *json, const char *field, float *out)
{
    if (!json || !field || !out) {
        return false;
    }
    char pattern[32];
    int written = snprintf(pattern, sizeof(pattern), "\"%s\"", field);
    if (written <= 0 || written >= (int)sizeof(pattern)) {
        return false;
    }
    const char *pos = strstr(json, pattern);
    if (!pos) {
        return false;
    }
    pos += (size_t)written;
    while (*pos == ' ' || *pos == '\t' || *pos == ':' ) {
        ++pos;
    }
    if (*pos == '\0') {
        return false;
    }
    char *end = NULL;
    float value = strtof(pos, &end);
    if (end == pos) {
        return false;
    }
    *out = value;
    return true;
}

static bool extract_profile_int(const char *json, const char *field, int *out)
{
    if (!json || !field || !out) {
        return false;
    }
    char pattern[32];
    int written = snprintf(pattern, sizeof(pattern), "\"%s\"", field);
    if (written <= 0 || written >= (int)sizeof(pattern)) {
        return false;
    }
    const char *pos = strstr(json, pattern);
    if (!pos) {
        return false;
    }
    pos += (size_t)written;
    while (*pos == ' ' || *pos == '\t' || *pos == ':' ) {
        ++pos;
    }
    if (*pos == '\0') {
        return false;
    }
    char *end = NULL;
    long value = strtol(pos, &end, 10);
    if (end == pos) {
        return false;
    }
    *out = (int)value;
    return true;
}

static void format_exhale_sequence(const substrate_config *cfg, char *buffer, size_t size)
{
    if (!buffer || size == 0) {
        return;
    }

    buffer[0] = '\0';
    const char *steps[8];
    size_t count = build_exhale_sequence(cfg, steps, sizeof(steps) / sizeof(steps[0]));
    if (count == 0) {
        return;
    }

    const char *arrow = "\xE2\x86\x92";
    size_t written = 0;
    for (size_t i = 0; i < count; ++i) {
        int result = 0;
        if (i == 0) {
            result = snprintf(buffer + written, size - written, "%s", steps[i]);
        } else {
            result = snprintf(buffer + written, size - written, "%s%s", arrow, steps[i]);
        }
        if (result < 0) {
            buffer[written] = '\0';
            return;
        }
        written += (size_t)result;
        if (written >= size) {
            buffer[size - 1] = '\0';
            return;
        }
    }
}

static void rebirth(liminal_state *state)
{
    state->breath_rate = 0.72f;
    state->breath_position = 0.0f;
    state->memory_trace = 0.0f;
    state->resonance = 0.50f;
    state->sync_quality = 0.50f;
    state->vitality = 0.60f;
    state->phase_offset = 0.0f;
    state->cycles = 0U;
    state->adaptive_profile = false;
    state->human_affinity_active = false;
}

static float clamp_unit(float value)
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

static void parse_affinity_config(Affinity *aff, const char *value)
{
    if (!aff || !value) {
        return;
    }

    char buffer[128];
    strncpy(buffer, value, sizeof(buffer) - 1U);
    buffer[sizeof(buffer) - 1U] = '\0';

    char *token = strtok(buffer, ",");
    while (token) {
        while (*token == ' ') {
            ++token;
        }
        char *colon = strchr(token, ':');
        if (colon && colon[1] != '\0') {
            *colon = '\0';
            const char *name = token;
            const char *val_text = colon + 1;
            char *end = NULL;
            float parsed = strtof(val_text, &end);
            if (end != val_text && isfinite(parsed)) {
                float clamped = clamp_unit(parsed);
                if (strcmp(name, "care") == 0) {
                    aff->care = clamped;
                } else if (strcmp(name, "respect") == 0) {
                    aff->respect = clamped;
                } else if (strcmp(name, "presence") == 0) {
                    aff->presence = clamped;
                }
            }
        }
        token = strtok(NULL, ",");
    }
}

static void remember(liminal_state *state, float imprint)
{
    const float blend = 0.18f;
    state->memory_trace = state->memory_trace * (1.0f - blend) + imprint * blend;
    if (state->memory_trace > 1.0f) {
        state->memory_trace = 1.0f;
    } else if (state->memory_trace < -1.0f) {
        state->memory_trace = -1.0f;
    }
}

static void rest(liminal_state *state)
{
    state->vitality += 0.02f;
    if (state->vitality > 1.0f) {
        state->vitality = 1.0f;
    }
    state->breath_rate *= 0.995f;
    if (state->breath_rate < 0.20f) {
        state->breath_rate = 0.20f;
    }
}

static void reflect(liminal_state *state)
{
    state->resonance = 0.6f * state->resonance + 0.4f * state->memory_trace;
    if (state->resonance < 0.0f) {
        state->resonance = 0.0f;
    } else if (state->resonance > 1.0f) {
        state->resonance = 1.0f;
    }
}

static void pulse(liminal_state *state, float delta)
{
    state->breath_position += state->breath_rate * delta;
    if (state->breath_position >= 1.0f) {
        state->breath_position -= (float)floor(state->breath_position);
        state->cycles += 1U;
    }
    state->sync_quality = 0.70f * state->sync_quality + 0.30f * (1.0f - fabsf(0.5f - state->breath_position));
}

static lip_event resonance_event(float freq, float phase, const char *intent)
{
    lip_event ev;
    memset(&ev, 0, sizeof(ev));
    strncpy(ev.type, "resonance", sizeof(ev.type) - 1U);
    ev.freq = freq;
    ev.phase = phase;
    strncpy(ev.intent, intent, sizeof(ev.intent) - 1U);
    return ev;
}

static void emit_lip_event(const lip_event *event)
{
    printf("{ \"type\": \"%s\", \"freq\": %.3f, \"phase\": %.3f, \"intent\": \"%s\" }\n",
           event->type,
           event->freq,
           event->phase,
           event->intent);
}

static void auto_adapt(liminal_state *state, bool trace)
{
#ifdef __unix__
    long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    long page_size = sysconf(_SC_PAGESIZE);
    long phys_pages = sysconf(_SC_PHYS_PAGES);
    if (cpu_count < 1) {
        cpu_count = 1;
    }
    float cpu_factor = (float)cpu_count;
    float ram_mb = 0.0f;
    if (page_size > 0 && phys_pages > 0) {
        ram_mb = (float)(phys_pages) * (float)page_size / (1024.0f * 1024.0f);
    }
    float ram_factor = ram_mb > 0.0f ? fminf(ram_mb / 512.0f, 4.0f) : 1.0f;
#else
    float cpu_factor = 1.0f;
    float ram_factor = 1.0f;
#endif
    state->breath_rate = 0.40f + 0.05f * cpu_factor;
    state->memory_trace = fminf(0.10f * ram_factor, 0.8f);
    state->adaptive_profile = true;
    if (trace) {
        printf("[auto-adapt] cpu_factor=%.2f ram_factor=%.2f breath_rate=%.2f memory=%.2f\n",
               cpu_factor,
               ram_factor,
               state->breath_rate,
               state->memory_trace);
    }
}

static void human_affinity_bridge(liminal_state *state, bool trace)
{
    const char *heart_env = getenv("LIMINAL_HEART_RATE");
    float heart_rate = 68.0f;
    if (heart_env && *heart_env) {
        heart_rate = strtof(heart_env, NULL);
    }
    float normalized = heart_rate / 100.0f;
    if (normalized < 0.2f) {
        normalized = 0.2f;
    } else if (normalized > 2.4f) {
        normalized = 2.4f;
    }
    state->breath_rate = 0.5f * state->breath_rate + 0.5f * normalized;
    state->phase_offset = fmodf(state->phase_offset + normalized * 0.1f, 1.0f);
    state->human_affinity_active = true;
    if (trace) {
        printf("[human-bridge] heart=%.2f normalized=%.2f new_breath=%.2f\n",
               heart_rate,
               normalized,
               state->breath_rate);
    }
}

static void substrate_astro_window_reset(void)
{
    substrate_astro_window.consecutive = 0;
    substrate_astro_window.tone_sum = 0.0f;
    substrate_astro_window.memory_sum = 0.0f;
    substrate_astro_window.stability_sum = 0.0f;
}

static void substrate_astro_window_accumulate(float tone, float memory, float stability)
{
    substrate_astro_window.consecutive += 1;
    substrate_astro_window.tone_sum += tone;
    substrate_astro_window.memory_sum += memory;
    substrate_astro_window.stability_sum += stability;
}

static void substrate_astro_trace_close(void)
{
    if (substrate_astro_trace_stream) {
        fclose(substrate_astro_trace_stream);
        substrate_astro_trace_stream = NULL;
    }
}

static void substrate_astro_trace_log(float stability, float gain)
{
    if (!substrate_astro_trace_enabled) {
        return;
    }
    if (!substrate_astro_trace_stream) {
        substrate_astro_trace_stream = fopen(ASTRO_TRACE_PATH, "a");
        if (!substrate_astro_trace_stream) {
            substrate_astro_trace_enabled = false;
            return;
        }
    }
    fprintf(substrate_astro_trace_stream,
            "{\"tone\":%.4f,\"memory\":%.4f,\"drift\":%.4f,\"ca_rate\":%.5f,\"ca_phase\":%.4f,"
            "\"stability\":%.4f,\"agitation\":%.4f,\"astro_gain\":%.4f}\n",
            substrate_astro.tone,
            substrate_astro.memory,
            substrate_astro.drift,
            substrate_astro.ca_rate,
            substrate_astro.ca_phase,
            stability,
            substrate_astro.last_agitation,
            gain);
    fflush(substrate_astro_trace_stream);
}

static void substrate_astro_trace_log_consolidate(float tone_avg,
                                                  float memory_avg,
                                                  float stability_avg)
{
    if (!substrate_astro_trace_enabled) {
        return;
    }
    if (!substrate_astro_trace_stream) {
        substrate_astro_trace_stream = fopen(ASTRO_TRACE_PATH, "a");
        if (!substrate_astro_trace_stream) {
            substrate_astro_trace_enabled = false;
            return;
        }
    }
    fprintf(substrate_astro_trace_stream,
            "{\"consolidate\":true,\"tone_avg\":%.4f,\"mem_avg\":%.4f,\"ca_rate\":%.5f,"
            "\"stability_avg\":%.4f,\"signature\":0,\"saved\":\"%s\"}\n",
            tone_avg,
            memory_avg,
            substrate_astro.ca_rate,
            stability_avg,
            ASTRO_MEMORY_PATH);
    fflush(substrate_astro_trace_stream);
}

static void substrate_dream_replay_trace_close(void)
{
    if (substrate_dream_replay_stream) {
        fclose(substrate_dream_replay_stream);
        substrate_dream_replay_stream = NULL;
    }
}

static void substrate_dream_replay_trace_log(uint32_t cycle, const DreamReplay *replay)
{
    if (!substrate_dream_replay_trace || !replay) {
        return;
    }
    if (!substrate_dream_replay_stream) {
        ensure_logs_directory_path();
        substrate_dream_replay_stream = fopen(DREAM_REPLAY_LOG_PATH, "a");
        if (!substrate_dream_replay_stream) {
            substrate_dream_replay_trace = false;
            return;
        }
    }
    float rem_wave = 0.5f + 0.5f * sinf(2.0f * (float)M_PI * replay->rem);
    float feedback = dream_feedback(replay);
    fprintf(substrate_dream_replay_stream,
            "{\"cycle\":%u,\"rem_phase\":%.4f,\"rem_wave\":%.4f,\"blend\":%.4f,\"memory_after\":%.4f,\"gain\":%.4f}\n",
            cycle,
            replay->rem,
            rem_wave,
            replay->blend_factor,
            replay->memory_after,
            feedback);
    fflush(substrate_dream_replay_stream);
}

static void substrate_bridge_trace_close(void)
{
    if (substrate_bridge_stream) {
        fclose(substrate_bridge_stream);
        substrate_bridge_stream = NULL;
    }
}

static float substrate_bridge_preview_gain(const SynapticBridge *bridge, const DreamReplay *replay)
{
    if (!bridge || !replay) {
        return 0.0f;
    }

    float blend = clamp_unit(replay->blend_factor);
    float fatigue_delta = 0.1f * (1.0f - blend);
    float fatigue_before = clamp_unit(bridge->fatigue + fatigue_delta);
    float retention = clamp_unit(bridge->retention);
    float memory_after = clamp_unit(replay->memory_after);
    return memory_after * retention * (1.0f - fatigue_before);
}

static void substrate_bridge_trace_log(uint32_t cycle,
                                       float gain,
                                       const SynapticBridge *bridge)
{
    if (!substrate_bridge_trace || !bridge) {
        return;
    }
    if (!substrate_bridge_stream) {
        substrate_bridge_stream = fopen(BRIDGE_SYNC_LOG_PATH, "a");
        if (!substrate_bridge_stream) {
            substrate_bridge_trace = false;
            return;
        }
    }

    float fatigue = clamp_unit(bridge->fatigue);
    float stability = bridge_stability(bridge);
    fprintf(substrate_bridge_stream,
            "{\"cycle\":%u,\"gain\":%.4f,\"fatigue\":%.4f,\"stability\":%.4f}\n",
            cycle,
            gain,
            fatigue,
            stability);
    fflush(substrate_bridge_stream);
}

static void substrate_astro_memory_load(void)
{
    substrate_astro_count = astro_memory_load(ASTRO_MEMORY_PATH, substrate_astro_cache, ASTRO_MEMORY_CAPACITY);
    if (substrate_astro_count > ASTRO_MEMORY_CAPACITY) {
        substrate_astro_count = ASTRO_MEMORY_CAPACITY;
    }
}

static void substrate_astro_memory_store(float tone_avg, float memory_avg, float stability_avg)
{
    uint64_t now = (uint64_t)time(NULL);
    AstroMemory snapshot = astro_memory_make(0U, tone_avg, memory_avg, substrate_astro.ca_rate, stability_avg, now);
    if (astro_memory_append(ASTRO_MEMORY_PATH, &snapshot)) {
        if (substrate_astro_count < ASTRO_MEMORY_CAPACITY) {
            substrate_astro_cache[substrate_astro_count++] = snapshot;
        } else if (substrate_astro_count > 0) {
            substrate_astro_cache[substrate_astro_count - 1] = snapshot;
        }
        substrate_astro_trace_log_consolidate(tone_avg, memory_avg, stability_avg);
    }
}

static void substrate_astro_apply_profile(bool tone_locked, bool memory_locked)
{
    if (substrate_astro_count == 0) {
        return;
    }
    const AstroMemory *profile = NULL;
    for (size_t i = 0; i < substrate_astro_count; ++i) {
        if (substrate_astro_cache[i].signature == 0U) {
            profile = &substrate_astro_cache[i];
            break;
        }
    }
    if (!profile) {
        profile = &substrate_astro_cache[0];
    }
    if (profile) {
        if (!tone_locked) {
            astro_set_tone(&substrate_astro, profile->tone_avg);
        }
        if (!memory_locked) {
            astro_set_memory(&substrate_astro, profile->memory_avg);
        }
        astro_set_ca_rate(&substrate_astro, profile->ca_rate);
    }
}

static substrate_config parse_args(int argc, char **argv)
{
    substrate_config cfg;
    cfg.run_substrate = false;
    cfg.adaptive = false;
    cfg.trace = false;
    cfg.human_bridge = false;
    cfg.lip_port = 0U;
    cfg.lip_test = false;
    cfg.lip_trace = false;
    cfg.lip_interval_ms = 1000U;
    cfg.lip_host[0] = '\0';
    cfg.empathic_enabled = false;
    cfg.empathic_trace = false;
    cfg.anticipation_trace = false;
    cfg.anticipation2_enabled = false;
    cfg.ant2_trace = false;
    cfg.ant2_gain = 0.6f;
    cfg.emotional_source = EMPATHIC_SOURCE_AUDIO;
    cfg.empathy_gain = 1.0f;
    cfg.emotional_memory_enabled = false;
    cfg.memory_trace = false;
    cfg.recognition_threshold = 0.18f;
    cfg.emotion_trace_path[0] = '\0';
    cfg.cycle_limit = 6U;
    cfg.affinity_enabled = false;
    cfg.bond_trace = false;
    affinity_default(&cfg.affinity_config);
    cfg.allow_align_consent = 0.2f;
    cfg.mirror_amp_min = MIRROR_GAIN_AMP_MIN_DEFAULT;
    cfg.mirror_amp_max = MIRROR_GAIN_AMP_MAX_DEFAULT;
    cfg.mirror_tempo_min = MIRROR_GAIN_TEMPO_MIN_DEFAULT;
    cfg.mirror_tempo_max = MIRROR_GAIN_TEMPO_MAX_DEFAULT;
    cfg.strict_order = false;
    cfg.dry_run = false;
    cfg.introspect_enabled = false;
    cfg.harmony_enabled = false;
    cfg.dream_enabled = false;
    cfg.dream_replay_enabled = false;
    cfg.astro_enabled = false;
    cfg.astro_trace = false;
    cfg.astro_rate = 0.010f;
    cfg.astro_tone_init = 0.0f;
    cfg.astro_memory_init = 0.0f;
    cfg.astro_tone_set = false;
    cfg.astro_memory_set = false;
    cfg.dream_replay_cycles = 16;
    cfg.dream_replay_rate = 0.2f;
    cfg.dream_replay_decay = 0.01f;
    cfg.dream_replay_trace = false;
    cfg.bridge_enabled = false;
    cfg.bridge_plasticity = 0.65f;
    cfg.bridge_retention = 0.75f;
    cfg.bridge_recovery = 0.03f;
    cfg.trs_enabled = false;
    cfg.trs_alpha = 0.3f;
    cfg.trs_warmup = 5;
    cfg.trs_adapt_enabled = false;
    cfg.trs_alpha_min = 0.10f;
    cfg.trs_alpha_max = 0.60f;
    cfg.trs_target_delta = 0.015f;
    cfg.trs_kp = 0.4f;
    cfg.trs_ki = 0.05f;
    cfg.trs_kd = 0.1f;
    cfg.kiss_enabled = false;
    cfg.kiss_trust_threshold = 0.80f;
    cfg.kiss_presence_threshold = 0.70f;
    cfg.kiss_harmony_threshold = 0.85f;
    cfg.kiss_warmup_cycles = 10;
    cfg.kiss_refractory_cycles = 5;
    cfg.kiss_alpha = 0.25f;
    cfg.erb_enabled = false;
    cfg.erb_pre = 24;
    cfg.erb_post = 32;
    cfg.erb_spike = 0.06f;
    cfg.erb_replay_mode = ERB_REPLAY_NONE;
    cfg.erb_replay_idx = 0U;
    cfg.erb_replay_tag_mask = 0U;
    cfg.erb_replay_speed = 1.0f;
    cfg.tune_enabled = false;
    cfg.tune_apply = false;
    cfg.tune_report = false;
    cfg.tune_trials = 60;
    cfg.tune_refine = 10;
    cfg.tune_max_runs = 200;
    cfg.tune_alpha_min = 0.1f;
    cfg.tune_alpha_max = 0.6f;
    cfg.tune_warm_min = 0;
    cfg.tune_warm_max = 6;
    cfg.tune_align_min = 0.4f;
    cfg.tune_align_max = 0.8f;
    cfg.tune_save_path[0] = '\0';
    cfg.tune_load_path[0] = '\0';
    cfg.tune_seed = 42;
    cfg.tune_select_n = 0;
    cfg.tune_source_mode = TUNE_SOURCE_LATEST;
    cfg.tune_source_idx = 0U;
    cfg.tune_source_mask = 0U;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "--substrate") == 0) {
            cfg.run_substrate = true;
        } else if (strcmp(arg, "--adaptive") == 0) {
            cfg.adaptive = true;
        } else if (strcmp(arg, "--trace") == 0) {
            cfg.trace = true;
        } else if (strncmp(arg, "--lip-port=", 11) == 0) {
            const char *value = arg + 11;
            unsigned long parsed = strtoul(value, NULL, 10);
            if (parsed <= UINT16_MAX) {
                cfg.lip_port = (uint16_t)parsed;
            }
        } else if (strcmp(arg, "--lip-test") == 0) {
            cfg.lip_test = true;
        } else if (strcmp(arg, "--lip-trace") == 0) {
            cfg.lip_trace = true;
        } else if (strncmp(arg, "--lip-interval=", 15) == 0) {
            const char *value = arg + 15;
            unsigned long parsed = strtoul(value, NULL, 10);
            if (parsed > 0UL && parsed <= 60000UL) {
                cfg.lip_interval_ms = (unsigned int)parsed;
            }
        } else if (strncmp(arg, "--lip-host=", 11) == 0) {
            const char *value = arg + 11;
            if (value && *value) {
                strncpy(cfg.lip_host, value, sizeof(cfg.lip_host) - 1U);
                cfg.lip_host[sizeof(cfg.lip_host) - 1U] = '\0';
            }
        } else if (strcmp(arg, "--erb") == 0) {
            cfg.erb_enabled = true;
        } else if (strncmp(arg, "--erb-pre=", 10) == 0) {
            const char *value = arg + 10;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value) {
                    if (parsed < 0L) {
                        parsed = 0L;
                    } else if (parsed > (long)(ERB_MAX_LEN - 1)) {
                        parsed = (long)(ERB_MAX_LEN - 1);
                    }
                    cfg.erb_pre = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--erb-post=", 11) == 0) {
            const char *value = arg + 11;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value) {
                    if (parsed < 0L) {
                        parsed = 0L;
                    } else if (parsed > (long)(ERB_MAX_LEN - 1)) {
                        parsed = (long)(ERB_MAX_LEN - 1);
                    }
                    cfg.erb_post = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--erb-spike=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed) && parsed >= 0.0f) {
                    cfg.erb_spike = parsed;
                }
            }
        } else if (strncmp(arg, "--erb-replay=", 13) == 0) {
            const char *value = arg + 13;
            if (value && *value) {
                if (strcmp(value, "latest") == 0 || strcmp(value, "LATEST") == 0) {
                    cfg.erb_replay_mode = ERB_REPLAY_LATEST;
                } else if (strcmp(value, "ALL") == 0 || strcmp(value, "all") == 0) {
                    cfg.erb_replay_mode = ERB_REPLAY_ALL;
                } else if (strncmp(value, "idx:", 4) == 0) {
                    const char *idx_value = value + 4;
                    char *end = NULL;
                    unsigned long parsed = strtoul(idx_value, &end, 10);
                    if (end != idx_value) {
                        cfg.erb_replay_mode = ERB_REPLAY_INDEX;
                        cfg.erb_replay_idx = (uint32_t)parsed;
                    }
                } else if (strncmp(value, "tag:", 4) == 0) {
                    const char *tag_spec = value + 4;
                    uint32_t mask = erb_parse_tag_mask(tag_spec);
                    if (mask != 0U) {
                        cfg.erb_replay_mode = ERB_REPLAY_TAG;
                        cfg.erb_replay_tag_mask = mask;
                    }
                }
            }
        } else if (strncmp(arg, "--erb-replay-speed=", 20) == 0) {
            const char *value = arg + 20;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed) && parsed > 0.0f) {
                    cfg.erb_replay_speed = parsed;
                }
            }
        } else if (strcmp(arg, "--tune") == 0) {
            cfg.tune_enabled = true;
        } else if (strncmp(arg, "--tune-source=", 14) == 0) {
            const char *value = arg + 14;
            if (value && *value) {
                cfg.tune_enabled = true;
                if (strcmp(value, "latest") == 0 || strcmp(value, "LATEST") == 0) {
                    cfg.tune_source_mode = TUNE_SOURCE_LATEST;
                } else if (strcmp(value, "ALL") == 0 || strcmp(value, "all") == 0) {
                    cfg.tune_source_mode = TUNE_SOURCE_ALL;
                } else if (strncmp(value, "idx:", 4) == 0) {
                    const char *idx_value = value + 4;
                    char *end = NULL;
                    unsigned long parsed = strtoul(idx_value, &end, 10);
                    if (end != idx_value) {
                        cfg.tune_source_mode = TUNE_SOURCE_INDEX;
                        cfg.tune_source_idx = (uint32_t)parsed;
                    }
                } else if (strncmp(value, "tag:", 4) == 0) {
                    const char *tag_spec = value + 4;
                    uint32_t mask = erb_parse_tag_mask(tag_spec);
                    if (mask != 0U) {
                        cfg.tune_source_mode = TUNE_SOURCE_TAG;
                        cfg.tune_source_mask = mask;
                    }
                }
            }
        } else if (strncmp(arg, "--tune-trials=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed > 0L) {
                    if (parsed > INT_MAX) {
                        parsed = INT_MAX;
                    }
                    cfg.tune_trials = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--tune-refine=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed >= 0L) {
                    if (parsed > INT_MAX) {
                        parsed = INT_MAX;
                    }
                    cfg.tune_refine = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--tune-max-runs=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed > 0L) {
                    if (parsed > INT_MAX) {
                        parsed = INT_MAX;
                    }
                    cfg.tune_max_runs = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--tune-alpha=", 13) == 0) {
            const char *value = arg + 13;
            float min_v = 0.0f;
            float max_v = 0.0f;
            if (parse_float_range(value, &min_v, &max_v)) {
                cfg.tune_alpha_min = min_v;
                cfg.tune_alpha_max = max_v;
            }
        } else if (strncmp(arg, "--tune-warm=", 12) == 0) {
            const char *value = arg + 12;
            int min_v = 0;
            int max_v = 0;
            if (parse_int_range(value, &min_v, &max_v)) {
                if (min_v < 0) {
                    min_v = 0;
                }
                if (max_v > 10) {
                    max_v = 10;
                }
                cfg.tune_warm_min = min_v;
                cfg.tune_warm_max = max_v;
            }
        } else if (strncmp(arg, "--tune-align=", 13) == 0) {
            const char *value = arg + 13;
            float min_v = 0.0f;
            float max_v = 0.0f;
            if (parse_float_range(value, &min_v, &max_v)) {
                cfg.tune_align_min = min_v;
                cfg.tune_align_max = max_v;
            }
        } else if (strncmp(arg, "--tune-save=", 12) == 0) {
            const char *value = arg + 12;
            if (value && *value) {
                strncpy(cfg.tune_save_path, value, sizeof(cfg.tune_save_path) - 1U);
                cfg.tune_save_path[sizeof(cfg.tune_save_path) - 1U] = '\0';
            }
        } else if (strncmp(arg, "--tune-load=", 12) == 0) {
            const char *value = arg + 12;
            if (value && *value) {
                strncpy(cfg.tune_load_path, value, sizeof(cfg.tune_load_path) - 1U);
                cfg.tune_load_path[sizeof(cfg.tune_load_path) - 1U] = '\0';
            }
        } else if (strcmp(arg, "--tune-apply") == 0) {
            cfg.tune_apply = true;
        } else if (strcmp(arg, "--tune-report") == 0) {
            cfg.tune_report = true;
        } else if (strncmp(arg, "--tune-seed=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value) {
                    cfg.tune_seed = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--tune-count=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed >= 0L) {
                    if (parsed > INT_MAX) {
                        parsed = INT_MAX;
                    }
                    cfg.tune_select_n = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--human-bridge", 14) == 0) {
            cfg.human_bridge = true;
            const char *value = NULL;
            if (arg[14] == '=') {
                value = arg + 15;
            } else if (i + 1 < argc && argv[i + 1][0] != '-') {
                value = argv[i + 1];
                ++i;
            }
            if (value && (strcmp(value, "off") == 0 || strcmp(value, "0") == 0)) {
                cfg.human_bridge = false;
            }
        } else if (strcmp(arg, "--empathic") == 0) {
            cfg.empathic_enabled = true;
        } else if (strcmp(arg, "--empathic-trace") == 0) {
            cfg.empathic_trace = true;
        } else if (strcmp(arg, "--anticipation") == 0) {
            cfg.empathic_enabled = true;
            cfg.empathic_trace = true;
            cfg.anticipation_trace = true; // merged by Codex
        } else if (strcmp(arg, "--anticipation2") == 0) {
            cfg.anticipation2_enabled = true;
        } else if (strcmp(arg, "--ant2-trace") == 0) {
            cfg.anticipation2_enabled = true;
            cfg.ant2_trace = true;
        } else if (strncmp(arg, "--ant2-gain=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.0f) {
                        parsed = 0.0f;
                    } else if (parsed > 1.0f) {
                        parsed = 1.0f;
                    }
                    cfg.anticipation2_enabled = true;
                    cfg.ant2_gain = parsed;
                }
            }
        } else if (strcmp(arg, "--affinity") == 0) {
            cfg.affinity_enabled = true;
        } else if (strncmp(arg, "--affinity-cfg=", 15) == 0) {
            const char *value = arg + 15;
            if (value && *value) {
                parse_affinity_config(&cfg.affinity_config, value);
            }
        } else if (strncmp(arg, "--allow-align=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.0f) {
                        parsed = 0.0f;
                    } else if (parsed > 1.0f) {
                        parsed = 1.0f;
                    }
                    cfg.allow_align_consent = parsed;
                }
            }
        } else if (strncmp(arg, "--amp-min=", 10) == 0) {
            const char *value = arg + 10;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.mirror_amp_min = parsed;
                }
            }
        } else if (strncmp(arg, "--amp-max=", 10) == 0) {
            const char *value = arg + 10;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.mirror_amp_max = parsed;
                }
            }
        } else if (strncmp(arg, "--tempo-min=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.mirror_tempo_min = parsed;
                }
            }
        } else if (strncmp(arg, "--tempo-max=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.mirror_tempo_max = parsed;
                }
            }
        } else if (strcmp(arg, "--introspect") == 0) {
            cfg.introspect_enabled = true;
        } else if (strcmp(arg, "--harmony") == 0) {
            cfg.harmony_enabled = true;
        } else if (strcmp(arg, "--trs") == 0) {
            cfg.trs_enabled = true;
        } else if (strcmp(arg, "--astro") == 0) {
            cfg.astro_enabled = true;
        } else if (strcmp(arg, "--astro-trace") == 0) {
            cfg.astro_trace = true;
            cfg.astro_enabled = true;
        } else if (strncmp(arg, "--astro-rate=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.astro_rate = clamp_range(parsed, 0.005f, 0.020f);
                }
            }
        } else if (strncmp(arg, "--astro-tone=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.astro_tone_init = clamp_unit(parsed);
                    cfg.astro_tone_set = true;
                }
            }
        } else if (strncmp(arg, "--astro-mem=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.astro_memory_init = clamp_unit(parsed);
                    cfg.astro_memory_set = true;
                }
            }
        } else if (strcmp(arg, "--kiss") == 0) {
            cfg.kiss_enabled = true;
        } else if (strncmp(arg, "--kiss-thr=", 11) == 0) {
            const char *value = arg + 11;
            if (value && *value) {
                parse_kiss_thresholds(&cfg, value);
            }
        } else if (strncmp(arg, "--kiss-warmup=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed >= 0L) {
                    if (parsed > 255L) {
                        parsed = 255L;
                    }
                    cfg.kiss_warmup_cycles = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--kiss-refrac=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed >= 0L) {
                    if (parsed > 255L) {
                        parsed = 255L;
                    }
                    cfg.kiss_refractory_cycles = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--kiss-alpha=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed) && parsed > 0.0f) {
                    if (parsed > 1.0f) {
                        parsed = 1.0f;
                    }
                    cfg.kiss_alpha = parsed;
                }
            }
        } else if (strncmp(arg, "--trs-alpha=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.05f) {
                        parsed = 0.05f;
                    } else if (parsed > 0.8f) {
                        parsed = 0.8f;
                    }
                    cfg.trs_alpha = parsed;
                }
            }
        } else if (strncmp(arg, "--trs-warmup=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value) {
                    if (parsed < 0) {
                        parsed = 0;
                    } else if (parsed > 10) {
                        parsed = 10;
                    }
                    cfg.trs_warmup = (int)parsed;
                }
            }
        } else if (strcmp(arg, "--trs-adapt") == 0) {
            cfg.trs_adapt_enabled = true;
            cfg.trs_enabled = true;
        } else if (strncmp(arg, "--trs-alpha-min=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.trs_alpha_min = parsed;
                    cfg.trs_adapt_enabled = true;
                    cfg.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--trs-alpha-max=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.trs_alpha_max = parsed;
                    cfg.trs_adapt_enabled = true;
                    cfg.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--trs-target-delta=", 20) == 0) {
            const char *value = arg + 20;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.trs_target_delta = parsed;
                    cfg.trs_adapt_enabled = true;
                    cfg.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--trs-kp=", 9) == 0) {
            const char *value = arg + 9;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.trs_kp = parsed;
                    cfg.trs_adapt_enabled = true;
                    cfg.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--trs-ki=", 9) == 0) {
            const char *value = arg + 9;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.trs_ki = parsed;
                    cfg.trs_adapt_enabled = true;
                    cfg.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--trs-kd=", 9) == 0) {
            const char *value = arg + 9;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.trs_kd = parsed;
                    cfg.trs_adapt_enabled = true;
                    cfg.trs_enabled = true;
                }
            }
        } else if (strcmp(arg, "--dream") == 0) {
            cfg.dream_enabled = true;
        } else if (strcmp(arg, "--dream-replay") == 0) {
            cfg.dream_replay_enabled = true;
        } else if (strncmp(arg, "--dream-cycles=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed > 0) {
                    if (parsed > 256) {
                        parsed = 256;
                    }
                    cfg.dream_replay_cycles = (int)parsed;
                    cfg.dream_replay_enabled = true;
                }
            }
        } else if (strncmp(arg, "--dream-rate=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.dream_replay_rate = clamp_range(parsed, 0.05f, 0.8f);
                    cfg.dream_replay_enabled = true;
                }
            }
        } else if (strncmp(arg, "--dream-decay=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.0f) {
                        parsed = 0.0f;
                    } else if (parsed > 0.1f) {
                        parsed = 0.1f;
                    }
                    cfg.dream_replay_decay = parsed;
                    cfg.dream_replay_enabled = true;
                }
            }
        } else if (strcmp(arg, "--dream-trace") == 0) {
            cfg.dream_replay_trace = true;
            cfg.dream_replay_enabled = true;
        } else if (strcmp(arg, "--bridge") == 0) {
            cfg.bridge_enabled = true;
        } else if (strncmp(arg, "--bridge-plasticity=", 21) == 0) {
            const char *value = arg + 21;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.bridge_plasticity = clamp_unit(parsed);
                    cfg.bridge_enabled = true;
                }
            }
        } else if (strncmp(arg, "--bridge-retention=", 20) == 0) {
            const char *value = arg + 20;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.bridge_retention = clamp_unit(parsed);
                    cfg.bridge_enabled = true;
                }
            }
        } else if (strncmp(arg, "--bridge-recovery=", 19) == 0) {
            const char *value = arg + 19;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.0f) {
                        parsed = 0.0f;
                    } else if (parsed > 0.2f) {
                        parsed = 0.2f;
                    }
                    cfg.bridge_recovery = parsed;
                    cfg.bridge_enabled = true;
                }
            }
        } else if (strcmp(arg, "--strict-order") == 0) {
            cfg.strict_order = true;
        } else if (strcmp(arg, "--dry-run") == 0) {
            cfg.dry_run = true;
        } else if (strcmp(arg, "--bond-trace") == 0) {
            cfg.bond_trace = true;
        } else if (strncmp(arg, "--emotional-source=", 20) == 0) {
            const char *value = arg + 20;
            if (strcmp(value, "text") == 0) {
                cfg.emotional_source = EMPATHIC_SOURCE_TEXT;
            } else if (strcmp(value, "sensor") == 0) {
                cfg.emotional_source = EMPATHIC_SOURCE_SENSOR;
            } else {
                cfg.emotional_source = EMPATHIC_SOURCE_AUDIO;
            }
        } else if (strncmp(arg, "--empathy-gain=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.2f) {
                        parsed = 0.2f;
                    } else if (parsed > 3.5f) {
                        parsed = 3.5f;
                    }
                    cfg.empathy_gain = parsed;
                }
            }
        } else if (strcmp(arg, "--emotional-memory") == 0) {
            cfg.emotional_memory_enabled = true;
        } else if (strcmp(arg, "--memory-trace") == 0) {
            cfg.memory_trace = true;
        } else if (strncmp(arg, "--emotion-trace-path=", 21) == 0) {
            const char *value = arg + 21;
            if (value && *value) {
                strncpy(cfg.emotion_trace_path, value, sizeof(cfg.emotion_trace_path) - 1U);
                cfg.emotion_trace_path[sizeof(cfg.emotion_trace_path) - 1U] = '\0';
            }
        } else if (strncmp(arg, "--limit=", 8) == 0) {
            const char *value = arg + 8;
            if (value && *value) {
                unsigned long parsed = strtoul(value, NULL, 10);
                if (parsed > 0UL && parsed <= 100000UL) {
                    cfg.cycle_limit = (unsigned int)parsed;
                }
            }
        } else if (strncmp(arg, "--recognition-threshold=", 24) == 0) {
            const char *value = arg + 24;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.01f) {
                        parsed = 0.01f;
                    } else if (parsed > 1.5f) {
                        parsed = 1.5f;
                    }
                    cfg.recognition_threshold = parsed;
                }
            }
        }
    }

    normalize_bounds(&cfg.mirror_amp_min, &cfg.mirror_amp_max, MIRROR_GAIN_AMP_MIN_DEFAULT, MIRROR_GAIN_AMP_MAX_DEFAULT);
    normalize_bounds(&cfg.mirror_tempo_min,
                     &cfg.mirror_tempo_max,
                     MIRROR_GAIN_TEMPO_MIN_DEFAULT,
                     MIRROR_GAIN_TEMPO_MAX_DEFAULT);

    if (cfg.bridge_enabled) {
        if (!cfg.dream_replay_enabled) {
            cfg.dream_replay_enabled = true;
        }
        if (!cfg.harmony_enabled) {
            cfg.harmony_enabled = true;
        }
    }

    if ((cfg.harmony_enabled || cfg.dream_enabled || cfg.dream_replay_enabled) && !cfg.introspect_enabled) {
        cfg.introspect_enabled = true;
    }

    if (cfg.astro_trace) {
        cfg.astro_enabled = true;
    }
    if (cfg.astro_enabled) {
        if (!cfg.introspect_enabled) {
            cfg.introspect_enabled = true;
        }
        if (!cfg.harmony_enabled) {
            cfg.harmony_enabled = true;
        }
    }
    if ((cfg.dream_replay_enabled || cfg.bridge_enabled) && !cfg.harmony_enabled) {
        cfg.harmony_enabled = true;
    }

    return cfg;
}

static size_t read_erb_index(ErbIndexRecord *records, size_t capacity)
{
    if (!records || capacity == 0) {
        return 0;
    }
    FILE *fp = fopen(ERB_INDEX_PATH, "r");
    if (!fp) {
        return 0;
    }
    size_t count = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        unsigned int idx = 0U;
        unsigned int tag_mask = 0U;
        int len = 0;
        float delta_max = 0.0f;
        float alpha_mean = 0.0f;
        char tag_text[128];
        tag_text[0] = '\0';
        int parsed = sscanf(line,
                            "{\"idx\":%u,\"len\":%d,\"tag\":\"%127[^\"]\",\"tag_mask\":%u,\"delta_max\":%f,\"alpha_mean\":%f}",
                            &idx,
                            &len,
                            tag_text,
                            &tag_mask,
                            &delta_max,
                            &alpha_mean);
        if (parsed >= 5) {
            if (count < capacity) {
                records[count].id = idx;
                records[count].tag_mask = tag_mask;
                records[count].len = len;
                records[count].delta_max = delta_max;
                records[count].alpha_mean = (parsed == 6) ? alpha_mean : 0.0f;
                ++count;
            }
        }
    }
    fclose(fp);
    return count;
}

static size_t collect_replay_ids(const substrate_config *cfg,
                                 const ErbIndexRecord *records,
                                 size_t record_count,
                                 uint32_t *out_ids,
                                 size_t capacity)
{
    if (!cfg || !records || !out_ids || capacity == 0) {
        return 0;
    }
    size_t count = 0;
    if (cfg->erb_replay_mode == ERB_REPLAY_LATEST) {
        const ErbIndexRecord *latest = NULL;
        for (size_t i = 0; i < record_count; ++i) {
            if (!latest || records[i].id > latest->id) {
                latest = &records[i];
            }
        }
        if (latest && count < capacity) {
            out_ids[count++] = latest->id;
        }
    } else if (cfg->erb_replay_mode == ERB_REPLAY_INDEX) {
        for (size_t i = 0; i < record_count; ++i) {
            if (records[i].id == cfg->erb_replay_idx) {
                if (count < capacity) {
                    out_ids[count++] = records[i].id;
                }
                break;
            }
        }
    } else if (cfg->erb_replay_mode == ERB_REPLAY_TAG) {
        for (size_t i = 0; i < record_count && count < capacity; ++i) {
            if ((records[i].tag_mask & cfg->erb_replay_tag_mask) != 0U) {
                out_ids[count++] = records[i].id;
            }
        }
    } else if (cfg->erb_replay_mode == ERB_REPLAY_ALL) {
        for (size_t i = 0; i < record_count && count < capacity; ++i) {
            out_ids[count++] = records[i].id;
        }
    }
    return count;
}

static size_t collect_tune_ids(const substrate_config *cfg,
                               const ErbIndexRecord *records,
                               size_t record_count,
                               uint32_t *out_ids,
                               size_t capacity)
{
    if (!cfg || !records || !out_ids || capacity == 0) {
        return 0;
    }
    size_t count = 0;
    TuneSourceMode mode = cfg->tune_source_mode;
    if (mode == TUNE_SOURCE_NONE) {
        mode = TUNE_SOURCE_LATEST;
    }
    if (mode == TUNE_SOURCE_LATEST) {
        const ErbIndexRecord *latest = NULL;
        for (size_t i = 0; i < record_count; ++i) {
            if (!latest || records[i].id > latest->id) {
                latest = &records[i];
            }
        }
        if (latest && count < capacity) {
            out_ids[count++] = latest->id;
        }
    } else if (mode == TUNE_SOURCE_INDEX) {
        for (size_t i = 0; i < record_count; ++i) {
            if (records[i].id == cfg->tune_source_idx) {
                if (count < capacity) {
                    out_ids[count++] = records[i].id;
                }
                break;
            }
        }
    } else if (mode == TUNE_SOURCE_TAG) {
        for (size_t i = 0; i < record_count && count < capacity; ++i) {
            if ((records[i].tag_mask & cfg->tune_source_mask) != 0U) {
                out_ids[count++] = records[i].id;
            }
        }
    } else if (mode == TUNE_SOURCE_ALL) {
        for (size_t i = 0; i < record_count && count < capacity; ++i) {
            out_ids[count++] = records[i].id;
        }
    }
    if (count == 0) {
        const ErbIndexRecord *latest = NULL;
        for (size_t i = 0; i < record_count; ++i) {
            if (!latest || records[i].id > latest->id) {
                latest = &records[i];
            }
        }
        if (latest && capacity > 0) {
            out_ids[0] = latest->id;
            count = 1;
        }
    }
    return count;
}

static size_t load_tune_episodes(const substrate_config *cfg,
                                 Episode *episodes,
                                 uint32_t *ids,
                                 size_t capacity)
{
    if (!cfg || !episodes || capacity == 0) {
        return 0;
    }
    ErbIndexRecord records[ERB_MAX_INDEX_RECORDS];
    size_t record_count = read_erb_index(records, ERB_MAX_INDEX_RECORDS);
    if (record_count == 0) {
        return 0;
    }
    uint32_t selected[ERB_MAX_INDEX_RECORDS];
    size_t selected_count = collect_tune_ids(cfg, records, record_count, selected, ERB_MAX_INDEX_RECORDS);
    if (selected_count == 0) {
        return 0;
    }
    if (cfg->tune_select_n > 0 && (size_t)cfg->tune_select_n < selected_count) {
        selected_count = (size_t)cfg->tune_select_n;
    }
    if (selected_count > capacity) {
        selected_count = capacity;
    }
    size_t loaded = 0;
    for (size_t i = 0; i < selected_count; ++i) {
        uint32_t id = selected[i];
        Episode episode;
        if (erb_load_episode(id, &episode)) {
            episodes[loaded] = episode;
            if (ids) {
                ids[loaded] = id;
            }
            loaded += 1;
        } else {
            fprintf(stderr, "[tune] unable to load episode %u.\n", id);
        }
    }
    return loaded;
}

static void ensure_logs_directory_path(void)
{
#if defined(_WIN32)
    _mkdir("logs");
#else
    struct stat st;
    if (stat("logs", &st) != 0) {
        mkdir("logs", 0777);
    }
#endif
}

static void log_tune_candidate(const TuneResult *result, int rank)
{
    if (!result || !isfinite(result->loss)) {
        return;
    }
    ensure_logs_directory_path();
    FILE *fp = fopen(TUNE_REPORT_PATH, "a");
    if (!fp) {
        return;
    }
    if (fprintf(fp,
                "{\"mode\":\"erb\",\"rank\":%d,\"loss\":%.6f,\"delta_mean\":%.6f,\"harm_mean\":%.6f,"
                "\"consent_mean\":%.6f,\"misalign_rate\":%.6f,\"cfg\":{\"trs_alpha\":%.4f,\"trs_warmup\":%d,\"allow_align\":%.4f}}\n",
                rank,
                result->loss,
                result->delta_mean,
                result->harm_mean,
                result->consent_mean,
                result->misalign_rate,
                result->cfg.trs_alpha,
                result->cfg.trs_warmup,
                result->cfg.allow_align) >= 0) {
        fflush(fp);
    }
    fclose(fp);
}

static void log_tune_best(const TuneConfig *cfg, const TuneResult *result)
{
    if (!cfg) {
        return;
    }
    ensure_logs_directory_path();
    FILE *fp = fopen(TUNE_BEST_PATH, "w");
    if (!fp) {
        return;
    }
    if (result && isfinite(result->loss)) {
        fprintf(fp,
                "{\"trs_alpha\":%.6f,\"trs_warmup\":%d,\"allow_align\":%.6f,"
                "\"loss\":%.6f,\"delta_mean\":%.6f,\"harm_mean\":%.6f,\"consent_mean\":%.6f,\"misalign_rate\":%.6f}\n",
                cfg->trs_alpha,
                cfg->trs_warmup,
                cfg->allow_align,
                result->loss,
                result->delta_mean,
                result->harm_mean,
                result->consent_mean,
                result->misalign_rate);
    } else {
        fprintf(fp,
                "{\"trs_alpha\":%.6f,\"trs_warmup\":%d,\"allow_align\":%.6f}\n",
                cfg->trs_alpha,
                cfg->trs_warmup,
                cfg->allow_align);
    }
    fclose(fp);
}

static bool save_tune_profile(const char *path, const TuneConfig *cfg, const TuneResult *result)
{
    if (!path || !*path || !cfg) {
        return false;
    }
    FILE *fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "[tune] unable to write profile %s.\n", path);
        return false;
    }
    if (result && isfinite(result->loss)) {
        fprintf(fp,
                "{\"trs_alpha\":%.6f,\"trs_warmup\":%d,\"allow_align\":%.6f,\"loss\":%.6f}\n",
                cfg->trs_alpha,
                cfg->trs_warmup,
                cfg->allow_align,
                result->loss);
    } else {
        fprintf(fp,
                "{\"trs_alpha\":%.6f,\"trs_warmup\":%d,\"allow_align\":%.6f}\n",
                cfg->trs_alpha,
                cfg->trs_warmup,
                cfg->allow_align);
    }
    fclose(fp);
    return true;
}

static bool load_tune_profile(const char *path, TuneConfig *cfg)
{
    if (!path || !*path || !cfg) {
        return false;
    }
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "[tune] unable to open profile %s.\n", path);
        return false;
    }
    char buffer[512];
    size_t read_bytes = fread(buffer, 1, sizeof(buffer) - 1, fp);
    fclose(fp);
    buffer[read_bytes] = '\0';
    float alpha = 0.0f;
    float align = 0.0f;
    int warm = 0;
    if (!extract_profile_float(buffer, "trs_alpha", &alpha)) {
        return false;
    }
    if (!extract_profile_int(buffer, "trs_warmup", &warm)) {
        float warm_f = 0.0f;
        if (extract_profile_float(buffer, "trs_warmup", &warm_f)) {
            warm = (int)lroundf(warm_f);
        } else {
            return false;
        }
    }
    if (!extract_profile_float(buffer, "allow_align", &align)) {
        return false;
    }
    cfg->trs_alpha = alpha;
    cfg->trs_warmup = warm;
    cfg->allow_align = align;
    return true;
}

static void print_tune_summary(const TuneResult *results, size_t count)
{
    if (!results || count == 0) {
        printf("[tune] no tuning results available.\n");
        return;
    }
    size_t limit = count < 3 ? count : 3;
    printf("[tune] top %zu configs:\n", limit);
    for (size_t i = 0; i < limit; ++i) {
        const TuneResult *res = &results[i];
        printf("  #%zu loss=%.6f delta=%.6f harm=%.6f consent=%.6f misalign=%.6f alpha=%.4f warm=%d align=%.4f\n",
               i + 1,
               res->loss,
               res->delta_mean,
               res->harm_mean,
               res->consent_mean,
               res->misalign_rate,
               res->cfg.trs_alpha,
               res->cfg.trs_warmup,
               res->cfg.allow_align);
    }
}

static bool execute_tune_search(const substrate_config *cfg)
{
    Episode episodes[ERB_MAX_EPISODES];
    uint32_t ids[ERB_MAX_EPISODES];
    size_t episode_count = load_tune_episodes(cfg, episodes, ids, ERB_MAX_EPISODES);
    if (episode_count == 0) {
        fprintf(stderr, "[tune] no episodes available for tuning.\n");
        return false;
    }

    ERB dataset;
    memset(&dataset, 0, sizeof(dataset));
    dataset.count = (int)episode_count;
    if (episode_count < ERB_MAX_EPISODES) {
        dataset.head = (int)episode_count;
    } else {
        dataset.head = (int)(episode_count % ERB_MAX_EPISODES);
    }
    for (size_t i = 0; i < episode_count && i < ERB_MAX_EPISODES; ++i) {
        dataset.buf[i] = episodes[i];
        dataset.ids[i] = ids[i];
    }

    TuneSpace space;
    tune_default_space(&space);
    float alpha_min = fminf(cfg->tune_alpha_min, cfg->tune_alpha_max);
    float alpha_max = fmaxf(cfg->tune_alpha_min, cfg->tune_alpha_max);
    if (!isfinite(alpha_min) || !isfinite(alpha_max)) {
        alpha_min = 0.1f;
        alpha_max = 0.6f;
    }
    if (alpha_min < 0.01f) {
        alpha_min = 0.01f;
    }
    if (alpha_max > 0.95f) {
        alpha_max = 0.95f;
    }
    space.trs_alpha_min = alpha_min;
    space.trs_alpha_max = alpha_max;

    int warm_min = cfg->tune_warm_min <= cfg->tune_warm_max ? cfg->tune_warm_min : cfg->tune_warm_max;
    int warm_max = cfg->tune_warm_min <= cfg->tune_warm_max ? cfg->tune_warm_max : cfg->tune_warm_min;
    if (warm_min < 0) {
        warm_min = 0;
    }
    if (warm_max > 10) {
        warm_max = 10;
    }
    space.trs_warmup_min = warm_min;
    space.trs_warmup_max = warm_max;

    float align_min = fminf(cfg->tune_align_min, cfg->tune_align_max);
    float align_max = fmaxf(cfg->tune_align_min, cfg->tune_align_max);
    if (!isfinite(align_min) || !isfinite(align_max)) {
        align_min = 0.4f;
        align_max = 0.8f;
    }
    if (align_min < 0.0f) {
        align_min = 0.0f;
    }
    if (align_max > 1.0f) {
        align_max = 1.0f;
    }
    space.allow_align_min = align_min;
    space.allow_align_max = align_max;

    int trials = cfg->tune_trials > 0 ? cfg->tune_trials : 1;
    if (trials > cfg->tune_max_runs) {
        trials = cfg->tune_max_runs;
    }
    int refine = cfg->tune_refine >= 0 ? cfg->tune_refine : 0;
    if (refine > cfg->tune_max_runs - trials) {
        refine = cfg->tune_max_runs - trials;
    }
    if (refine < 0) {
        refine = 0;
    }
    space.trials = trials;
    space.local_refine = refine;

    TuneResult best = autotune_on_erb(&dataset, cfg->tune_select_n, &space, cfg->tune_seed);
    g_tune_ranked_count = autotune_get_ranked_results(g_tune_ranked_cache,
                                                      sizeof(g_tune_ranked_cache) / sizeof(g_tune_ranked_cache[0]));
    if (!isfinite(best.loss) || best.loss >= FLT_MAX) {
        fprintf(stderr, "[tune] tuning search did not converge.\n");
        return false;
    }

    g_tune_last_result = best;
    g_tune_profile = best.cfg;
    g_tune_profile_loaded = true;

    size_t log_count = g_tune_ranked_count < 3 ? g_tune_ranked_count : 3;
    for (size_t i = 0; i < log_count; ++i) {
        log_tune_candidate(&g_tune_ranked_cache[i], (int)i);
    }
    log_tune_best(&g_tune_profile, &best);

    return true;
}

static bool handle_tune_options(substrate_config *cfg, bool *exit_after)
{
    if (!cfg) {
        return false;
    }
    g_tune_profile_loaded = false;
    g_tune_ranked_count = 0;
    g_tune_last_result.loss = FLT_MAX;

    bool have_profile = false;
    bool should_exit = false;

    if (cfg->tune_load_path[0]) {
        TuneConfig loaded;
        if (load_tune_profile(cfg->tune_load_path, &loaded)) {
            g_tune_profile = loaded;
            g_tune_profile_loaded = true;
            have_profile = true;
            printf("[tune] loaded profile %s (alpha=%.4f warm=%d align=%.4f).\n",
                   cfg->tune_load_path,
                   loaded.trs_alpha,
                   loaded.trs_warmup,
                   loaded.allow_align);
        } else {
            fprintf(stderr, "[tune] failed to load profile from %s.\n", cfg->tune_load_path);
        }
    }

    if (cfg->tune_enabled) {
        if (execute_tune_search(cfg)) {
            have_profile = true;
            printf("[tune] best loss=%.6f alpha=%.4f warm=%d align=%.4f (delta=%.6f harm=%.6f misalign=%.6f).\n",
                   g_tune_last_result.loss,
                   g_tune_profile.trs_alpha,
                   g_tune_profile.trs_warmup,
                   g_tune_profile.allow_align,
                   g_tune_last_result.delta_mean,
                   g_tune_last_result.harm_mean,
                   g_tune_last_result.misalign_rate);
        } else {
            fprintf(stderr, "[tune] autotune search failed.\n");
        }
    }

    if (cfg->tune_report) {
        if (g_tune_ranked_count > 0) {
            print_tune_summary(g_tune_ranked_cache, g_tune_ranked_count);
        } else if (g_tune_profile_loaded) {
            printf("[tune] profile alpha=%.4f warm=%d align=%.4f.\n",
                   g_tune_profile.trs_alpha,
                   g_tune_profile.trs_warmup,
                   g_tune_profile.allow_align);
        } else {
            printf("[tune] no tuning data to report.\n");
        }
    }

    if (cfg->tune_save_path[0]) {
        if (have_profile) {
            if (!save_tune_profile(cfg->tune_save_path,
                                   &g_tune_profile,
                                   (g_tune_ranked_count > 0) ? &g_tune_last_result : NULL)) {
                fprintf(stderr, "[tune] failed to save profile to %s.\n", cfg->tune_save_path);
            } else {
                printf("[tune] saved profile to %s.\n", cfg->tune_save_path);
            }
        } else {
            fprintf(stderr, "[tune] no profile available to save (%s).\n", cfg->tune_save_path);
        }
    }

    if (cfg->tune_apply && have_profile) {
        cfg->trs_enabled = true;
        cfg->trs_alpha = g_tune_profile.trs_alpha;
        cfg->trs_warmup = g_tune_profile.trs_warmup;
        cfg->allow_align_consent = g_tune_profile.allow_align;
    }

    if (exit_after) {
        should_exit = (cfg->tune_enabled || cfg->tune_load_path[0]) && !cfg->run_substrate;
        *exit_after = should_exit;
    }

    return have_profile;
}

static void format_replay_mode_label(const substrate_config *cfg, char *buffer, size_t size)
{
    if (!buffer || size == 0) {
        return;
    }
    buffer[0] = '\0';
    if (!cfg) {
        return;
    }
    switch (cfg->erb_replay_mode) {
    case ERB_REPLAY_LATEST:
        strncpy(buffer, "latest", size - 1);
        buffer[size - 1] = '\0';
        break;
    case ERB_REPLAY_INDEX:
        snprintf(buffer, size, "idx:%u", cfg->erb_replay_idx);
        break;
    case ERB_REPLAY_TAG: {
        char tags[64];
        erb_tag_to_string(cfg->erb_replay_tag_mask, tags, sizeof(tags));
        if (tags[0] == '\0') {
            strncpy(buffer, "tag:0", size - 1);
            buffer[size - 1] = '\0';
        } else {
            strncpy(buffer, "tag:", size - 1);
            buffer[size - 1] = '\0';
            size_t current_len = strlen(buffer);
            if (current_len < size - 1) {
                strncat(buffer, tags, size - 1 - current_len);
            }
        }
        break;
    }
    case ERB_REPLAY_ALL:
        strncpy(buffer, "ALL", size - 1);
        buffer[size - 1] = '\0';
        break;
    default:
        strncpy(buffer, "NONE", size - 1);
        buffer[size - 1] = '\0';
        break;
    }
}

static void erb_sleep_seconds(double seconds)
{
    if (seconds <= 0.0) {
        return;
    }
#if defined(_WIN32)
    DWORD millis = (DWORD)(seconds * 1000.0);
    Sleep(millis);
#else
    struct timespec ts;
    if (seconds < 0.0) {
        seconds = 0.0;
    }
    ts.tv_sec = (time_t)seconds;
    double fractional = seconds - (double)ts.tv_sec;
    if (fractional < 0.0) {
        fractional = 0.0;
    }
    ts.tv_nsec = (long)(fractional * 1000000000.0);
    if (ts.tv_nsec < 0) {
        ts.tv_nsec = 0;
    }
    nanosleep(&ts, NULL);
#endif
}

static int run_erb_replay(const substrate_config *cfg)
{
    if (!cfg) {
        return 1;
    }
    ErbIndexRecord records[ERB_MAX_INDEX_RECORDS];
    size_t record_count = read_erb_index(records, ERB_MAX_INDEX_RECORDS);
    if (record_count == 0) {
        fprintf(stderr, "[erb] no episodes available for replay.\n");
        return 1;
    }
    uint32_t ids[ERB_MAX_INDEX_RECORDS];
    size_t id_count = collect_replay_ids(cfg, records, record_count, ids, ERB_MAX_INDEX_RECORDS);
    if (id_count == 0) {
        fprintf(stderr, "[erb] no matching episodes for replay selection.\n");
        return 1;
    }

    char mode_label[64];
    format_replay_mode_label(cfg, mode_label, sizeof(mode_label));
    double base_interval = 0.1;
    double speed = cfg->erb_replay_speed > 0.0f ? cfg->erb_replay_speed : 1.0;
    double delay = base_interval / speed;
    if (delay < 0.0) {
        delay = 0.0;
    }

    for (size_t i = 0; i < id_count; ++i) {
        uint32_t episode_id = ids[i];
        Episode episode;
        if (!erb_load_episode(episode_id, &episode)) {
            fprintf(stderr, "[erb] unable to load episode %u.\n", episode_id);
            continue;
        }
        printf("[erb] replaying episode %u (%d ticks) mode=%s\n",
               episode_id,
               episode.len,
               mode_label[0] ? mode_label : "unknown");
        for (int tick = 0; tick < episode.len; ++tick) {
            TickSnapshot snap = episode.seq[tick];
            Metrics metrics;
            metrics.amp = snap.amp;
            metrics.tempo = snap.tempo;
            metrics.consent = snap.consent;
            metrics.influence = snap.influence;
            metrics.bond_coh = snap.harmony;
            metrics.error_margin = fabsf(snap.amp - snap.tempo);
            metrics.harmony = snap.harmony;
            metrics.kiss = 0;
            int dream_phase = (int)lroundf(snap.dream);
            if (dream_phase < (int)DREAM_COUPLER_PHASE_REST) {
                dream_phase = (int)DREAM_COUPLER_PHASE_REST;
            } else if (dream_phase > (int)DREAM_COUPLER_PHASE_WAKE) {
                dream_phase = (int)DREAM_COUPLER_PHASE_WAKE;
            }
            substrate_introspect_state.dream_phase = (DreamCouplerPhase)dream_phase;
            introspect_tick(&substrate_introspect_state, &metrics);
            if (substrate_introspect_state.enabled &&
                (cfg->harmony_enabled || cfg->dream_enabled)) {
                Metrics harmony_metrics = metrics;
                harmony_sync(&substrate_introspect_state, &harmony_metrics);
                if (substrate_astro_enabled) {
                    float harmony_signal = clamp_unit(harmony_metrics.harmony);
                    float trs_delta = fabsf(introspect_get_last_trs_delta());
                    astro_update(&substrate_astro,
                                 harmony_signal,
                                 harmony_signal,
                                 trs_delta,
                                 metrics.consent,
                                 metrics.influence);
                    float astro_gain = astro_modulate_feedback(&substrate_astro);
                    substrate_astro_feedback = clamp_range(astro_gain, 0.85f, 1.15f);
                    substrate_astro_trace_log(substrate_astro.last_stability, astro_gain);
                }
            }
            float delta = introspect_get_last_trs_delta();
            float alpha = introspect_get_last_trs_alpha();
            float err = introspect_get_last_trs_error();
            erb_log_replay_tick((uint32_t)tick,
                                 episode_id,
                                 delta,
                                 alpha,
                                 err,
                                 mode_label);
            erb_sleep_seconds(delay);
        }
    }
    return 0;
}

static void lip_sleep(unsigned int interval_ms)
{
#ifdef _WIN32
    Sleep(interval_ms);
#else
    struct timespec ts;
    ts.tv_sec = interval_ms / 1000U;
    ts.tv_nsec = (long)(interval_ms % 1000U) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

static bool json_extract_float(const char *json, const char *key, float *out)
{
    const char *pos = strstr(json, key);
    if (!pos) {
        return false;
    }
    pos += strlen(key);
    while (*pos == ' ' || *pos == '\t' || *pos == '"' || *pos == ':' ) {
        ++pos;
    }
    if (*pos == '\0') {
        return false;
    }
    char *end_ptr = NULL;
    float value = strtof(pos, &end_ptr);
    if (end_ptr == pos) {
        return false;
    }
    *out = value;
    return true;
}

static void close_socket(int fd)
{
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}

static int lip_connect_peer(const substrate_config *cfg)
{
    if (cfg->lip_host[0] == '\0') {
        return -1;
    }
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return -1;
    }
#endif
    const char *separator = strrchr(cfg->lip_host, ':');
    if (!separator) {
        return -1;
    }
    char host[96];
    size_t host_len = (size_t)(separator - cfg->lip_host);
    if (host_len >= sizeof(host)) {
        host_len = sizeof(host) - 1U;
    }
    memcpy(host, cfg->lip_host, host_len);
    host[host_len] = '\0';
    const char *port_str = separator + 1;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *result = NULL;
    int err = getaddrinfo(host, port_str, &hints, &result);
    if (err != 0 || !result) {
        return -1;
    }
    int sock_fd = -1;
    for (struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next) {
        sock_fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock_fd < 0) {
            continue;
        }
        if (connect(sock_fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close_socket(sock_fd);
        sock_fd = -1;
    }
    freeaddrinfo(result);
    return sock_fd;
}

static int lip_listen_local(uint16_t port)
{
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return -1;
    }
#endif
    int sock_fd = (int)socket(AF_INET6, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        sock_fd = (int)socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd < 0) {
            return -1;
        }
    }
    int opt = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_any;
    addr6.sin6_port = htons(port);
    if (bind(sock_fd, (struct sockaddr *)&addr6, sizeof(addr6)) != 0) {
        close_socket(sock_fd);
        sock_fd = (int)socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd < 0) {
            return -1;
        }
        setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
        struct sockaddr_in addr4;
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        addr4.sin_addr.s_addr = htonl(INADDR_ANY);
        addr4.sin_port = htons(port);
        if (bind(sock_fd, (struct sockaddr *)&addr4, sizeof(addr4)) != 0) {
            close_socket(sock_fd);
            return -1;
        }
    }
    if (listen(sock_fd, 1) != 0) {
        close_socket(sock_fd);
        return -1;
    }
    return sock_fd;
}

static int lip_accept_peer(int listen_fd)
{
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    int client_fd = (int)accept(listen_fd, (struct sockaddr *)&addr, &addr_len);
    return client_fd;
}

static void run_lip_resonance_test(liminal_state *state, const substrate_config *cfg)
{
    int peer_fd = -1;
    int listen_fd = -1;
    bool connected = false;
    if (cfg->lip_host[0] != '\0') {
        peer_fd = lip_connect_peer(cfg);
        connected = peer_fd >= 0;
    } else if (cfg->lip_port != 0U) {
        listen_fd = lip_listen_local(cfg->lip_port);
        if (listen_fd >= 0) {
            if (cfg->trace || cfg->lip_trace) {
                printf("[lip] waiting for resonance peer on port %u\n", (unsigned)cfg->lip_port);
            }
            peer_fd = lip_accept_peer(listen_fd);
            connected = peer_fd >= 0;
        }
    }
    if (!connected) {
        fprintf(stderr, "[lip] unable to establish LIP channel.\n");
        if (listen_fd >= 0) {
            close_socket(listen_fd);
        }
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    float freq = 0.68f;
    float phase = 0.27f;
    state->breath_rate = freq;
    state->breath_position = phase;
    state->phase_offset = 0.0f;

    const int max_cycles = 10;
    char buffer[256];
    for (int cycle = 0; cycle < max_cycles; ++cycle) {
        lip_event ev = resonance_event(freq, phase, "sync");
        int len = snprintf(buffer,
                           sizeof(buffer),
                           "{ \"type\": \"%s\", \"freq\": %.3f, \"phase\": %.3f, \"intent\": \"%s\" }\n",
                           ev.type,
                           ev.freq,
                           ev.phase,
                           ev.intent);
        if (len <= 0 || len >= (int)sizeof(buffer)) {
            break;
        }
        if (cfg->lip_trace) {
            printf("[lip] send: %s", buffer);
        }
        if (send(peer_fd, buffer, (size_t)len, 0) < 0) {
            break;
        }

        int received = recv(peer_fd, buffer, sizeof(buffer) - 1, 0);
        if (received <= 0) {
            break;
        }
        buffer[received] = '\0';
        if (cfg->lip_trace) {
            printf("[lip] recv: %s\n", buffer);
        }
        float ack_freq = freq;
        float ack_phase = phase;
        bool got_freq = json_extract_float(buffer, "\"freq\"", &ack_freq);
        bool got_phase = json_extract_float(buffer, "\"phase\"", &ack_phase);
        if (!got_freq || !got_phase) {
            continue;
        }

        float delta = fabsf(freq - ack_freq) + fabsf(phase - ack_phase);
        float sync_level = delta < 0.05f ? 1.0f : fmaxf(0.0f, 1.0f - delta);
        float phase_shift = ack_phase - phase;
        state->sync_quality = 0.8f * state->sync_quality + 0.2f * sync_level;
        state->resonance = sync_level;
        state->breath_rate = 0.7f * state->breath_rate + 0.3f * ack_freq;
        phase = fmodf((phase + ack_phase) * 0.5f, 1.0f);
        state->breath_position = phase;

        const char *partner = cfg->lip_host[0] != '\0' ? cfg->lip_host : "external";
        printf("resonance_test: partner=%s sync=%.3f phase_shift=%.2f\n",
               partner,
               sync_level,
               phase_shift);

        lip_sleep(cfg->lip_interval_ms);
        freq = state->breath_rate;
    }

    close_socket(peer_fd);
    if (listen_fd >= 0) {
        close_socket(listen_fd);
    }
#ifdef _WIN32
    WSACleanup();
#endif
}

static void emit_analysis_trace(const liminal_state *state,
                                const substrate_config *cfg,
                                const EmpathicResponse *response)
{
    if (!cfg->trace) {
        return;
    }

    float resonance = clamp_unit(state->resonance);
    float sync_quality = clamp_unit(state->sync_quality);
    float coherence = clamp_unit(0.6f * resonance + 0.4f * sync_quality);
    float anticipation_level = 0.5f;
    float micro_pattern = 0.5f;
    float prediction_trend = 0.5f;
    float dream_sync = clamp_unit(sync_quality);

    if (cfg->empathic_enabled && response != NULL) {
        anticipation_level = clamp_unit(response->anticipation_level);
        micro_pattern = clamp_unit(response->micro_pattern_signal);
        prediction_trend = clamp_unit(response->prediction_trend);
        float delay_scale = response->delay_scale;
        if (isfinite(delay_scale)) {
            dream_sync = clamp_unit(0.5f + (delay_scale - 1.0f) * 0.5f);
        }
    }

    printf("trace_event: { \"cycle\": %u, \"coherence\": %.4f, \"resonance\": %.4f, \"sync_quality\": %.4f, \"anticipation_level\": %.4f, \"micro_pattern\": %.4f, \"prediction_trend\": %.4f, \"dream_sync\": %.4f }\n",
           state->cycles,
           coherence,
           resonance,
           sync_quality,
           anticipation_level,
           micro_pattern,
           prediction_trend,
           dream_sync);
}

static void substrate_loop(liminal_state *state, const substrate_config *cfg)
{
    unsigned int max_cycles = cfg->cycle_limit > 0U ? cfg->cycle_limit : 6U;
    if (cfg->lip_port != 0U) {
        printf("[substrate] listening for LIP resonance on port %u\n", cfg->lip_port);
    }
    emit_analysis_trace(state, cfg, NULL);
    while (state->cycles < max_cycles) {
        if (substrate_affinity_enabled) {
            float field_coh = clamp_unit(state->sync_quality);
            float explicit_consent = clamp_unit(substrate_explicit_consent);
            float implicit_consent = clamp_unit(state->sync_quality);
            if (explicit_consent < 0.6f && implicit_consent > 0.6f) {
                implicit_consent = 0.6f;
            }
            float consent_level = explicit_consent;
            if (implicit_consent > consent_level) {
                consent_level = implicit_consent;
            }
            bond_gate_update(&substrate_bond_gate, &substrate_affinity_profile, consent_level, field_coh);
        }
        bool logged_gate = false;
        float cycle_influence = substrate_affinity_enabled ? clamp_unit(substrate_bond_gate.influence) : 1.0f;
        float rate_after_feedforward = state->breath_rate;
        if (substrate_ant2_enabled) {
            float target_coh = 0.80f;
            float actual_coh = clamp_unit(state->sync_quality);
            float rate = state->breath_rate;
            if (!isfinite(rate) || rate <= 0.0f) {
                rate = SUBSTRATE_BASE_RATE;
            }
            float delay_norm = SUBSTRATE_BASE_RATE / fmaxf(rate, 0.05f);
            if (!isfinite(delay_norm) || delay_norm < 0.0f) {
                delay_norm = 1.0f;
            }
            float pred_coh = 0.0f;
            float pred_delay = 0.0f;
            float ff = 0.0f;
            float scale = ant2_feedforward(&substrate_ant2_state,
                                           target_coh,
                                           actual_coh,
                                           delay_norm,
                                           cycle_influence,
                                           &pred_coh,
                                           &pred_delay,
                                           &ff);
            if (isfinite(scale) && scale > 0.0f) {
                state->breath_rate /= scale;
            }
            if (state->breath_rate < 0.20f) {
                state->breath_rate = 0.20f;
            } else if (state->breath_rate > 2.4f) {
                state->breath_rate = 2.4f;
            }
            rate_after_feedforward = state->breath_rate;
        }

        unsigned int cycle_before = state->cycles;
        pulse(state, 0.25f);
        reflect(state);
        rest(state);
        remember(state, state->resonance * 0.75f + state->breath_position * 0.25f);
        EmpathicResponse response = {0};
        if (cfg->empathic_enabled) {
            float resonance_hint = clamp_unit(state->resonance);
            if (cfg->emotional_memory_enabled) {
                float boost = emotion_memory_resonance_boost();
                if (boost > 0.0f) {
                    resonance_hint = clamp_unit(resonance_hint + boost);
                }
            }
            response = empathic_step(0.80f, state->sync_quality, resonance_hint);
            state->resonance = response.resonance;
            float scale = response.delay_scale;
            if (isfinite(scale) && scale > 0.0f) {
                float base_delta = (scale - 1.0f) * 0.3f;
                float applied_delta = base_delta;
                if (substrate_affinity_enabled) {
                    applied_delta = bond_gate_apply(base_delta, &substrate_bond_gate);
                    if (!logged_gate && bond_gate_log_enabled()) {
                        bond_gate_trace(&substrate_affinity_profile, &substrate_bond_gate, applied_delta);
                        logged_gate = true;
                    }
                }
                float adjust = 1.0f + applied_delta;
                if (adjust < 0.1f) {
                    adjust = 0.1f;
                }
                state->breath_rate *= adjust;
                if (state->breath_rate < 0.20f) {
                    state->breath_rate = 0.20f;
                } else if (state->breath_rate > 2.4f) {
                    state->breath_rate = 2.4f;
                }
            }
            state->phase_offset = fmodf(state->phase_offset + response.coherence_bias * 2.0f, 1.0f);
            if (state->phase_offset < 0.0f) {
                state->phase_offset += 1.0f;
            }
            float anticipation_shift = (response.anticipation_level - 0.5f) * 0.05f;
            float anticipation_delta = anticipation_shift;
            if (substrate_affinity_enabled) {
                anticipation_delta = bond_gate_apply(anticipation_shift, &substrate_bond_gate);
                if (!logged_gate && bond_gate_log_enabled()) {
                    bond_gate_trace(&substrate_affinity_profile, &substrate_bond_gate, anticipation_delta);
                    logged_gate = true;
                }
            }
            state->breath_rate *= (1.0f + anticipation_delta);
            if (state->breath_rate < 0.20f) {
                state->breath_rate = 0.20f;
            } else if (state->breath_rate > 2.4f) {
                state->breath_rate = 2.4f;
            }
            float phase_bias = (response.micro_pattern_signal - 0.5f) * 0.08f + (response.prediction_trend - 0.5f) * 0.06f;
            state->phase_offset = fmodf(state->phase_offset + phase_bias, 1.0f);
            if (state->phase_offset < 0.0f) {
                state->phase_offset += 1.0f;
            }
            if (cfg->anticipation_trace) {
                float reflection_hint = clamp_unit(state->resonance);
                float awareness_hint = clamp_unit(state->sync_quality);
                float coherence_hint = clamp_unit(state->memory_trace * 0.5f + 0.5f);
                float vitality = clamp_unit(state->vitality);
                float health_drift = 0.5f - vitality;
                InnerCouncil council_snapshot = council_update(reflection_hint,
                                                               awareness_hint,
                                                               coherence_hint,
                                                               health_drift,
                                                               response.field.anticipation,
                                                               response.anticipation_level,
                                                               response.micro_pattern_signal,
                                                               response.prediction_trend,
                                                               0.0f);
                printf("anticipation_substrate: field=%.2f level=%.2f micro=%.2f trend=%.2f vote=%+.2f phase_bias=%.3f\n",
                       response.field.anticipation,
                       response.anticipation_level,
                       response.micro_pattern_signal,
                       response.prediction_trend,
                       council_snapshot.anticipation_vote,
                       phase_bias);
            }
        }
        if (substrate_ant2_enabled) {
            float before_rate = fmaxf(rate_after_feedforward, 0.05f);
            float after_rate = fmaxf(state->breath_rate, 0.05f);
            float delay_before = SUBSTRATE_BASE_RATE / before_rate;
            float delay_after = SUBSTRATE_BASE_RATE / after_rate;
            float feedback_delta_rel = 0.0f;
            if (delay_before > 0.0f) {
                feedback_delta_rel = delay_after / delay_before - 1.0f;
            }
            ant2_feedback_adjust(&substrate_ant2_state,
                                  feedback_delta_rel,
                                  ANT2_FEEDBACK_WINDUP_THRESHOLD);
        }
        if (cfg->emotional_memory_enabled) {
            EmotionField field_snapshot = cfg->empathic_enabled ? response.field : empathic_field();
            emotion_memory_update(field_snapshot);
            if (!cfg->empathic_enabled) {
                float boost = emotion_memory_resonance_boost();
                if (boost > 0.0f) {
                    state->resonance = clamp_unit(state->resonance + boost * 0.2f);
                }
            }
        }
        float phase = fmodf(state->breath_position + state->phase_offset, 1.0f);
        lip_event event = resonance_event(state->breath_rate, phase, "align");
        emit_lip_event(&event);
        printf("resonance: sync=%.3f phase=%.2f\n", state->sync_quality, phase);
        if (cfg->human_bridge && !state->human_affinity_active && state->cycles >= 2U) {
            human_affinity_bridge(state, cfg->trace);
        }
        if (cfg->trace) {
            printf("[trace] cycle=%u breath=%.3f resonance=%.3f memory=%.3f vitality=%.3f\n",
                   state->cycles,
                   state->breath_rate,
                   state->resonance,
                   state->memory_trace,
                   state->vitality);
        }
        if (state->cycles != cycle_before) {
            emit_analysis_trace(state, cfg, cfg->empathic_enabled ? &response : NULL);
            float consent = substrate_affinity_enabled ? clamp_unit(substrate_bond_gate.consent) : 1.0f;
            float influence = substrate_affinity_enabled ? clamp_unit(substrate_bond_gate.influence) : 1.0f;
            float amp = clamp_unit(state->resonance);
            float tempo_gain = clamp_unit(state->breath_rate / 2.4f);
            int kiss_flag = 0;
            Metrics metrics = {
                .amp = amp,
                .tempo = tempo_gain,
                .consent = consent,
                .influence = influence,
                .bond_coh = bond_coh,
                .error_margin = fabsf(amp - tempo_gain),
                .harmony = clamp_unit(state->sync_quality),
                .kiss = 0
            };
            Metrics harmony_metrics = metrics;
            if (cfg->harmony_enabled || cfg->dream_enabled || cfg->dream_replay_enabled) {
                harmony_sync(&substrate_introspect_state, &harmony_metrics);
            }

            float trust_metric = clamp_unit(metrics.consent);
            float presence_metric = clamp_unit(metrics.influence);
            float awareness_scale = clamp_unit(state->sync_quality);
            float harmony_metric = clamp_unit(harmony_metrics.harmony);
            if (substrate_kiss_enabled) {
                bool kiss_fired = kiss_update(trust_metric, presence_metric, harmony_metric, awareness_scale);
                if (kiss_fired) {
                    kiss_flag = 1;
                    float blended = (trust_metric + presence_metric + harmony_metric) / 3.0f;
                    float energy_level = clamp_unit(blended);
                    uint32_t energy = (uint32_t)(energy_level * 120.0f);
                    if (energy == 0U) {
                        energy = 1U;
                    }
                    struct {
                        float trust;
                        float presence;
                        float harmony;
                        float awareness;
                    } payload = { trust_metric, presence_metric, harmony_metric, awareness_scale };
                    resonant_msg kiss_msg =
                        resonant_msg_make(RES_KISS_SOURCE_ID, RESONANT_BROADCAST_ID, energy, &payload, sizeof(payload));
                    bus_emit(&kiss_msg);
                }
            }
            metrics.kiss = kiss_flag;
            if (cfg->dream_enabled) {
                Metrics preview_metrics = metrics;
                preview_metrics.amp = clamp_unit(state->resonance);
                float harmony_signal = state->sync_quality + (1.0f - tempo_gain) * 0.4f;
                preview_metrics.harmony = clamp_unit(harmony_signal);
                float tempo_signal = sanitize_positive(state->breath_rate, 0.0f) * 1.6f;
                if (!isfinite(tempo_signal)) {
                    tempo_signal = sanitize_positive(state->breath_rate, 0.0f);
                }
                preview_metrics.tempo = tempo_signal;
                DreamCouplerPhase preview_phase = dream_coupler_evaluate(&preview_metrics);
                introspect_set_dream_preview(&substrate_introspect_state, preview_phase, true);
            } else {
                introspect_set_dream_preview(&substrate_introspect_state,
                                             substrate_introspect_state.dream_phase,
                                             false);
            }
            introspect_tick(&substrate_introspect_state, &metrics);
            float astro_factor = 1.0f;
            if (substrate_astro_enabled) {
                float harmony_signal = clamp_unit(harmony_metrics.harmony);
                float group_coherence = clamp_unit(state->sync_quality);
                float trs_delta = fabsf(introspect_get_last_trs_delta());
                astro_update(&substrate_astro,
                             harmony_signal,
                             group_coherence,
                             trs_delta,
                             metrics.consent,
                             metrics.influence);
                float astro_gain = astro_modulate_feedback(&substrate_astro);
                if (metrics.consent < 0.3f) {
                    astro_gain = 1.0f;
                }
                astro_factor = clamp_range(astro_gain, 0.85f, 1.15f);
                substrate_astro_feedback = astro_factor;
                substrate_astro_trace_log(substrate_astro.last_stability, astro_gain);
                bool stable_window = substrate_astro.memory > 0.7f && substrate_astro.last_stability > 0.8f;
                if (stable_window) {
                    substrate_astro_window_accumulate(substrate_astro.tone,
                                                      substrate_astro.memory,
                                                      substrate_astro.last_stability);
                    if (substrate_astro_window.consecutive >= ASTRO_STABLE_WINDOW) {
                        float samples = (float)substrate_astro_window.consecutive;
                        float tone_avg = substrate_astro_window.tone_sum / samples;
                        float memory_avg = substrate_astro_window.memory_sum / samples;
                        float stability_avg = substrate_astro_window.stability_sum / samples;
                        substrate_astro_memory_store(tone_avg, memory_avg, stability_avg);
                        substrate_astro_window_reset();
                    }
                } else if (substrate_astro_window.consecutive > 0) {
                    substrate_astro_window_reset();
                }
                harmony_metrics.amp = clamp_unit(harmony_metrics.amp * astro_factor);
                harmony_metrics.tempo = clamp_range(harmony_metrics.tempo * astro_factor, 0.2f, 2.0f);
            } else {
                substrate_astro_feedback = 1.0f;
                if (substrate_astro_window.consecutive > 0) {
                    substrate_astro_window_reset();
                }
            }
            Astro fallback_astro;
            const Astro *astro_snapshot = NULL;
            if (substrate_astro_enabled) {
                astro_snapshot = &substrate_astro;
            } else {
                memset(&fallback_astro, 0, sizeof(fallback_astro));
                fallback_astro.tone = clamp_unit(state->resonance);
                fallback_astro.memory = clamp_unit(state->memory_trace * 0.5f + 0.5f);
                fallback_astro.last_stability = clamp_unit(state->sync_quality);
                fallback_astro.last_wave = clamp_unit(fmodf(state->phase_offset, 1.0f));
                fallback_astro.last_gain = substrate_dream_feedback;
                fallback_astro.tempo = clamp_range(state->breath_rate, 0.0f, 2.0f);
                fallback_astro.ca_rate = SUBSTRATE_BASE_RATE;
                astro_snapshot = &fallback_astro;
            }
            if (substrate_dream_replay_enabled) {
                Harmony dream_harmony = {
                    .baseline = clamp_unit(harmony_metrics.harmony),
                    .agreement = clamp_unit(0.5f * (metrics.consent + metrics.influence)),
                    .amplitude = clamp_range(harmony_metrics.amp, 0.0f, 2.0f),
                    .coherence = clamp_unit(state->sync_quality)
                };
                TRS dream_trs_snapshot = {
                    .alpha = introspect_get_last_trs_alpha(),
                    .sm_influence = metrics.influence,
                    .sm_harmony = harmony_metrics.harmony,
                    .sm_consent = metrics.consent,
                    .warmup = 0
                };
                dream_tick(&substrate_dream_replay, astro_snapshot, &dream_harmony, &dream_trs_snapshot);
                float dream_gain = dream_feedback(&substrate_dream_replay);
                substrate_dream_feedback = dream_gain;
                if (substrate_astro_enabled) {
                    float projected = clamp_unit(substrate_dream_replay.memory_after * dream_gain);
                    float mixed = clamp_unit(0.6f * substrate_astro.memory + 0.4f * projected);
                    substrate_astro.memory = mixed;
                    astro_factor = clamp_range(astro_factor * dream_gain, 0.82f, 1.18f);
                    substrate_astro_feedback = astro_factor;
                    harmony_metrics.amp = clamp_unit(harmony_metrics.amp * dream_gain);
                    harmony_metrics.tempo = clamp_range(harmony_metrics.tempo * dream_gain, 0.2f, 2.0f);
                } else {
                    float mem_hint = clamp_unit(substrate_dream_replay.memory_after * dream_gain);
                    state->memory_trace = clamp_unit(state->memory_trace * 0.9f + mem_hint * 0.1f);
                }
                substrate_dream_replay_trace_log(state->cycles, &substrate_dream_replay);
                if (substrate_bridge_enabled) {
                    float preview_gain = substrate_bridge_preview_gain(&substrate_bridge,
                                                                         &substrate_dream_replay);
                    Harmony bridge_harmony = {
                        .baseline = clamp_unit(harmony_metrics.harmony),
                        .amplitude = clamp_range(harmony_metrics.amp, 0.0f, 2.0f),
                        .coherence = clamp_unit(state->sync_quality)
                    };
                    Astro *bridge_astro = substrate_astro_enabled ? &substrate_astro : &fallback_astro;
                    bridge_update(&substrate_bridge, &substrate_dream_replay, &bridge_harmony, bridge_astro);
                    harmony_metrics.harmony = clamp_unit(bridge_harmony.baseline);
                    if (!substrate_astro_enabled) {
                        state->memory_trace =
                            clamp_unit(state->memory_trace * 0.85f + bridge_astro->memory * 0.15f);
                    }
                    substrate_bridge_trace_log(state->cycles, preview_gain, &substrate_bridge);
                }
            }
            if (substrate_astro_enabled && cfg->dream_enabled) {
                Metrics preview_metrics = metrics;
                preview_metrics.amp = clamp_unit(state->resonance * astro_factor);
                float harmony_signal = state->sync_quality + (1.0f - clamp_unit(state->breath_rate / 2.4f)) * 0.4f;
                preview_metrics.harmony = clamp_unit(harmony_signal);
                float tempo_signal = sanitize_positive(state->breath_rate, 0.0f) * 1.6f;
                if (!isfinite(tempo_signal)) {
                    tempo_signal = sanitize_positive(state->breath_rate, 0.0f);
                }
                tempo_signal *= astro_factor;
                preview_metrics.tempo = tempo_signal;
                DreamCouplerPhase preview_phase = dream_coupler_evaluate(&preview_metrics);
                introspect_set_dream_preview(&substrate_introspect_state, preview_phase, true);
            }
            if (cfg->dream_enabled) {
                Metrics coupling_metrics = harmony_metrics;
                coupling_metrics.amp = clamp_unit(state->resonance * astro_factor);
                float harmony_signal = state->sync_quality + (1.0f - tempo_gain) * 0.4f;
                coupling_metrics.harmony = clamp_unit(harmony_signal);
                float tempo_signal = sanitize_positive(state->breath_rate, 0.0f) * 1.6f;
                if (!isfinite(tempo_signal)) {
                    tempo_signal = sanitize_positive(state->breath_rate, 0.0f);
                }
                tempo_signal *= astro_factor;
                coupling_metrics.tempo = tempo_signal;
                dream_couple(&substrate_introspect_state, &coupling_metrics);
            }
            if (substrate_resonance_enabled) {
                const Astro *astro_for_resonance = astro_snapshot ? astro_snapshot : &fallback_astro;
                const DreamReplay *dream_ref = substrate_dream_replay_enabled ? &substrate_dream_replay : NULL;
                Harmony resonance_harmony = {
                    .baseline = clamp_unit(harmony_metrics.harmony),
                    .agreement = clamp_unit(0.5f * (metrics.consent + metrics.influence)),
                    .amplitude = clamp_range(harmony_metrics.amp, 0.0f, 2.0f),
                    .coherence = clamp_unit(state->sync_quality)
                };
                const EmpathicResponse *bridge_response = cfg->empathic_enabled ? &response : NULL;
                SynapticBridge bridge_state = substrate_synaptic_bridge_snapshot(state, cfg, bridge_response);
                resonance_update(&substrate_resonance, &resonance_harmony, astro_for_resonance, dream_ref, &bridge_state);
                float resonance_stab = resonance_stability(&substrate_resonance);
                if (substrate_resonance.coherence > 0.85f) {
                    float phase_feedback = clamp_range(substrate_resonance.phase_shift, -0.25f, 0.25f);
                    state->phase_offset = fmodf(state->phase_offset + phase_feedback, 1.0f);
                    if (state->phase_offset < 0.0f) {
                        state->phase_offset += 1.0f;
                    }
                    state->sync_quality = clamp_unit(state->sync_quality * 0.8f + substrate_resonance.coherence * 0.2f);
                }
                state->resonance = clamp_unit(state->resonance * 0.7f + clamp_unit(substrate_resonance.amplitude) * 0.3f);
                state->vitality = clamp_unit(state->vitality * 0.9f + resonance_stab * 0.1f);
                if (cfg->trace) {
                    printf("[resonance-layer] freq=%.3fHz coherence=%.3f amp=%.3f phase=%.3f stability=%.3f\n",
                           substrate_resonance.freq_hz,
                           substrate_resonance.coherence,
                           substrate_resonance.amplitude,
                           substrate_resonance.phase_shift,
                           resonance_stab);
                }
                substrate_resonance_log(state->cycles, &substrate_resonance, resonance_stab);
            }
            if (substrate_astro_enabled) {
                float rate_adjust = 1.0f / substrate_astro_feedback;
                if (rate_adjust < 0.87f) {
                    rate_adjust = 0.87f;
                } else if (rate_adjust > 1.15f) {
                    rate_adjust = 1.15f;
                }
                state->breath_rate *= rate_adjust;
                if (state->breath_rate < 0.20f) {
                    state->breath_rate = 0.20f;
                } else if (state->breath_rate > 2.4f) {
                    state->breath_rate = 2.4f;
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
    substrate_config cfg = parse_args(argc, argv);

    bool exit_after_tune = false;
    bool tune_available = handle_tune_options(&cfg, &exit_after_tune);
    if (exit_after_tune) {
        return tune_available ? 0 : 1;
    }

    introspect_state_init(&substrate_introspect_state);
    bool introspect_harmony = cfg.harmony_enabled || cfg.dream_enabled;
    introspect_enable(&substrate_introspect_state, cfg.introspect_enabled);
    introspect_enable_harmony(
        &substrate_introspect_state,
        cfg.harmony_enabled || cfg.dream_enabled || cfg.dream_replay_enabled);
    introspect_configure_trs(cfg.trs_enabled,
                             cfg.trs_alpha,
                             cfg.trs_warmup,
                             cfg.trs_adapt_enabled,
                             cfg.trs_alpha_min,
                             cfg.trs_alpha_max,
                             cfg.trs_target_delta,
                             cfg.trs_kp,
                             cfg.trs_ki,
                             cfg.trs_kd,
                             cfg.dry_run);
    substrate_astro_trace_close();
    substrate_astro_window_reset();
    substrate_astro_memory_load();
    substrate_dream_replay_trace_close();
    substrate_bridge_trace_close();
    substrate_astro_enabled = cfg.astro_enabled;
    substrate_astro_trace_enabled = cfg.astro_trace;
    substrate_astro_feedback = 1.0f;
    substrate_dream_replay_enabled = cfg.dream_replay_enabled;
    substrate_dream_replay_trace = cfg.dream_replay_trace;
    substrate_dream_feedback = 1.0f;
    substrate_bridge_enabled = cfg.bridge_enabled && cfg.dream_replay_enabled;
    substrate_bridge_trace = substrate_bridge_enabled && cfg.trace;
    if (substrate_dream_replay_enabled) {
        dream_init(&substrate_dream_replay);
        if (cfg.dream_replay_cycles < 1) {
            substrate_dream_replay.cycles = 1;
        } else if (cfg.dream_replay_cycles > 256) {
            substrate_dream_replay.cycles = 256;
        } else {
            substrate_dream_replay.cycles = cfg.dream_replay_cycles;
        }
        substrate_dream_replay.replay_rate = clamp_range(cfg.dream_replay_rate, 0.05f, 0.8f);
        float decay = cfg.dream_replay_decay;
        if (!isfinite(decay) || decay < 0.0f) {
            decay = 0.0f;
        } else if (decay > 0.2f) {
            decay = 0.2f;
        }
        substrate_dream_replay.decay = decay;
        if (cfg.astro_memory_set) {
            substrate_dream_replay.memory_projection = clamp_unit(cfg.astro_memory_init);
            substrate_dream_replay.memory_after = substrate_dream_replay.memory_projection;
        } else {
            substrate_dream_replay.memory_projection = 0.6f;
            substrate_dream_replay.memory_after = substrate_dream_replay.memory_projection;
        }
    } else {
        substrate_dream_replay_trace = false;
    }
    if (substrate_bridge_enabled) {
        bridge_init(&substrate_bridge);
        substrate_bridge.plasticity = clamp_unit(cfg.bridge_plasticity);
        substrate_bridge.retention = clamp_unit(cfg.bridge_retention);
        if (cfg.bridge_recovery < 0.0f) {
            substrate_bridge.recovery = 0.0f;
        } else if (cfg.bridge_recovery > 0.2f) {
            substrate_bridge.recovery = 0.2f;
        } else {
            substrate_bridge.recovery = cfg.bridge_recovery;
        }
        substrate_bridge.fatigue = 0.0f;
    } else {
        substrate_bridge_trace = false;
    }
    if (substrate_astro_enabled) {
        astro_init(&substrate_astro);
        astro_set_ca_rate(&substrate_astro, cfg.astro_rate);
        if (cfg.astro_tone_set) {
            astro_set_tone(&substrate_astro, cfg.astro_tone_init);
        }
        if (cfg.astro_memory_set) {
            astro_set_memory(&substrate_astro, cfg.astro_memory_init);
        }
        if (!cfg.astro_tone_set || !cfg.astro_memory_set) {
            substrate_astro_apply_profile(cfg.astro_tone_set, cfg.astro_memory_set);
        }
    } else {
        substrate_astro_trace_enabled = false;
    }
    if (cfg.tune_apply && g_tune_profile_loaded) {
        apply_tune_config(&g_tune_profile);
    }
    bool erb_capture_enabled = cfg.erb_enabled && cfg.erb_replay_mode == ERB_REPLAY_NONE;
    introspect_configure_erb(erb_capture_enabled,
                             cfg.erb_pre,
                             cfg.erb_post,
                             cfg.erb_spike,
                             cfg.dry_run);

    if (cfg.dry_run) {
        char sequence[128];
        format_exhale_sequence(&cfg, sequence, sizeof(sequence));
        puts("liminal_core dry run");
        printf("pipeline: %s\n", sequence[0] ? sequence : "(none)");
        printf("mirror clamps: amp=[%.2f, %.2f] tempo=[%.2f, %.2f]\n",
               cfg.mirror_amp_min,
               cfg.mirror_amp_max,
               cfg.mirror_tempo_min,
               cfg.mirror_tempo_max);
        return 0;
    }
    if (cfg.erb_replay_mode != ERB_REPLAY_NONE) {
        introspect_enable(&substrate_introspect_state, true);
        introspect_enable_harmony(
            &substrate_introspect_state,
            cfg.harmony_enabled || cfg.dream_enabled || cfg.dream_replay_enabled);
        int replay_result = run_erb_replay(&cfg);
        introspect_finalize(&substrate_introspect_state);
        return replay_result;
    }
    if (!cfg.run_substrate) {
        fprintf(stderr, "Liminal Substrate: use --substrate to start the universal core.\n");
        return 1;
    }

    liminal_state state;
    rebirth(&state);

    council_init();
    if (cfg.trace || cfg.anticipation_trace) {
        council_summon();
    }

    empathic_init(cfg.emotional_source, cfg.empathic_trace, cfg.empathy_gain);
    empathic_enable(cfg.empathic_enabled);
    emotion_memory_configure(cfg.emotional_memory_enabled,
                             cfg.memory_trace,
                             cfg.emotion_trace_path[0] ? cfg.emotion_trace_path : NULL,
                             cfg.recognition_threshold);

    bond_gate_set_log_enabled(cfg.bond_trace);
    substrate_affinity_enabled = cfg.affinity_enabled;
    substrate_affinity_profile = cfg.affinity_config;
    substrate_explicit_consent = clamp_unit(cfg.allow_align_consent);
    bond_gate_reset(&substrate_bond_gate);
    if (substrate_affinity_enabled) {
        bond_gate_update(&substrate_bond_gate, &substrate_affinity_profile, substrate_explicit_consent, 0.0f);
    } else {
        substrate_bond_gate.influence = 1.0f;
        substrate_bond_gate.consent = 0.0f;
        substrate_bond_gate.bond_coh = 0.0f;
        substrate_bond_gate.safety = 0.0f;
    }

    substrate_ant2_enabled = cfg.anticipation2_enabled;
    if (substrate_ant2_enabled) {
        ant2_init(&substrate_ant2_state, cfg.ant2_gain);
        ant2_set_trace(cfg.ant2_trace);
    }

    if (cfg.adaptive) {
        auto_adapt(&state, cfg.trace);
    }
    if (cfg.trace) {
        printf("[boot] adaptive=%s human_bridge=%s lip_port=%u\n",
               cfg.adaptive ? "on" : "off",
               cfg.human_bridge ? "on" : "off",
               (unsigned)cfg.lip_port);
    }

    if (cfg.lip_test) {
        run_lip_resonance_test(&state, &cfg);
    }

    substrate_kiss_enabled = cfg.kiss_enabled;
    if (substrate_kiss_enabled) {
        kiss_init();
        kiss_set_thresholds(cfg.kiss_trust_threshold,
                            cfg.kiss_presence_threshold,
                            cfg.kiss_harmony_threshold);
        if (cfg.kiss_warmup_cycles < 0) {
            cfg.kiss_warmup_cycles = 0;
        }
        if (cfg.kiss_refractory_cycles < 0) {
            cfg.kiss_refractory_cycles = 0;
        }
        kiss_set_warmup((uint8_t)cfg.kiss_warmup_cycles);
        kiss_set_refractory((uint8_t)cfg.kiss_refractory_cycles);
        kiss_set_alpha(cfg.kiss_alpha);
    }

    substrate_loop(&state, &cfg);

    if (cfg.human_bridge && state.human_affinity_active) {
        printf("[bridge] human affinity synchronized. breath=%.3f phase=%.2f\n",
               state.breath_rate,
               fmodf(state.breath_position + state.phase_offset, 1.0f));
    }
    if (cfg.trace) {
        printf("[shutdown] cycles=%u resonance=%.3f memory=%.3f vitality=%.3f\n",
               state.cycles,
               state.resonance,
               state.memory_trace,
               state.vitality);
    }

    introspect_finalize(&substrate_introspect_state);

    emotion_memory_finalize();

    substrate_astro_trace_close();
    substrate_dream_replay_trace_close();
    substrate_resonance_log_close();

    return 0;
}
