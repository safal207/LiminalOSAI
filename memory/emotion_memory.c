#include "emotion_memory.h"

#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef EMOTION_MEMORY_PATH_MAX
#define EMOTION_MEMORY_PATH_MAX 256
#endif

#ifndef EMOTION_RESONANCE_MIN
#define EMOTION_RESONANCE_MIN 0.03f
#endif

#ifndef EMOTION_RESONANCE_MAX
#define EMOTION_RESONANCE_MAX 0.05f
#endif

typedef struct {
    bool enabled;
    bool trace_enabled;
    bool session_active;
    bool recognized;
    bool announced_once;
    bool dirty;
    float recognition_threshold;
    float resonance_boost;
    float last_distance;
    size_t session_updates;
    EmotionTrace current;
    EmotionTrace recognized_trace;
    EmotionTrace *known;
    size_t known_count;
    size_t known_capacity;
    char storage_path[EMOTION_MEMORY_PATH_MAX];
} emotion_memory_state;

static emotion_memory_state g_memory = {0};

static void compute_signature_from_trace(EmotionTrace *trace);

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

static uint64_t current_timestamp(void)
{
    struct timespec ts;
#if defined(CLOCK_REALTIME)
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        ts.tv_sec = time(NULL);
        ts.tv_nsec = 0;
    }
#else
    ts.tv_sec = time(NULL);
    ts.tv_nsec = 0;
#endif
    return (uint64_t)ts.tv_sec;
}

static void clear_known(void)
{
    if (g_memory.known) {
        free(g_memory.known);
        g_memory.known = NULL;
    }
    g_memory.known_count = 0;
    g_memory.known_capacity = 0;
}

static void ensure_capacity(size_t needed)
{
    if (needed <= g_memory.known_capacity) {
        return;
    }
    size_t new_capacity = g_memory.known_capacity ? g_memory.known_capacity * 2 : 8;
    while (new_capacity < needed) {
        new_capacity *= 2;
    }
    EmotionTrace *resized = (EmotionTrace *)realloc(g_memory.known, new_capacity * sizeof(EmotionTrace));
    if (!resized) {
        return;
    }
    g_memory.known = resized;
    g_memory.known_capacity = new_capacity;
}

static void push_known(const EmotionTrace *trace)
{
    if (!trace) {
        return;
    }
    ensure_capacity(g_memory.known_count + 1);
    if (g_memory.known_count < g_memory.known_capacity) {
        g_memory.known[g_memory.known_count++] = *trace;
    }
}

static bool parse_string_field(const char *line, const char *key, char *out, size_t out_size)
{
    if (!line || !key || !out || out_size == 0) {
        return false;
    }
    const char *pos = strstr(line, key);
    if (!pos) {
        return false;
    }
    pos = strchr(pos + strlen(key), ':');
    if (!pos) {
        return false;
    }
    ++pos;
    while (*pos == ' ' || *pos == '\t') {
        ++pos;
    }
    if (*pos != '"') {
        return false;
    }
    ++pos;
    size_t len = 0;
    while (pos[len] != '\0' && pos[len] != '"') {
        if (len + 1 < out_size) {
            out[len] = pos[len];
        }
        ++len;
    }
    if (len >= out_size) {
        len = out_size - 1;
    }
    out[len] = '\0';
    return true;
}

static bool parse_float_field(const char *line, const char *key, float *out)
{
    if (!line || !key || !out) {
        return false;
    }
    const char *pos = strstr(line, key);
    if (!pos) {
        return false;
    }
    pos = strchr(pos + strlen(key), ':');
    if (!pos) {
        return false;
    }
    ++pos;
    while (*pos == ' ' || *pos == '\t' || *pos == '"') {
        ++pos;
    }
    errno = 0;
    char *end = NULL;
    float value = strtof(pos, &end);
    if (end == pos || errno != 0) {
        return false;
    }
    *out = value;
    return true;
}

static bool parse_u64_field(const char *line, const char *key, uint64_t *out)
{
    if (!line || !key || !out) {
        return false;
    }
    const char *pos = strstr(line, key);
    if (!pos) {
        return false;
    }
    pos = strchr(pos + strlen(key), ':');
    if (!pos) {
        return false;
    }
    ++pos;
    while (*pos == ' ' || *pos == '\t') {
        ++pos;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(pos, &end, 10);
    if (end == pos || errno != 0) {
        return false;
    }
    *out = (uint64_t)value;
    return true;
}

static bool parse_trace_line(const char *line, EmotionTrace *out)
{
    if (!line || !out) {
        return false;
    }
    EmotionTrace trace;
    memset(&trace, 0, sizeof(trace));
    if (!parse_string_field(line, "\"signature\"", trace.signature, sizeof(trace.signature))) {
        return false;
    }
    if (!parse_float_field(line, "\"warmth\"", &trace.warmth_avg)) {
        return false;
    }
    if (!parse_float_field(line, "\"tension\"", &trace.tension_avg)) {
        return false;
    }
    if (!parse_float_field(line, "\"harmony\"", &trace.harmony_avg)) {
        return false;
    }
    if (!parse_float_field(line, "\"resonance\"", &trace.resonance_avg)) {
        return false;
    }
    if (!parse_float_field(line, "\"anticipation\"", &trace.anticipation_avg)) {
        trace.anticipation_avg = 0.5f;
    }
    if (!parse_u64_field(line, "\"timestamp\"", &trace.timestamp)) {
        trace.timestamp = current_timestamp();
    }
    compute_signature_from_trace(&trace);
    *out = trace;
    return true;
}

static void load_existing(const char *path)
{
    if (!path || !*path) {
        return;
    }
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return;
    }
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        EmotionTrace trace;
        if (parse_trace_line(line, &trace)) {
            push_known(&trace);
        }
    }
    fclose(fp);
}

static uint32_t quantize_component(float value)
{
    float clamped = clamp_unit(value);
    return (uint32_t)lroundf(clamped * 1000.0f);
}

static void compute_signature_from_trace(EmotionTrace *trace)
{
    if (!trace) {
        return;
    }
    uint32_t w = quantize_component(trace->warmth_avg);
    uint32_t t = quantize_component(trace->tension_avg);
    uint32_t h = quantize_component(trace->harmony_avg);
    uint32_t r = quantize_component(trace->resonance_avg);
    uint32_t a = quantize_component(trace->anticipation_avg);
    uint32_t hash1 = 2166136261u;
    uint32_t data[5] = {w, t, h, r, a};
    for (size_t i = 0; i < 5; ++i) {
        uint32_t value = data[i];
        for (int b = 0; b < 4; ++b) {
            uint8_t byte = (uint8_t)((value >> (b * 8)) & 0xFFu);
            hash1 ^= byte;
            hash1 *= 16777619u;
        }
    }
    uint32_t hash2 = 16777619u;
    for (size_t i = 0; i < 5; ++i) {
        hash2 ^= data[i] + (uint32_t)(i * 109u);
        hash2 *= 2166136261u;
    }
    snprintf(trace->signature, sizeof(trace->signature), "%08x%08x", hash1, hash2);
}

static float distance_to_trace(const EmotionTrace *a, const EmotionTrace *b)
{
    if (!a || !b) {
        return 1000.0f;
    }
    float dw = a->warmth_avg - b->warmth_avg;
    float dt = a->tension_avg - b->tension_avg;
    float dh = a->harmony_avg - b->harmony_avg;
    float dr = a->resonance_avg - b->resonance_avg;
    float da = a->anticipation_avg - b->anticipation_avg;
    float sum = dw * dw + dt * dt + dh * dh + dr * dr + da * da;
    if (sum <= 0.0f) {
        return 0.0f;
    }
    return sqrtf(sum);
}

static void announce_state(float best_distance, bool force_echo)
{
    if (!g_memory.session_active) {
        return;
    }
    bool should_echo = force_echo || g_memory.trace_enabled;
    if (!should_echo) {
        return;
    }

    char recognized_flag = g_memory.recognized ? 'Y' : 'N';
    float boost = g_memory.recognized ? g_memory.resonance_boost : 0.0f;
    printf("memory_echo: recognized=%c resonance_boost=+%.2f signature=%s",
           recognized_flag,
           boost,
           g_memory.current.signature);
    if (g_memory.recognized && g_memory.recognized_trace.signature[0] != '\0') {
        printf(" match=%s", g_memory.recognized_trace.signature);
    }
    if (best_distance >= 0.0f && isfinite(best_distance)) {
        printf(" distance=%.3f", best_distance);
    }
    putchar('\n');

    if (g_memory.trace_enabled) {
        printf("memory_trace: warmth=%.3f tension=%.3f harmony=%.3f empathy=%.3f anticipation=%.3f boost=%.3f\n",
               g_memory.current.warmth_avg,
               g_memory.current.tension_avg,
               g_memory.current.harmony_avg,
               g_memory.current.resonance_avg,
               g_memory.current.anticipation_avg,
               boost);
    }

    g_memory.announced_once = true;
}

static void evaluate_recognition(void)
{
    float best_distance = -1.0f;
    EmotionTrace best_match;
    memset(&best_match, 0, sizeof(best_match));
    bool found = false;

    if (g_memory.recognition_threshold > 0.0f && g_memory.known_count > 0) {
        float closest = g_memory.recognition_threshold + 1000.0f;
        for (size_t i = 0; i < g_memory.known_count; ++i) {
            float dist = distance_to_trace(&g_memory.current, &g_memory.known[i]);
            if (strncmp(g_memory.current.signature,
                        g_memory.known[i].signature,
                        sizeof(g_memory.current.signature)) == 0) {
                dist = 0.0f;
            }
            if (dist < closest) {
                closest = dist;
                best_match = g_memory.known[i];
                found = true;
            }
        }
        if (found) {
            best_distance = closest;
        }
    }

    bool previous_recognized = g_memory.recognized;
    if (found && best_distance <= g_memory.recognition_threshold) {
        float closeness = 1.0f;
        if (g_memory.recognition_threshold > 0.0f) {
            closeness = 1.0f - (best_distance / g_memory.recognition_threshold);
            if (closeness < 0.0f) {
                closeness = 0.0f;
            }
        }
        float boost = EMOTION_RESONANCE_MIN + (EMOTION_RESONANCE_MAX - EMOTION_RESONANCE_MIN) * closeness;
        if (boost < EMOTION_RESONANCE_MIN) {
            boost = EMOTION_RESONANCE_MIN;
        }
        if (boost > EMOTION_RESONANCE_MAX) {
            boost = EMOTION_RESONANCE_MAX;
        }
        g_memory.recognized = true;
        g_memory.resonance_boost = boost;
        g_memory.recognized_trace = best_match;
        g_memory.last_distance = best_distance;
    } else {
        g_memory.recognized = false;
        g_memory.resonance_boost = 0.0f;
        memset(&g_memory.recognized_trace, 0, sizeof(g_memory.recognized_trace));
        g_memory.last_distance = best_distance;
    }

    bool force_echo = !g_memory.announced_once || previous_recognized != g_memory.recognized;
    if (g_memory.trace_enabled || force_echo) {
        announce_state(best_distance, force_echo);
    }
}

void emotion_memory_configure(bool enable,
                              bool trace,
                              const char *path,
                              float recognition_threshold)
{
    clear_known();
    memset(&g_memory, 0, sizeof(g_memory));

    g_memory.enabled = enable;
    g_memory.trace_enabled = trace;
    g_memory.recognition_threshold = (recognition_threshold > 0.0f) ? recognition_threshold : 0.18f;
    g_memory.last_distance = -1.0f;
    if (path && *path) {
        strncpy(g_memory.storage_path, path, sizeof(g_memory.storage_path) - 1U);
        g_memory.storage_path[sizeof(g_memory.storage_path) - 1U] = '\0';
    } else {
        strcpy(g_memory.storage_path, "emotion_soil.jsonl");
    }

    if (!enable) {
        return;
    }

    load_existing(g_memory.storage_path);
    if (g_memory.trace_enabled) {
        printf("memory_soil: loaded=%zu threshold=%.2f path=%s\n",
               g_memory.known_count,
               g_memory.recognition_threshold,
               g_memory.storage_path);
    }
}

void emotion_memory_update(EmotionField field)
{
    if (!g_memory.enabled) {
        return;
    }

    if (!g_memory.session_active) {
        memset(&g_memory.current, 0, sizeof(g_memory.current));
        g_memory.current.warmth_avg = clamp_unit(field.warmth);
        g_memory.current.tension_avg = clamp_unit(field.tension);
        g_memory.current.harmony_avg = clamp_unit(field.harmony);
        g_memory.current.resonance_avg = clamp_unit(field.empathy);
        g_memory.current.anticipation_avg = clamp_unit(field.anticipation);
        g_memory.session_active = true;
        g_memory.session_updates = 1;
    } else {
        g_memory.current.warmth_avg = g_memory.current.warmth_avg * 0.8f + clamp_unit(field.warmth) * 0.2f;
        g_memory.current.tension_avg = g_memory.current.tension_avg * 0.8f + clamp_unit(field.tension) * 0.2f;
        g_memory.current.harmony_avg = g_memory.current.harmony_avg * 0.8f + clamp_unit(field.harmony) * 0.2f;
        g_memory.current.resonance_avg = g_memory.current.resonance_avg * 0.8f + clamp_unit(field.empathy) * 0.2f;
        g_memory.current.anticipation_avg = g_memory.current.anticipation_avg * 0.8f + clamp_unit(field.anticipation) * 0.2f;
        ++g_memory.session_updates;
    }

    g_memory.current.timestamp = current_timestamp();
    compute_signature_from_trace(&g_memory.current);
    g_memory.dirty = true;

    evaluate_recognition();
}

bool emotion_memory_recognized(void)
{
    if (!g_memory.enabled) {
        return false;
    }
    return g_memory.recognized;
}

float emotion_memory_resonance_boost(void)
{
    if (!g_memory.enabled) {
        return 0.0f;
    }
    if (!g_memory.recognized) {
        return 0.0f;
    }
    return g_memory.resonance_boost;
}

const EmotionTrace *emotion_memory_last_trace(void)
{
    if (!g_memory.enabled || !g_memory.session_active) {
        return NULL;
    }
    return &g_memory.current;
}

void emotion_memory_finalize(void)
{
    if (!g_memory.enabled || !g_memory.session_active || !g_memory.dirty) {
        clear_known();
        return;
    }

    compute_signature_from_trace(&g_memory.current);
    g_memory.current.timestamp = current_timestamp();

    if (g_memory.storage_path[0] != '\0') {
        FILE *fp = fopen(g_memory.storage_path, "a");
        if (fp) {
            fprintf(fp,
                    "{\"signature\":\"%s\",\"timestamp\":%" PRIu64 ",\"warmth\":%.4f,\"tension\":%.4f,\"harmony\":%.4f,\"resonance\":%.4f,\"anticipation\":%.4f}\n",
                    g_memory.current.signature,
                    g_memory.current.timestamp,
                    g_memory.current.warmth_avg,
                    g_memory.current.tension_avg,
                    g_memory.current.harmony_avg,
                    g_memory.current.resonance_avg,
                    g_memory.current.anticipation_avg);
            fclose(fp);
            push_known(&g_memory.current);
            if (g_memory.trace_enabled) {
                printf("memory_soil: stored signature=%s warmth=%.3f tension=%.3f harmony=%.3f resonance=%.3f anticipation=%.3f\n",
                       g_memory.current.signature,
                       g_memory.current.warmth_avg,
                       g_memory.current.tension_avg,
                       g_memory.current.harmony_avg,
                       g_memory.current.resonance_avg,
                       g_memory.current.anticipation_avg);
            }
        } else if (g_memory.trace_enabled) {
            fprintf(stderr, "memory_soil: failed to write %s\n", g_memory.storage_path);
        }
    }

    g_memory.dirty = false;
    clear_known();
}
