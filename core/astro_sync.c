#include "astro_sync.h"

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

static float clampf(float value, float min_value, float max_value)
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
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

void astro_init(Astro *a)
{
    if (!a) {
        return;
    }
    a->tone = 0.0f;
    a->memory = 0.0f;
    a->drift = 0.0f;
    a->k_tone = 0.03f;
    a->k_relax = 0.01f;
    a->k_mem = 0.02f;
    a->k_decay = 0.015f;
    a->ca_phase = 0.0f;
    a->ca_rate = 0.010f;
    a->tempo = 0.0f;
    a->last_stability = 0.0f;
    a->last_agitation = 0.0f;
    a->last_wave = 0.0f;
    a->last_gain = 1.0f;
}

void astro_set_tone(Astro *a, float tone)
{
    if (!a) {
        return;
    }
    a->tone = clamp_unit(tone);
}

void astro_set_memory(Astro *a, float memory)
{
    if (!a) {
        return;
    }
    a->memory = clamp_unit(memory);
}

void astro_set_ca_rate(Astro *a, float rate)
{
    if (!a) {
        return;
    }
    a->ca_rate = clampf(rate, 0.005f, 0.020f);
}

void astro_update(Astro *a,
                  float harm_sm,
                  float coh_group,
                  float trs_delta,
                  float consent,
                  float influence)
{
    if (!a) {
        return;
    }

    float harmonic = clamp_unit(harm_sm);
    float coherence = clamp_unit(coh_group);
    float consent_norm = clamp_unit(consent);
    float influence_norm = clamp_unit(influence);
    float agitation = clampf(fabsf(trs_delta), 0.0f, 0.5f);

    a->ca_phase = fmodf(a->ca_phase + a->ca_rate, 1.0f);
    if (a->ca_phase < 0.0f) {
        a->ca_phase += 1.0f;
    }
    float ca_wave = 0.5f + 0.5f * sinf(2.0f * (float)M_PI * a->ca_phase);

    float stability = 0.5f * harmonic + 0.5f * coherence;
    stability *= (0.7f + 0.3f * influence_norm);
    stability = clamp_unit(stability);

    float agitation_gate = 1.0f + (1.0f - consent_norm) * 0.2f;
    agitation = clampf(agitation * agitation_gate, 0.0f, 0.5f);

    a->tone += a->k_tone * (stability - a->tone) * (1.0f - agitation);
    a->tone = clamp_unit(a->tone);

    a->drift += 0.5f * (agitation - 0.5f * stability);
    a->drift *= (1.0f - a->k_relax);
    a->drift = clampf(a->drift, -0.35f, 0.35f);

    float mem_gain = a->k_mem * stability * consent_norm * (1.0f - agitation);
    mem_gain *= (0.6f + 0.4f * influence_norm);
    float mem_loss = a->k_decay * (agitation + fmaxf(0.0f, -a->drift));
    a->memory = clamp_unit(a->memory + mem_gain - mem_loss);

    float softness = 0.85f + 0.15f * a->tone;
    float memory_shield = 1.0f - 0.2f * a->memory;
    float ca_breathe = 0.9f + 0.1f * ca_wave;
    float base_gain = softness * memory_shield * ca_breathe;
    base_gain *= (0.9f + 0.1f * consent_norm);
    base_gain = clampf(base_gain, 0.0f, 1.2f);
    float gain = 0.8f + 0.4f * clampf(base_gain, 0.0f, 1.0f);
    gain *= (0.9f + 0.1f * influence_norm);
    gain = clampf(gain, 0.75f, 1.25f);

    a->last_stability = stability;
    a->last_agitation = agitation;
    a->last_wave = ca_wave;
    a->last_gain = gain;

    float tempo_hint = 0.6f * stability + 0.4f * (0.5f + 0.5f * ca_wave);
    float tempo_scale = a->ca_rate * 96.0f;
    if (!isfinite(tempo_scale)) {
        tempo_scale = 0.0f;
    }
    tempo_hint = clampf(tempo_hint + 0.2f * tempo_scale, 0.0f, 2.0f);
    a->tempo = tempo_hint;
}

float astro_modulate_feedback(const Astro *a)
{
    if (!a) {
        return 1.0f;
    }
    return clampf(a->last_gain, 0.75f, 1.25f);
}

AstroMemory astro_memory_make(uint32_t signature,
                              float tone_avg,
                              float memory_avg,
                              float ca_rate,
                              float stability_avg,
                              uint64_t timestamp)
{
    AstroMemory snapshot;
    snapshot.signature = signature;
    snapshot.tone_avg = tone_avg;
    snapshot.memory_avg = memory_avg;
    snapshot.ca_rate = ca_rate;
    snapshot.stability_avg = stability_avg;
    snapshot.timestamp = timestamp;
    return snapshot;
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
    pos += strlen(key);
    char *end = NULL;
    float value = strtof(pos, &end);
    if (end == pos) {
        return false;
    }
    *out = value;
    return true;
}

static bool parse_uint32_field(const char *line, const char *key, uint32_t *out)
{
    if (!line || !key || !out) {
        return false;
    }
    const char *pos = strstr(line, key);
    if (!pos) {
        return false;
    }
    pos += strlen(key);
    while (*pos == ' ' || *pos == '\t') {
        ++pos;
    }
    char *end = NULL;
    unsigned long value = strtoul(pos, &end, 10);
    if (end == pos) {
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

static bool parse_uint64_field(const char *line, const char *key, uint64_t *out)
{
    if (!line || !key || !out) {
        return false;
    }
    const char *pos = strstr(line, key);
    if (!pos) {
        return false;
    }
    pos += strlen(key);
    while (*pos == ' ' || *pos == '\t') {
        ++pos;
    }
    char *end = NULL;
    unsigned long long value = strtoull(pos, &end, 10);
    if (end == pos) {
        return false;
    }
    *out = (uint64_t)value;
    return true;
}

size_t astro_memory_load(const char *path, AstroMemory *entries, size_t max_entries)
{
    if (!path || !entries || max_entries == 0) {
        return 0;
    }
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return 0;
    }
    size_t count = 0;
    char line[384];
    while (fgets(line, sizeof(line), fp)) {
        if (count >= max_entries) {
            break;
        }
        float tone = 0.0f;
        float memory = 0.0f;
        float ca_rate = 0.0f;
        float stability = 0.0f;
        uint32_t signature = 0U;
        uint64_t timestamp = 0ULL;
        if (!parse_float_field(line, "\"tone_avg\":", &tone)) {
            continue;
        }
        if (!parse_float_field(line, "\"memory_avg\":", &memory)) {
            continue;
        }
        if (!parse_float_field(line, "\"ca_rate\":", &ca_rate)) {
            continue;
        }
        if (!parse_float_field(line, "\"stability_avg\":", &stability)) {
            continue;
        }
        if (!parse_uint32_field(line, "\"signature\":", &signature)) {
            signature = 0U;
        }
        if (!parse_uint64_field(line, "\"ts\":", &timestamp)) {
            timestamp = 0ULL;
        }
        entries[count++] = astro_memory_make(signature, tone, memory, ca_rate, stability, timestamp);
    }
    fclose(fp);
    return count;
}

bool astro_memory_append(const char *path, const AstroMemory *snapshot)
{
    if (!path || !snapshot) {
        return false;
    }
    FILE *fp = fopen(path, "a");
    if (!fp) {
        return false;
    }
    int written = fprintf(fp,
                          "{\"tone_avg\":%.4f,\"memory_avg\":%.4f,\"ca_rate\":%.5f,\"stability_avg\":%.4f,\"signature\":%u,\"ts\":%" PRIu64 "}\n",
                          snapshot->tone_avg,
                          snapshot->memory_avg,
                          snapshot->ca_rate,
                          snapshot->stability_avg,
                          snapshot->signature,
                          snapshot->timestamp);
    fflush(fp);
    fclose(fp);
    return written > 0;
}
