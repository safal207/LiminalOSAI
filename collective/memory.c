#include "collective_memory.h"

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

static int g_snapshot_interval = 20;
static int g_cycles_since_snapshot = 0;
static float g_last_volatility = 0.0f;

static float sanitize_sample(float value)
{
    if (!isfinite(value)) {
        return 0.0f;
    }
    return value;
}

static size_t cm_strnlen(const char *s, size_t max_len)
{
    if (!s) {
        return 0;
    }
    size_t len = 0;
    while (len < max_len && s[len] != '\0') {
        ++len;
    }
    return len;
}

static float cm_round_to(float value, float scale)
{
    if (!isfinite(value)) {
        return 0.0f;
    }
    if (scale <= 0.0f) {
        return value;
    }
    return floorf(value * scale + 0.5f) / scale;
}

float cm_clamp(float value, float min_value, float max_value)
{
    if (value < min_value) {
        return min_value;
    }
    if (value > max_value) {
        return max_value;
    }
    return value;
}

void cm_ring_reset(CMemRing *r)
{
    if (!r) {
        return;
    }
    memset(r, 0, sizeof(*r));
    g_cycles_since_snapshot = 0;
    g_last_volatility = 0.0f;
}

void cm_set_snapshot_interval(int interval)
{
    if (interval < 1) {
        interval = 1;
    }
    g_snapshot_interval = interval;
}

static float cm_ring_mean(const float *samples, int count)
{
    if (!samples || count <= 0) {
        return 0.0f;
    }
    double sum = 0.0;
    for (int i = 0; i < count; ++i) {
        sum += samples[i];
    }
    return (float)(sum / (double)count);
}

static float cm_ring_variance(const float *samples, int count, float mean)
{
    if (!samples || count <= 0) {
        return 0.0f;
    }
    double accum = 0.0;
    for (int i = 0; i < count; ++i) {
        double diff = (double)samples[i] - (double)mean;
        accum += diff * diff;
    }
    return (float)(accum / (double)count);
}

void cm_ring_push(CMemRing *r, float coh, float adj)
{
    if (!r) {
        return;
    }
    coh = sanitize_sample(coh);
    adj = sanitize_sample(adj);
    r->coh_ring[r->idx] = coh;
    r->adj_ring[r->idx] = adj;
    r->idx = (r->idx + 1) % CM_WINDOW;
    if (r->filled < CM_WINDOW) {
        ++r->filled;
    }
    ++g_cycles_since_snapshot;
}

float cm_last_volatility(void)
{
    return g_last_volatility;
}

void cm_mark_snapshot(void)
{
    g_cycles_since_snapshot = 0;
}

static float cm_compute_volatility(const CMemRing *r)
{
    if (!r || r->filled <= 0) {
        g_last_volatility = 0.0f;
        return 0.0f;
    }
    float coh_mean = cm_ring_mean(r->coh_ring, r->filled);
    float adj_mean = cm_ring_mean(r->adj_ring, r->filled);
    float coh_var = cm_ring_variance(r->coh_ring, r->filled, coh_mean);
    float adj_var = cm_ring_variance(r->adj_ring, r->filled, adj_mean);
    float combined = 0.5f * (coh_var + adj_var);
    g_last_volatility = combined;
    return combined;
}

bool cm_should_snapshot(const CMemRing *r)
{
    if (!r) {
        return false;
    }
    if (r->filled < CM_WINDOW) {
        cm_compute_volatility(r);
        return false;
    }
    float volatility = cm_compute_volatility(r);
    if (volatility > 0.06f) {
        return false;
    }
    if (volatility < 0.02f) {
        return true;
    }
    return g_cycles_since_snapshot >= g_snapshot_interval;
}

CMemTrace cm_build_snapshot(const CMemRing *r, uint32_t sig)
{
    CMemTrace trace = {0.0f, 0.0f, 0.0f, sig, (uint64_t)time(NULL)};
    if (!r || r->filled <= 0) {
        return trace;
    }
    float coh_mean = cm_ring_mean(r->coh_ring, r->filled);
    float adj_mean = cm_ring_mean(r->adj_ring, r->filled);
    float volatility = cm_compute_volatility(r);

    trace.group_coh_avg = cm_round_to(coh_mean, 100.0f);
    trace.adjust_avg = cm_round_to(adj_mean, 1000.0f);
    trace.volatility = cm_round_to(volatility, 1000.0f);
    trace.signature = sig;
    trace.ts = (uint64_t)time(NULL);
    return trace;
}

static char *cm_strdup(const char *src)
{
    if (!src) {
        return NULL;
    }
    size_t len = strlen(src);
    char *copy = (char *)malloc(len + 1);
    if (!copy) {
        return NULL;
    }
    memcpy(copy, src, len + 1);
    return copy;
}

static void cm_ensure_parent_dirs(const char *path)
{
    if (!path) {
        return;
    }
    char buffer[CM_PATH_MAX];
    size_t len = cm_strnlen(path, sizeof(buffer));
    if (len == 0) {
        return;
    }
    if (len >= sizeof(buffer)) {
        len = sizeof(buffer) - 1;
    }
    memcpy(buffer, path, len);
    buffer[len] = '\0';
    char *slash = strrchr(buffer, '/');
    if (!slash) {
        return;
    }
    *slash = '\0';
    if (buffer[0] == '\0') {
        return;
    }

    char tmp[CM_PATH_MAX];
    size_t idx = 0;
    while (buffer[idx] != '\0' && idx < sizeof(tmp) - 1) {
        tmp[idx] = buffer[idx];
        if (buffer[idx] == '/') {
            tmp[idx + 1] = '\0';
            if (tmp[0] != '\0') {
#ifdef _WIN32
                mkdir(tmp);
#else
                mkdir(tmp, 0777);
#endif
            }
        }
        ++idx;
    }
    tmp[idx] = '\0';
    if (tmp[0] != '\0') {
#ifdef _WIN32
        mkdir(tmp);
#else
        mkdir(tmp, 0777);
#endif
    }
}

void cm_store(const CMemTrace *t, const char *path)
{
    if (!t || !path) {
        return;
    }

    cm_ensure_parent_dirs(path);

    FILE *fp = fopen(path, "r");
    char **lines = NULL;
    size_t count = 0;
    size_t capacity = 0;

    if (fp) {
        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), fp)) {
            size_t line_len = strlen(buffer);
            char *entry = (char *)malloc(line_len + 1);
            if (!entry) {
                continue;
            }
            memcpy(entry, buffer, line_len + 1);
            if (count == capacity) {
                size_t new_cap = capacity == 0 ? 8 : capacity * 2;
                char **tmp = (char **)realloc(lines, new_cap * sizeof(char *));
                if (!tmp) {
                    free(entry);
                    continue;
                }
                lines = tmp;
                capacity = new_cap;
            }
            lines[count++] = entry;
        }
        fclose(fp);
    }

    char entry[256];
    int written = snprintf(entry,
                           sizeof(entry),
                           "{\"group_coh_avg\":%.4f,\"adjust_avg\":%.5f,\"volatility\":%.5f,\"signature\":%" PRIu32 ",\"ts\":%" PRIu64 "}\n",
                           t->group_coh_avg,
                           t->adjust_avg,
                           t->volatility,
                           t->signature,
                           t->ts);
    if (written < 0 || (size_t)written >= sizeof(entry)) {
        entry[sizeof(entry) - 2] = '\n';
        entry[sizeof(entry) - 1] = '\0';
    }

    char *new_line = cm_strdup(entry);
    if (!new_line) {
        for (size_t i = 0; i < count; ++i) {
            free(lines[i]);
        }
        free(lines);
        return;
    }

    if (count == capacity) {
        size_t new_cap = capacity == 0 ? 8 : capacity * 2;
        char **tmp = (char **)realloc(lines, new_cap * sizeof(char *));
        if (!tmp) {
            free(new_line);
            for (size_t i = 0; i < count; ++i) {
                free(lines[i]);
            }
            free(lines);
            return;
        }
        lines = tmp;
        capacity = new_cap;
    }
    lines[count++] = new_line;

    if (count > CM_MAX) {
        size_t start = count - CM_MAX;
        for (size_t i = 0; i < start; ++i) {
            free(lines[i]);
            lines[i] = NULL;
        }
        memmove(lines, lines + start, (count - start) * sizeof(char *));
        count -= start;
    }

    fp = fopen(path, "w");
    if (!fp) {
        for (size_t i = 0; i < count; ++i) {
            free(lines[i]);
        }
        free(lines);
        return;
    }

    for (size_t i = 0; i < count; ++i) {
        if (!lines[i]) {
            continue;
        }
        fputs(lines[i], fp);
        free(lines[i]);
    }
    free(lines);
    fclose(fp);
    cm_mark_snapshot();
}

static bool cm_parse_float(const char *line, const char *key, float *out)
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

static bool cm_parse_uint32(const char *line, const char *key, uint32_t *out)
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
    unsigned long value = strtoul(pos, &end, 10);
    if (end == pos) {
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

static bool cm_parse_uint64(const char *line, const char *key, uint64_t *out)
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
    unsigned long long value = strtoull(pos, &end, 10);
    if (end == pos) {
        return false;
    }
    *out = (uint64_t)value;
    return true;
}

static int cm_popcount(uint32_t value)
{
#if defined(__GNUC__)
    return __builtin_popcount(value);
#else
    int count = 0;
    while (value) {
        value &= value - 1U;
        ++count;
    }
    return count;
#endif
}

int cm_signature_distance(uint32_t a, uint32_t b)
{
    return cm_popcount(a ^ b);
}

float cm_signature_similarity(uint32_t a, uint32_t b)
{
    int distance = cm_signature_distance(a, b);
    float similarity = 1.0f - (float)distance / 32.0f;
    if (similarity < 0.0f) {
        similarity = 0.0f;
    }
    return similarity;
}

uint32_t cm_signature_hash(const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= bytes[i];
        for (int j = 0; j < 8; ++j) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

CMemTrace *cm_best_match(uint32_t sig, const char *path)
{
    if (!path) {
        return NULL;
    }
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return NULL;
    }

    char buffer[1024];
    float best_similarity = -1.0f;
    CMemTrace *best = NULL;

    while (fgets(buffer, sizeof(buffer), fp)) {
        CMemTrace candidate = {0.0f, 0.0f, 0.0f, 0u, 0u};
        if (!cm_parse_float(buffer, "\"group_coh_avg\":", &candidate.group_coh_avg)) {
            continue;
        }
        if (!cm_parse_float(buffer, "\"adjust_avg\":", &candidate.adjust_avg)) {
            continue;
        }
        if (!cm_parse_float(buffer, "\"volatility\":", &candidate.volatility)) {
            continue;
        }
        if (!cm_parse_uint32(buffer, "\"signature\":", &candidate.signature)) {
            continue;
        }
        cm_parse_uint64(buffer, "\"ts\":", &candidate.ts);

        float similarity = cm_signature_similarity(sig, candidate.signature);
        if (similarity > best_similarity) {
            best_similarity = similarity;
            CMemTrace *copy = (CMemTrace *)malloc(sizeof(CMemTrace));
            if (!copy) {
                continue;
            }
            *copy = candidate;
            if (best) {
                free(best);
            }
            best = copy;
        }
    }

    fclose(fp);
    return best;
}

void cm_trace_free(CMemTrace *trace)
{
    free(trace);
}

