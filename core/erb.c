#include "erb.h"

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#include <sys/stat.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#define ERB_RING_CAPACITY 256
#define ERB_INDEX_PATH "logs/erb_index.jsonl"
#define ERB_REPLAY_PATH "logs/erb_replay.jsonl"
#define ERB_EPISODE_PATTERN "logs/erb_episode_%06u.csv"
#define ERB_LOG_LIMIT_BYTES (5UL * 1024UL * 1024UL)

typedef struct {
    TickSnapshot snapshot;
    uint64_t seq;
} TickRingEntry;

static TickRingEntry g_tick_ring[ERB_RING_CAPACITY];
static int g_tick_ring_head = 0;
static int g_tick_ring_count = 0;
static uint64_t g_tick_ring_seq = 0;

static bool g_persistence_initialized = false;
static uint32_t g_next_episode_id = 0;

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

static void trim_log_if_needed(const char *path)
{
    if (!path) {
        return;
    }
#if defined(_WIN32)
    struct _stat64 st;
    if (_stat64(path, &st) == 0 && st.st_size > (long long)ERB_LOG_LIMIT_BYTES) {
        FILE *fp = fopen(path, "w");
        if (fp) {
            fclose(fp);
        }
    }
#else
    struct stat st;
    if (stat(path, &st) == 0 && st.st_size > (off_t)ERB_LOG_LIMIT_BYTES) {
        FILE *fp = fopen(path, "w");
        if (fp) {
            fclose(fp);
        }
    }
#endif
}

static void initialize_persistence(void)
{
    if (g_persistence_initialized) {
        return;
    }
    g_persistence_initialized = true;
    ensure_logs_directory();
    FILE *fp = fopen(ERB_INDEX_PATH, "r");
    if (!fp) {
        g_next_episode_id = 0U;
        return;
    }

    char line[512];
    uint32_t max_idx = 0U;
    bool have_idx = false;
    while (fgets(line, sizeof(line), fp)) {
        unsigned int idx = 0U;
        if (sscanf(line, "{\"idx\":%u", &idx) == 1) {
            if (!have_idx || idx >= max_idx) {
                max_idx = idx;
                have_idx = true;
            }
        }
    }
    fclose(fp);
    g_next_episode_id = have_idx ? (max_idx + 1U) : 0U;
}

static void reset_tick_ring(void)
{
    g_tick_ring_head = 0;
    g_tick_ring_count = 0;
    g_tick_ring_seq = 0;
}

static int sanitize_window_value(int value)
{
    if (value < 0) {
        return 0;
    }
    if (value > ERB_MAX_LEN - 1) {
        return ERB_MAX_LEN - 1;
    }
    return value;
}

static void sanitize_windows(int *pre, int *post)
{
    if (!pre || !post) {
        return;
    }
    int pre_value = sanitize_window_value(*pre);
    int post_value = sanitize_window_value(*post);
    int total = pre_value + post_value + 1;
    if (total > ERB_MAX_LEN) {
        int overflow = total - ERB_MAX_LEN;
        if (post_value >= overflow) {
            post_value -= overflow;
        } else {
            overflow -= post_value;
            post_value = 0;
            if (pre_value >= overflow) {
                pre_value -= overflow;
            } else {
                pre_value = 0;
            }
        }
    }
    *pre = pre_value;
    *post = post_value;
}

void erb_init(ERB *erb, int pre, int post, float spike_thr)
{
    if (!erb) {
        return;
    }

    initialize_persistence();
    reset_tick_ring();

    memset(erb, 0, sizeof(*erb));
    for (int i = 0; i < ERB_MAX_EPISODES; ++i) {
        erb->ids[i] = UINT32_MAX;
    }

    sanitize_windows(&pre, &post);
    erb->pre = pre;
    erb->post = post;
    erb->spike_thr = spike_thr > 0.0f ? spike_thr : 0.0f;
    erb->debounce = 0;
    erb->capture_active = false;
    erb->capture_post_remaining = 0;
    erb->capture_tag = 0U;
    erb->capture_last_seq = 0ULL;
    erb->capture.len = 0;

    /* load recent episodes from disk */
    uint32_t ids[ERB_MAX_EPISODES];
    size_t stored = 0U;
    FILE *fp = fopen(ERB_INDEX_PATH, "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            unsigned int idx = 0U;
            if (sscanf(line, "{\"idx\":%u", &idx) == 1) {
                if (stored < ERB_MAX_EPISODES) {
                    ids[stored++] = idx;
                } else {
                    memmove(ids, ids + 1, (ERB_MAX_EPISODES - 1) * sizeof(uint32_t));
                    ids[ERB_MAX_EPISODES - 1] = idx;
                }
            }
        }
        fclose(fp);
    }

    for (size_t i = 0; i < stored; ++i) {
        Episode episode;
        if (erb_load_episode(ids[i], &episode)) {
            int pos = erb->head;
            erb->buf[pos] = episode;
            erb->ids[pos] = ids[i];
            erb->head = (erb->head + 1) % ERB_MAX_EPISODES;
            if (erb->count < ERB_MAX_EPISODES) {
                erb->count += 1;
            }
        }
    }
}

static const TickRingEntry *ring_get_recent(int offset)
{
    if (offset < 0 || offset >= g_tick_ring_count) {
        return NULL;
    }
    int index = g_tick_ring_head - 1 - offset;
    if (index < 0) {
        index += ERB_RING_CAPACITY;
    }
    return &g_tick_ring[index];
}

void erb_tick_ring_push(TickSnapshot snapshot)
{
    g_tick_ring[g_tick_ring_head].snapshot = snapshot;
    g_tick_ring_seq += 1ULL;
    g_tick_ring[g_tick_ring_head].seq = g_tick_ring_seq;
    g_tick_ring_head = (g_tick_ring_head + 1) % ERB_RING_CAPACITY;
    if (g_tick_ring_count < ERB_RING_CAPACITY) {
        g_tick_ring_count += 1;
    }
}

static void erb_store_in_buffer(ERB *erb, const Episode *episode, uint32_t id)
{
    if (!erb || !episode) {
        return;
    }
    erb->buf[erb->head] = *episode;
    erb->ids[erb->head] = id;
    erb->head = (erb->head + 1) % ERB_MAX_EPISODES;
    if (erb->count < ERB_MAX_EPISODES) {
        erb->count += 1;
    }
}

static void append_tag_token(char **cursor, size_t *remaining, const char *token, bool *first)
{
    if (!cursor || !remaining || !token || !first) {
        return;
    }
    if (*remaining == 0) {
        return;
    }
    if (!*first && *remaining > 1) {
        **cursor = '|';
        (*cursor)++;
        (*remaining)--;
    }
    *first = false;
    size_t len = strlen(token);
    if (len >= *remaining) {
        len = *remaining - 1;
    }
    memcpy(*cursor, token, len);
    *cursor += len;
    *remaining -= len;
    **cursor = '\0';
}

void erb_tag_to_string(uint32_t tag, char *buffer, size_t size)
{
    if (!buffer || size == 0) {
        return;
    }
    buffer[0] = '\0';
    if (tag == 0U) {
        strncpy(buffer, "NONE", size - 1);
        buffer[size - 1] = '\0';
        return;
    }
    char *cursor = buffer;
    size_t remaining = size;
    bool first = true;
    if (tag & ERB_TAG_SPIKE) {
        append_tag_token(&cursor, &remaining, "SPIKE", &first);
    }
    if (tag & ERB_TAG_ALIGN) {
        append_tag_token(&cursor, &remaining, "ALIGN", &first);
    }
    if (tag & ERB_TAG_LOW_HARM) {
        append_tag_token(&cursor, &remaining, "LOW_HARM", &first);
    }
}

static uint32_t token_to_tag(const char *token)
{
    if (!token || !*token) {
        return 0U;
    }
    if (strcmp(token, "SPIKE") == 0) {
        return ERB_TAG_SPIKE;
    }
    if (strcmp(token, "ALIGN") == 0) {
        return ERB_TAG_ALIGN;
    }
    if (strcmp(token, "LOW_HARM") == 0 || strcmp(token, "LOWHARM") == 0) {
        return ERB_TAG_LOW_HARM;
    }
    if (strcmp(token, "ALL") == 0) {
        return ERB_TAG_SPIKE | ERB_TAG_ALIGN | ERB_TAG_LOW_HARM;
    }
    return 0U;
}

uint32_t erb_parse_tag_mask(const char *spec)
{
    if (!spec) {
        return 0U;
    }
    uint32_t mask = 0U;
    const char *ptr = spec;
    char token[32];
    while (*ptr) {
        while (*ptr && (*ptr == ' ' || *ptr == '|' || *ptr == ',' || *ptr == ';')) {
            ++ptr;
        }
        if (!*ptr) {
            break;
        }
        size_t len = 0U;
        while (*ptr && *ptr != '|' && *ptr != ',' && *ptr != ';') {
            if (len + 1 < sizeof(token)) {
                token[len++] = (char)toupper((unsigned char)*ptr);
            }
            ++ptr;
        }
        token[len] = '\0';
        mask |= token_to_tag(token);
    }
    return mask;
}

static void persist_episode(uint32_t id, const Episode *episode)
{
    if (!episode) {
        return;
    }
    ensure_logs_directory();

    char path[64];
    snprintf(path, sizeof(path), ERB_EPISODE_PATTERN, id);
    FILE *ep = fopen(path, "w");
    if (ep) {
        fprintf(ep, "#tag=%u\n", episode->tag);
        for (int i = 0; i < episode->len; ++i) {
            const TickSnapshot *snap = &episode->seq[i];
            fprintf(ep,
                    "%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f\n",
                    i,
                    snap->amp,
                    snap->tempo,
                    snap->consent,
                    snap->influence,
                    snap->harmony,
                    snap->dream,
                    snap->trs_delta,
                    snap->trs_alpha);
        }
        fclose(ep);
    }

    trim_log_if_needed(ERB_INDEX_PATH);
    FILE *idx = fopen(ERB_INDEX_PATH, "a");
    if (!idx) {
        return;
    }
    char tag_text[64];
    erb_tag_to_string(episode->tag, tag_text, sizeof(tag_text));
    float delta_max = 0.0f;
    float alpha_sum = 0.0f;
    for (int i = 0; i < episode->len; ++i) {
        float abs_delta = fabsf(episode->seq[i].trs_delta);
        if (abs_delta > delta_max) {
            delta_max = abs_delta;
        }
        alpha_sum += episode->seq[i].trs_alpha;
    }
    float alpha_mean = episode->len > 0 ? (alpha_sum / (float)episode->len) : 0.0f;
    fprintf(idx,
            "{\"idx\":%u,\"len\":%d,\"tag\":\"%s\",\"tag_mask\":%u,\"delta_max\":%.6f,\"alpha_mean\":%.6f}\n",
            id,
            episode->len,
            tag_text,
            episode->tag,
            delta_max,
            alpha_mean);
    fclose(idx);
}

static void finalize_capture(ERB *erb)
{
    if (!erb) {
        return;
    }
    erb->capture.tag = erb->capture_tag;
    uint32_t id = g_next_episode_id++;
    persist_episode(id, &erb->capture);
    erb_store_in_buffer(erb, &erb->capture, id);
    erb->capture_active = false;
    erb->capture_post_remaining = 0;
    erb->capture_last_seq = 0ULL;
    erb->capture_tag = 0U;
    erb->capture.len = 0;
    erb->debounce = erb->post;
}

static bool capture_progress(ERB *erb)
{
    if (!erb || !erb->capture_active) {
        return false;
    }
    bool completed = false;
    int total = g_tick_ring_count;
    if (total <= 0) {
        return false;
    }
    int start = (g_tick_ring_head - total + ERB_RING_CAPACITY) % ERB_RING_CAPACITY;
    for (int i = 0; i < total; ++i) {
        const TickRingEntry *entry = &g_tick_ring[(start + i) % ERB_RING_CAPACITY];
        if (entry->seq <= erb->capture_last_seq) {
            continue;
        }
        if (erb->capture.len < ERB_MAX_LEN) {
            erb->capture.seq[erb->capture.len++] = entry->snapshot;
        }
        erb->capture_last_seq = entry->seq;
        if (erb->capture_post_remaining > 0) {
            erb->capture_post_remaining -= 1;
        }
        if (erb->capture_post_remaining <= 0 || erb->capture.len >= ERB_MAX_LEN) {
            finalize_capture(erb);
            completed = true;
            break;
        }
    }
    return completed;
}

static bool start_capture(ERB *erb, uint32_t tag)
{
    if (!erb || g_tick_ring_count <= 0) {
        return false;
    }
    const TickRingEntry *current = ring_get_recent(0);
    if (!current) {
        return false;
    }
    int pre_count = erb->pre;
    if (pre_count > g_tick_ring_count - 1) {
        pre_count = g_tick_ring_count > 0 ? g_tick_ring_count - 1 : 0;
    }
    if (pre_count < 0) {
        pre_count = 0;
    }

    erb->capture.len = 0;
    for (int offset = pre_count; offset >= 0; --offset) {
        const TickRingEntry *entry = ring_get_recent(offset);
        if (!entry) {
            continue;
        }
        if (erb->capture.len < ERB_MAX_LEN) {
            erb->capture.seq[erb->capture.len++] = entry->snapshot;
            erb->capture_last_seq = entry->seq;
        }
    }
    erb->capture_tag = tag;
    erb->capture_post_remaining = erb->post;
    erb->capture_active = true;
    if (erb->capture_post_remaining <= 0) {
        finalize_capture(erb);
        return true;
    }
    return false;
}

bool erb_maybe_capture(ERB *erb, uint32_t tag)
{
    if (!erb) {
        return false;
    }
    if (erb->debounce > 0) {
        erb->debounce -= 1;
    }
    bool captured = false;
    if (erb->capture_active) {
        if (tag != 0U) {
            erb->capture_tag |= tag;
        }
        if (capture_progress(erb)) {
            captured = true;
        }
    }
    if (tag != 0U && !erb->capture_active && erb->debounce <= 0) {
        if (start_capture(erb, tag)) {
            captured = true;
        }
    }
    return captured;
}

const Episode *erb_get(const ERB *erb, int idx)
{
    if (!erb || idx < 0 || idx >= erb->count) {
        return NULL;
    }
    int position = erb->head - 1 - idx;
    if (position < 0) {
        position += ERB_MAX_EPISODES;
    }
    return &erb->buf[position];
}

int erb_count(const ERB *erb)
{
    if (!erb) {
        return 0;
    }
    return erb->count;
}

uint32_t erb_id_at(const ERB *erb, int idx)
{
    if (!erb || idx < 0 || idx >= erb->count) {
        return UINT32_MAX;
    }
    int position = erb->head - 1 - idx;
    if (position < 0) {
        position += ERB_MAX_EPISODES;
    }
    return erb->ids[position];
}

bool erb_load_episode(uint32_t id, Episode *out)
{
    if (!out) {
        return false;
    }
    char path[64];
    snprintf(path, sizeof(path), ERB_EPISODE_PATTERN, id);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return false;
    }
    out->len = 0;
    out->tag = 0U;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#') {
            unsigned int mask = 0U;
            if (sscanf(line, "#tag=%u", &mask) == 1) {
                out->tag = mask;
            }
            continue;
        }
        size_t index = 0U;
        TickSnapshot snap;
        if (sscanf(line,
                   "%zu,%f,%f,%f,%f,%f,%f,%f,%f",
                   &index,
                   &snap.amp,
                   &snap.tempo,
                   &snap.consent,
                   &snap.influence,
                   &snap.harmony,
                   &snap.dream,
                   &snap.trs_delta,
                   &snap.trs_alpha) == 9) {
            if (out->len < ERB_MAX_LEN) {
                out->seq[out->len++] = snap;
            }
        }
    }
    fclose(fp);
    return out->len > 0;
}

static void sanitize_mode_label(const char *mode, char *buffer, size_t size)
{
    if (!buffer || size == 0) {
        return;
    }
    buffer[0] = '\0';
    if (!mode || !*mode) {
        strncpy(buffer, "unknown", size - 1);
        buffer[size - 1] = '\0';
        return;
    }
    size_t len = 0U;
    while (mode[len] && len + 1 < size) {
        char c = mode[len];
        if (c == '"') {
            buffer[len] = '\'';
        } else {
            buffer[len] = c;
        }
        ++len;
    }
    buffer[len] = '\0';
}

void erb_log_replay_tick(uint32_t tick,
                         uint32_t src_idx,
                         float delta,
                         float alpha,
                         float err_after,
                         const char *mode)
{
    ensure_logs_directory();
    trim_log_if_needed(ERB_REPLAY_PATH);
    FILE *fp = fopen(ERB_REPLAY_PATH, "a");
    if (!fp) {
        return;
    }
    char mode_label[64];
    sanitize_mode_label(mode, mode_label, sizeof(mode_label));
    fprintf(fp,
            "{\"tick\":%u,\"src_idx\":%u,\"delta\":%.6f,\"alpha\":%.6f,\"err_after\":%.6f,\"mode\":\"%s\"}\n",
            tick,
            src_idx,
            delta,
            alpha,
            err_after,
            mode_label);
    fclose(fp);
}
