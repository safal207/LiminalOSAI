#ifndef LIMINAL_ERB_H
#define LIMINAL_ERB_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define ERB_MAX_EPISODES 32
#define ERB_MAX_LEN 128

#define ERB_TAG_SPIKE   0x1u
#define ERB_TAG_ALIGN   0x2u
#define ERB_TAG_LOW_HARM 0x4u

typedef struct {
    float amp;
    float tempo;
    float consent;
    float influence;
    float harmony;
    float dream;
    float trs_delta;
    float trs_alpha;
} TickSnapshot;

typedef struct {
    int len;
    TickSnapshot seq[ERB_MAX_LEN];
    uint32_t tag;
} Episode;

typedef struct {
    Episode buf[ERB_MAX_EPISODES];
    Episode capture;
    uint32_t ids[ERB_MAX_EPISODES];
    int head;
    int count;
    int pre;
    int post;
    float spike_thr;
    int debounce;
    bool capture_active;
    int capture_post_remaining;
    uint32_t capture_tag;
    uint64_t capture_last_seq;
} ERB;

void erb_init(ERB *erb, int pre, int post, float spike_thr);
void erb_tick_ring_push(TickSnapshot snapshot);
bool erb_maybe_capture(ERB *erb, uint32_t tag);
const Episode *erb_get(const ERB *erb, int idx);
int erb_count(const ERB *erb);
uint32_t erb_id_at(const ERB *erb, int idx);
void erb_tag_to_string(uint32_t tag, char *buffer, size_t size);
uint32_t erb_parse_tag_mask(const char *spec);
bool erb_load_episode(uint32_t id, Episode *out);
void erb_log_replay_tick(uint32_t tick,
                         uint32_t src_idx,
                         float delta,
                         float alpha,
                         float err_after,
                         const char *mode);

#endif /* LIMINAL_ERB_H */
