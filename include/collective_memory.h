#ifndef LIMINAL_INCLUDE_COLLECTIVE_MEMORY_H
#define LIMINAL_INCLUDE_COLLECTIVE_MEMORY_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    float group_coh_avg;
    float adjust_avg;
    float volatility;
    uint32_t signature;
    uint64_t ts;
} CMemTrace;

#define CM_WINDOW 32
#define CM_MAX 128
#define CM_PATH_MAX 256

typedef struct {
    float coh_ring[CM_WINDOW];
    float adj_ring[CM_WINDOW];
    int idx;
    int filled;
} CMemRing;

#ifdef __cplusplus
extern "C" {
#endif

void cm_ring_reset(CMemRing *r);
void cm_ring_push(CMemRing *r, float coh, float adj);
bool cm_should_snapshot(const CMemRing *r);
CMemTrace cm_build_snapshot(const CMemRing *r, uint32_t sig);
void cm_store(const CMemTrace *t, const char *path);
CMemTrace *cm_best_match(uint32_t sig, const char *path);
void cm_trace_free(CMemTrace *trace);
void cm_set_snapshot_interval(int interval);
void cm_mark_snapshot(void);
float cm_last_volatility(void);
float cm_signature_similarity(uint32_t a, uint32_t b);
int cm_signature_distance(uint32_t a, uint32_t b);
uint32_t cm_signature_hash(const void *data, size_t len);
float cm_clamp(float value, float min_value, float max_value);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_INCLUDE_COLLECTIVE_MEMORY_H */
