#ifndef LIMINAL_SOIL_H
#define LIMINAL_SOIL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SOIL_CAPACITY 256
#define SOIL_TRACE_DATA_SIZE 64

#define SOIL_PRE_ECHO_CAPACITY 64 // unified merge by Codex

typedef struct {
    uint64_t timestamp;
    uint32_t energy;
    uint8_t data[SOIL_TRACE_DATA_SIZE];
} soil_trace;

typedef struct {
    soil_trace trace;
    float anticipation_hint;
    float resonance_hint;
} soil_pre_echo; // unified merge by Codex

soil_pre_echo soil_pre_echo_make(uint32_t energy,
                                const void *data,
                                size_t data_len,
                                float anticipation_hint,
                                float resonance_hint);
void soil_store_pre_echo(const soil_pre_echo *echo);
size_t soil_recent_pre_echo(soil_pre_echo *out_buffer, size_t max_count);
void soil_pre_echo_clear(void);

void soil_init(void);
void soil_write(const soil_trace *trace);
soil_trace soil_read_last(void);
void soil_decay(void);
size_t soil_recent(soil_trace *out_buffer, size_t max_count);
soil_trace soil_trace_make(uint32_t energy, const void *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_SOIL_H */
