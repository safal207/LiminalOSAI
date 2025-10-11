#ifndef LIMINAL_MEMORY_SOIL_H
#define LIMINAL_MEMORY_SOIL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SOIL_CAPACITY
#define SOIL_CAPACITY 128
#endif

typedef enum {
    SOIL_TRACE_ECHO = 0,
    SOIL_TRACE_SEED = 1,
    SOIL_TRACE_IMPRINT = 2
} soil_trace_type;

typedef struct {
    soil_trace_type type;
    uint64_t pulse_id;
    uint32_t energy;
} soil_trace;

void soil_init(void);
void soil_trace_record(soil_trace_type type, uint32_t energy);
size_t soil_snapshot(soil_trace *out_buffer, size_t max_count);
uint64_t soil_total_pulses(void);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_MEMORY_SOIL_H */
