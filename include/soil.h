#ifndef LIMINAL_INCLUDE_SOIL_H
#define LIMINAL_INCLUDE_SOIL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SOIL_CAPACITY 256
#define SOIL_TRACE_DATA_SIZE 64

typedef struct {
    uint64_t timestamp;
    uint32_t energy;
    uint8_t data[SOIL_TRACE_DATA_SIZE];
} soil_trace;

void soil_init(void);
void soil_write(const soil_trace *trace);
soil_trace soil_read_last(void);
void soil_decay(void);
size_t soil_recent(soil_trace *out_buffer, size_t max_count);
soil_trace soil_trace_make(uint32_t energy, const void *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_INCLUDE_SOIL_H */
