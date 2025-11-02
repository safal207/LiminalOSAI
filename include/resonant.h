#ifndef LIMINAL_RESONANT_H
#define LIMINAL_RESONANT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RESONANT_BUS_CAPACITY 32
#define RESONANT_MSG_DATA_SIZE 32
#define RESONANT_BROADCAST_ID (-1)
#ifndef RESONANT_WAVE_SOURCE_ID
#define RESONANT_WAVE_SOURCE_ID 17
#endif

#define RES_ACTION_OPEN 101
#define RES_ACTION_CLOSE 102

typedef struct {
    int source_id;
    int target_id;
    uint32_t energy;
    uint8_t payload[RESONANT_MSG_DATA_SIZE];
} resonant_msg;

void bus_init(void);
void bus_emit(const resonant_msg *msg);
void bus_emit_wave(const char *tag, float level);
void bus_broadcast(int action_id, float value);
void bus_register_sensor(int sensor_id);
bool bus_listen(int sensor_id, resonant_msg *out_msg);
size_t bus_pending(void);
resonant_msg resonant_msg_make(int source_id, int target_id, uint32_t energy, const void *payload, size_t payload_len);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_RESONANT_H */
