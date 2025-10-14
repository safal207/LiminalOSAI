#include "resonant.h"

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    resonant_msg msg;
    uint32_t read_mask;
} bus_entry;

static bus_entry bus_queue[RESONANT_BUS_CAPACITY];
static size_t bus_count = 0;

static int sensor_registry[RESONANT_BUS_CAPACITY];
static size_t sensor_count = 0;

static bool sensor_registered(int sensor_id)
{
    if (sensor_id == RESONANT_BROADCAST_ID) {
        return true;
    }

    for (size_t i = 0; i < sensor_count; ++i) {
        if (sensor_registry[i] == sensor_id) {
            return true;
        }
    }

    return false;
}

void bus_register_sensor(int sensor_id)
{
    if (sensor_id == RESONANT_BROADCAST_ID || sensor_id == 0) {
        return;
    }

    if (sensor_registered(sensor_id)) {
        return;
    }

    if (sensor_count >= RESONANT_BUS_CAPACITY) {
        return;
    }

    sensor_registry[sensor_count++] = sensor_id;
}

static void shift_right_from(size_t index)
{
    for (size_t i = bus_count; i > index; --i) {
        bus_queue[i] = bus_queue[i - 1];
    }
}

static void shift_left_from(size_t index)
{
    for (size_t i = index; i + 1 < bus_count; ++i) {
        bus_queue[i] = bus_queue[i + 1];
    }
}

static uint32_t sensor_bit(int sensor_id)
{
    if (sensor_id == RESONANT_BROADCAST_ID || sensor_id == 0) {
        return 0U;
    }

    for (size_t i = 0; i < sensor_count && i < 32; ++i) {
        if (sensor_registry[i] == sensor_id) {
            return 1U << i;
        }
    }

    return 0U;
}

static uint32_t sensor_mask(void)
{
    uint32_t mask = 0U;
    size_t limit = sensor_count < 32 ? sensor_count : 32;
    for (size_t i = 0; i < limit; ++i) {
        mask |= (1U << i);
    }
    return mask;
}

void bus_init(void)
{
    memset(bus_queue, 0, sizeof(bus_queue));
    bus_count = 0;
    memset(sensor_registry, 0, sizeof(sensor_registry));
    sensor_count = 0;
}

void bus_emit(const resonant_msg *msg)
{
    if (!msg) {
        return;
    }

    if (bus_count == RESONANT_BUS_CAPACITY) {
        size_t last = bus_count - 1;
        if (bus_queue[last].msg.energy >= msg->energy) {
            return;
        }
        bus_queue[last].msg = *msg;
        bus_queue[last].read_mask = 0U;
        while (last > 0 && bus_queue[last - 1].msg.energy < bus_queue[last].msg.energy) {
            bus_entry tmp = bus_queue[last - 1];
            bus_queue[last - 1] = bus_queue[last];
            bus_queue[last] = tmp;
            --last;
        }
        return;
    }

    size_t insert_index = 0;
    while (insert_index < bus_count && bus_queue[insert_index].msg.energy >= msg->energy) {
        ++insert_index;
    }

    shift_right_from(insert_index);
    bus_queue[insert_index].msg = *msg;
    bus_queue[insert_index].read_mask = 0U;
    ++bus_count;
}

bool bus_listen(int sensor_id, resonant_msg *out_msg)
{
    if (!out_msg || bus_count == 0) {
        return false;
    }

    bus_register_sensor(sensor_id);

    uint32_t listener_bit = sensor_bit(sensor_id);

    for (size_t i = 0; i < bus_count; ++i) {
        resonant_msg *message = &bus_queue[i].msg;
        if (message->target_id == sensor_id) {
            resonant_msg delivered = *message;
            shift_left_from(i);
            --bus_count;
            *out_msg = delivered;
            return true;
        }

        if (message->target_id == RESONANT_BROADCAST_ID && listener_bit != 0U) {
            if ((bus_queue[i].read_mask & listener_bit) != 0U) {
                continue;
            }

            bus_queue[i].read_mask |= listener_bit;
            *out_msg = *message;

            uint32_t all_bits = sensor_mask();
            if (all_bits != 0U && (bus_queue[i].read_mask & all_bits) == all_bits) {
                shift_left_from(i);
                --bus_count;
            }
            return true;
        }
    }

    return false;
}

size_t bus_pending(void)
{
    return bus_count;
}

resonant_msg resonant_msg_make(int source_id, int target_id, uint32_t energy, const void *payload, size_t payload_len)
{
    resonant_msg msg;
    memset(&msg, 0, sizeof(msg));
    msg.source_id = source_id;
    msg.target_id = target_id;
    msg.energy = energy;

    if (payload && payload_len > 0) {
        if (payload_len > RESONANT_MSG_DATA_SIZE) {
            payload_len = RESONANT_MSG_DATA_SIZE;
        }
        memcpy(msg.payload, payload, payload_len);
    }

    return msg;
}

void bus_emit_wave(const char *tag, float level)
{
    char payload[RESONANT_MSG_DATA_SIZE];
    const char *use_tag = tag ? tag : "wave";

    float magnitude = fabsf(level);
    if (!isfinite(magnitude)) {
        magnitude = 0.0f;
    }
    if (magnitude > 1.0f) {
        magnitude = 1.0f;
    }

    int written = snprintf(payload, sizeof(payload), "%s:%.2f", use_tag, magnitude);
    if (written < 0) {
        written = 0;
        payload[0] = '\0';
    } else if (written >= (int)sizeof(payload)) {
        written = (int)sizeof(payload) - 1;
        payload[written] = '\0';
    }

    uint32_t energy = (uint32_t)(magnitude * 120.0f);
    if (energy == 0U) {
        energy = 1U;
    }

    resonant_msg msg = resonant_msg_make(RESONANT_WAVE_SOURCE_ID, RESONANT_BROADCAST_ID, energy, payload, (size_t)written);
    bus_emit(&msg);
}
