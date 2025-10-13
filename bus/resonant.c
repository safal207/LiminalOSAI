#include "resonant.h"

#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static resonant_msg bus_queue[RESONANT_BUS_CAPACITY];
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

static void queue_duplicate(const resonant_msg *msg, int sensor_id)
{
    if (!msg || sensor_id == RESONANT_BROADCAST_ID) {
        return;
    }

    resonant_msg duplicate = *msg;
    duplicate.target_id = sensor_id;
    bus_emit(&duplicate);
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
        if (bus_queue[last].energy >= msg->energy) {
            return;
        }
        bus_queue[last] = *msg;
        while (last > 0 && bus_queue[last - 1].energy < bus_queue[last].energy) {
            resonant_msg tmp = bus_queue[last - 1];
            bus_queue[last - 1] = bus_queue[last];
            bus_queue[last] = tmp;
            --last;
        }
        return;
    }

    size_t insert_index = 0;
    while (insert_index < bus_count && bus_queue[insert_index].energy >= msg->energy) {
        ++insert_index;
    }

    shift_right_from(insert_index);
    bus_queue[insert_index] = *msg;
    ++bus_count;
}

bool bus_listen(int sensor_id, resonant_msg *out_msg)
{
    if (!out_msg || bus_count == 0) {
        return false;
    }

    bus_register_sensor(sensor_id);

    for (size_t i = 0; i < bus_count; ++i) {
        if (bus_queue[i].target_id == sensor_id || bus_queue[i].target_id == RESONANT_BROADCAST_ID) {
            resonant_msg message = bus_queue[i];
            shift_left_from(i);
            --bus_count;
            *out_msg = message;

            if (message.target_id == RESONANT_BROADCAST_ID) {
                for (size_t sensor_index = 0; sensor_index < sensor_count; ++sensor_index) {
                    int registered_id = sensor_registry[sensor_index];
                    if (registered_id == sensor_id) {
                        continue;
                    }
                    queue_duplicate(&message, registered_id);
                }
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
