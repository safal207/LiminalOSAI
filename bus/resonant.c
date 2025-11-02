#include "resonant.h"

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static resonant_msg bus_queue[RESONANT_BUS_CAPACITY];
static uint64_t broadcast_delivery_mask[RESONANT_BUS_CAPACITY];
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

static int sensor_index_of(int sensor_id)
{
    if (sensor_id == RESONANT_BROADCAST_ID) {
        return -1;
    }

    for (size_t i = 0; i < sensor_count; ++i) {
        if (sensor_registry[i] == sensor_id) {
            return (int)i;
        }
    }

    return -1;
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
        broadcast_delivery_mask[i] = broadcast_delivery_mask[i - 1];
    }
}

static void shift_left_from(size_t index)
{
    for (size_t i = index; i + 1 < bus_count; ++i) {
        bus_queue[i] = bus_queue[i + 1];
        broadcast_delivery_mask[i] = broadcast_delivery_mask[i + 1];
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
    memset(broadcast_delivery_mask, 0, sizeof(broadcast_delivery_mask));
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
        broadcast_delivery_mask[last] = 0ULL;
        while (last > 0 && bus_queue[last - 1].energy < bus_queue[last].energy) {
            resonant_msg tmp = bus_queue[last - 1];
            bus_queue[last - 1] = bus_queue[last];
            bus_queue[last] = tmp;
            uint64_t mask_tmp = broadcast_delivery_mask[last - 1];
            broadcast_delivery_mask[last - 1] = broadcast_delivery_mask[last];
            broadcast_delivery_mask[last] = mask_tmp;
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
    broadcast_delivery_mask[insert_index] = 0ULL;
    ++bus_count;
}

void bus_broadcast(int action_id, float value)
{
    float sanitized = value;
    if (!isfinite(sanitized)) {
        sanitized = 0.0f;
    }
    if (sanitized < 0.0f) {
        sanitized = 0.0f;
    } else if (sanitized > 1.0f) {
        sanitized = 1.0f;
    }

    struct {
        int32_t action_id;
        float score;
    } payload = { action_id, sanitized };

    uint32_t energy = (uint32_t)(sanitized * 120.0f);
    if (energy == 0U) {
        energy = 1U;
    }

    resonant_msg msg =
        resonant_msg_make(action_id, RESONANT_BROADCAST_ID, energy, &payload, sizeof(payload));
    bus_emit(&msg);
}

bool bus_listen(int sensor_id, resonant_msg *out_msg)
{
    if (!out_msg || bus_count == 0) {
        return false;
    }

    bus_register_sensor(sensor_id);

    int registry_index = sensor_index_of(sensor_id);

    for (size_t i = 0; i < bus_count; ++i) {
        resonant_msg message = bus_queue[i];
        if (message.target_id == sensor_id) {
            shift_left_from(i);
            --bus_count;
            broadcast_delivery_mask[bus_count] = 0ULL;
            *out_msg = message;
            return true;
        }

        if (message.target_id != RESONANT_BROADCAST_ID || registry_index < 0) {
            continue;
        }

        uint64_t delivered_mask = broadcast_delivery_mask[i];
        uint64_t sensor_bit = 1ULL << (uint64_t)registry_index;
        if (delivered_mask & sensor_bit) {
            continue;
        }

        delivered_mask |= sensor_bit;
        broadcast_delivery_mask[i] = delivered_mask;
        *out_msg = message;

        bool all_delivered = true;
        for (size_t sensor_index = 0; sensor_index < sensor_count; ++sensor_index) {
            uint64_t bit = 1ULL << (uint64_t)sensor_index;
            if ((delivered_mask & bit) == 0ULL) {
                all_delivered = false;
                break;
            }
        }

        if (all_delivered) {
            shift_left_from(i);
            --bus_count;
            broadcast_delivery_mask[bus_count] = 0ULL;
        }

        return true;
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
