#include "resonant.h"

#include <string.h>

static resonant_msg bus_queue[RESONANT_BUS_CAPACITY];
static size_t bus_count = 0;

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

    for (size_t i = 0; i < bus_count; ++i) {
        if (bus_queue[i].target_id == sensor_id || bus_queue[i].target_id == RESONANT_BROADCAST_ID) {
            *out_msg = bus_queue[i];
            shift_left_from(i);
            --bus_count;
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
