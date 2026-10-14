#include "pulse_loop.h"

uint64_t pulse_loop_run(const PulseLoop *loop)
{
    uint64_t pulses = 0;
    while (!loop->limit || pulses < loop->limit) {
        loop->inhale(loop->context);
        loop->reflect(loop->context);
        loop->exhale(loop->context);
        loop->delay(loop->context);
        if (loop->completed) {
            loop->completed(loop->context, pulses + 1);
        }
        ++pulses;
    }
    return pulses;
}
