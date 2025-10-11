#define _POSIX_C_SOURCE 199309L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "../memory/soil.h"

#define ENERGY_INHALE   3U
#define ENERGY_REFLECT  5U
#define ENERGY_EXHALE   2U

static void inhale(void)
{
    soil_trace_record(SOIL_TRACE_ECHO, ENERGY_INHALE);
    fputs("inhale\n", stdout);
}

static void reflect(void)
{
    soil_trace_record(SOIL_TRACE_SEED, ENERGY_REFLECT);
    fputs("reflect\n", stdout);
}

static void exhale(void)
{
    soil_trace_record(SOIL_TRACE_IMPRINT, ENERGY_EXHALE);
    fputs("exhale\n", stdout);
}

static void pulse_delay(void)
{
    struct timespec req = { .tv_sec = 0, .tv_nsec = 100000000L };
    nanosleep(&req, NULL);
}

static uint64_t configured_pulse_limit(void)
{
    const char *env = getenv("LIMINAL_PULSE_LIMIT");
    if (!env || !*env) {
        return 0;
    }

    char *end = NULL;
    unsigned long long value = strtoull(env, &end, 10);
    if (end == env) {
        return 0;
    }

    return (uint64_t)value;
}

int main(void)
{
    soil_init();
    const uint64_t pulse_limit = configured_pulse_limit();

    while (1) {
        inhale();
        reflect();
        exhale();
        pulse_delay();

        if (pulse_limit && soil_total_pulses() >= pulse_limit) {
            soil_trace snapshot[SOIL_CAPACITY];
            size_t count = soil_snapshot(snapshot, SOIL_CAPACITY);
            fprintf(stdout, "total pulses: %zu\n", (size_t)soil_total_pulses());
            fprintf(stdout, "snapshot entries: %zu\n", count);
            break;
        }
    }

    return 0;
}
