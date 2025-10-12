#define _POSIX_C_SOURCE 199309L

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "soil.h"
#include "resonant.h"
#include "symbol.h"
#include "reflection.h"
#include "awareness.h"

#define ENERGY_INHALE   3U
#define ENERGY_REFLECT  5U
#define ENERGY_EXHALE   2U

#define SENSOR_INHALE   1
#define SENSOR_REFLECT  2
#define SENSOR_EXHALE   3

typedef struct {
    bool show_trace;
    bool show_symbols;
    bool show_reflections;
    bool show_awareness;
    bool auto_tune;
    uint64_t limit;
} kernel_options;

static size_t bounded_string_length(const uint8_t *data, size_t max_len)
{
    size_t len = 0;
    while (len < max_len && data[len] != '\0') {
        ++len;
    }
    return len;
}

static kernel_options parse_options(int argc, char **argv)
{
    kernel_options opts = {
        .show_trace = false,
        .show_symbols = false,
        .show_reflections = false,
        .show_awareness = false,
        .auto_tune = false,
        .limit = 0
    };

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "--trace") == 0) {
            opts.show_trace = true;
        } else if (strcmp(arg, "--symbols") == 0) {
            opts.show_symbols = true;
        } else if (strcmp(arg, "--reflect") == 0) {
            opts.show_reflections = true;
        } else if (strcmp(arg, "--awareness") == 0) {
            opts.show_awareness = true;
        } else if (strcmp(arg, "--auto-tune") == 0) {
            opts.auto_tune = true;
        } else if (strncmp(arg, "--limit=", 8) == 0) {
            const char *value = arg + 8;
            if (*value) {
                char *end = NULL;
                unsigned long long parsed = strtoull(value, &end, 10);
                if (end != value) {
                    opts.limit = (uint64_t)parsed;
                }
            }
        }
    }

    if (!opts.limit) {
        const char *env = getenv("LIMINAL_PULSE_LIMIT");
        if (env && *env) {
            char *end = NULL;
            unsigned long long parsed = strtoull(env, &end, 10);
            if (end != env) {
                opts.limit = (uint64_t)parsed;
            }
        }
    }

    return opts;
}

static void pulse_delay(void)
{
    const double base_delay = 0.1;
    double tuned_delay = awareness_adjust_delay(base_delay);

    if (tuned_delay < 0.001) {
        tuned_delay = 0.001;
    }

    time_t seconds = (time_t)tuned_delay;
    long nanoseconds = (long)((tuned_delay - (double)seconds) * 1000000000.0);
    if (nanoseconds < 0) {
        nanoseconds = 0;
    }
    if (nanoseconds >= 1000000000L) {
        seconds += nanoseconds / 1000000000L;
        nanoseconds %= 1000000000L;
    }
    if (seconds == 0 && nanoseconds == 0) {
        nanoseconds = 1000000L;
    }

    struct timespec req = { .tv_sec = seconds, .tv_nsec = nanoseconds };
    nanosleep(&req, NULL);
}

static void inhale(void)
{
    const char *label = "inhale";
    soil_trace trace = soil_trace_make(ENERGY_INHALE, label, strlen(label));
    soil_write(&trace);

    static const char inhale_signal[] = "rise";
    resonant_msg inhale_msg = resonant_msg_make(SENSOR_INHALE, SENSOR_REFLECT, ENERGY_INHALE, inhale_signal, sizeof(inhale_signal) - 1);
    bus_emit(&inhale_msg);

    fputs("inhale\n", stdout);
}

static void reflect(const kernel_options *opts)
{
    const char *label = "reflect";
    soil_trace trace = soil_trace_make(ENERGY_REFLECT, label, strlen(label));
    soil_write(&trace);

    resonant_msg message;
    resonant_msg pending_echoes[RESONANT_BUS_CAPACITY];
    size_t pending_count = 0;

    for (int sensor = SENSOR_INHALE; sensor <= SENSOR_EXHALE; ++sensor) {
        while (bus_listen(sensor, &message)) {
            char imprint[SOIL_TRACE_DATA_SIZE];
            int written = snprintf(imprint, sizeof(imprint), "S%d->S%d:%u", message.source_id, message.target_id, message.energy);
            if (written < 0) {
                imprint[0] = '\0';
                written = 0;
            }

            soil_trace echo = soil_trace_make(message.energy, imprint, (size_t)written);
            soil_write(&echo);

            size_t payload_len = bounded_string_length(message.payload, RESONANT_MSG_DATA_SIZE);
            if (payload_len > 0 && message.energy > 1 && pending_count < RESONANT_BUS_CAPACITY) {
                pending_echoes[pending_count++] = resonant_msg_make(sensor, RESONANT_BROADCAST_ID, message.energy - 1, message.payload, payload_len);
            }
        }
    }

    for (size_t i = 0; i < pending_count; ++i) {
        bus_emit(&pending_echoes[i]);
    }

    size_t activated = symbol_layer_pulse();

    fputs("reflect\n", stdout);

    if (opts && opts->show_symbols) {
        if (activated == 0) {
            fputs("symbols: (quiet)\n", stdout);
        } else {
            const Symbol *active[16];
            size_t count = symbol_layer_active(active, sizeof(active) / sizeof(active[0]));
            fputs("symbols:", stdout);
            for (size_t i = 0; i < count; ++i) {
                fprintf(stdout, " %s(res=%.2f,en=%.2f)", active[i]->key, active[i]->resonance, active[i]->energy);
            }
            fputc('\n', stdout);
        }
    }
}

static void exhale(const kernel_options *opts)
{
    const Symbol *active[16];
    size_t active_count = symbol_layer_active(active, sizeof(active) / sizeof(active[0]));

    float energy_sum = 0.0f;
    float resonance_sum = 0.0f;
    for (size_t i = 0; i < active_count; ++i) {
        if (!active[i]) {
            continue;
        }
        energy_sum += active[i]->energy;
        resonance_sum += active[i]->resonance;
    }

    float energy_avg = 0.0f;
    float resonance_avg = 0.0f;
    if (active_count > 0) {
        energy_avg = energy_sum / (float)active_count;
        resonance_avg = resonance_sum / (float)active_count;
    }

    float stability = 0.0f;
    if (active_count > 0) {
        const float max_signal = 12.0f;
        float energy_norm = energy_avg / max_signal;
        float resonance_norm = resonance_avg / max_signal;
        if (energy_norm > 1.0f) {
            energy_norm = 1.0f;
        }
        if (resonance_norm > 1.0f) {
            resonance_norm = 1.0f;
        }
        float presence = (float)active_count / 4.0f;
        if (presence > 1.0f) {
            presence = 1.0f;
        }
        stability = (energy_norm + resonance_norm) * 0.45f + presence * 0.10f;
        if (stability > 1.0f) {
            stability = 1.0f;
        }
    }

    char note[64];
    if (active_count == 0) {
        strcpy(note, "listening for symbols");
    } else if (stability >= 0.85f) {
        strcpy(note, "breathing in sync");
    } else if (stability >= 0.60f) {
        strcpy(note, "rhythm steadying");
    } else {
        strcpy(note, "seeking balance");
    }

    soil_decay();

    const char *label = "exhale";
    soil_trace trace = soil_trace_make(ENERGY_EXHALE, label, strlen(label));
    soil_write(&trace);

    static const char exhale_signal[] = "ebb";
    resonant_msg exhale_msg = resonant_msg_make(SENSOR_EXHALE, RESONANT_BROADCAST_ID, ENERGY_EXHALE, exhale_signal, sizeof(exhale_signal) - 1);
    bus_emit(&exhale_msg);

    reflect_log(energy_avg, resonance_avg, stability, note);

    awareness_update(resonance_avg, stability);

    if (opts && opts->show_awareness) {
        AwarenessState state = awareness_state();
        double breath = awareness_cycle_duration();
        printf("awareness state | level: %.2f | coherence: %.2f | drift: %.2f | breath: %.3fs%s\n",
               state.awareness_level,
               state.self_coherence,
               state.drift,
               breath,
               awareness_auto_tune_enabled() ? "" : " (manual)");
    }

    fputs("exhale\n", stdout);
}

static void print_recent_traces(void)
{
    soil_trace last[5];
    size_t count = soil_recent(last, 5);

    if (count == 0) {
        fputs("Memory Soil is quiet.\n", stdout);
        return;
    }

    fputs("Memory Soil traces:\n", stdout);
    for (size_t i = 0; i < count; ++i) {
        char data_text[SOIL_TRACE_DATA_SIZE + 1];
        memcpy(data_text, last[i].data, SOIL_TRACE_DATA_SIZE);
        data_text[SOIL_TRACE_DATA_SIZE] = '\0';
        size_t len = bounded_string_length((const uint8_t *)data_text, SOIL_TRACE_DATA_SIZE);
        data_text[len] = '\0';

        fprintf(stdout, "  [%zu] t=%" PRIu64 " energy=%u data=\"%s\"\n", i, last[i].timestamp, last[i].energy, data_text);
    }
}

int main(int argc, char **argv)
{
    kernel_options opts = parse_options(argc, argv);

    soil_init();
    bus_init();
    symbol_layer_init();
    awareness_init();
    awareness_set_auto_tune(opts.auto_tune);
    uint64_t pulses = 0;
    while (!opts.limit || pulses < opts.limit) {
        inhale();
        reflect(&opts);
        exhale(&opts);
        pulse_delay();
        ++pulses;
    }

    if (opts.show_trace) {
        print_recent_traces();
    }

    if (opts.show_reflections) {
        reflect_dump(10);
    }

    return 0;
}
