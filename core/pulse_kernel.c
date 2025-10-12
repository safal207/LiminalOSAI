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
#include "council.h"
#include "coherence.h"

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
    bool show_council;
    bool show_coherence;
    bool auto_tune;
    bool climate_log;
    uint64_t limit;
    float target_coherence;
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
        .show_council = false,
        .show_coherence = false,
        .auto_tune = false,
        .climate_log = false,
        .limit = 0,
        .target_coherence = 0.80f
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
        } else if (strcmp(arg, "--council") == 0) {
            opts.show_council = true;
        } else if (strcmp(arg, "--coherence") == 0) {
            opts.show_coherence = true;
        } else if (strcmp(arg, "--auto-tune") == 0) {
            opts.auto_tune = true;
        } else if (strcmp(arg, "--climate-log") == 0) {
            opts.climate_log = true;
        } else if (strncmp(arg, "--limit=", 8) == 0) {
            const char *value = arg + 8;
            if (*value) {
                char *end = NULL;
                unsigned long long parsed = strtoull(value, &end, 10);
                if (end != value) {
                    opts.limit = (uint64_t)parsed;
                }
            }
        } else if (strncmp(arg, "--target=", 9) == 0) {
            const char *value = arg + 9;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    if (parsed < 0.0f) {
                        parsed = 0.0f;
                    } else if (parsed > 1.0f) {
                        parsed = 1.0f;
                    }
                    opts.target_coherence = parsed;
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
    double tuned_delay = base_delay * coherence_delay_scale();
    tuned_delay = awareness_adjust_delay(tuned_delay);

    const double min_delay = 0.03;
    const double max_delay = 0.25;
    if (tuned_delay < min_delay) {
        tuned_delay = min_delay;
    } else if (tuned_delay > max_delay) {
        tuned_delay = max_delay;
    }

    coherence_register_delay(tuned_delay);

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
    (void)opts;

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

    fputs("reflect\n", stdout);
}

static void exhale(const kernel_options *opts)
{
    soil_decay();

    const char *label = "exhale";
    soil_trace trace = soil_trace_make(ENERGY_EXHALE, label, strlen(label));
    soil_write(&trace);

    static const char exhale_signal[] = "ebb";
    resonant_msg exhale_msg = resonant_msg_make(SENSOR_EXHALE, RESONANT_BROADCAST_ID, ENERGY_EXHALE, exhale_signal, sizeof(exhale_signal) - 1);
    bus_emit(&exhale_msg);

    size_t activated = symbol_layer_pulse();

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

    reflect_log(energy_avg, resonance_avg, stability, note);

    CouncilOutcome council = council_consult(energy_avg, resonance_avg, stability, active_count);

    awareness_update(resonance_avg, stability);
    AwarenessState awareness_snapshot = awareness_state();
    const CoherenceField *coherence_field = coherence_update(energy_avg, resonance_avg, stability, awareness_snapshot.awareness_level);

    if (opts && opts->show_symbols) {
        if (activated == 0) {
            fputs("symbols: (quiet)\n", stdout);
        } else {
            fputs("symbols:", stdout);
            for (size_t i = 0; i < active_count; ++i) {
                if (!active[i]) {
                    continue;
                }
                fprintf(stdout, " %s(res=%.2f,en=%.2f)", active[i]->key, active[i]->resonance, active[i]->energy);
            }
            fputc('\n', stdout);
        }
    }

    if (opts && opts->show_awareness) {
        double breath = awareness_cycle_duration();
        printf("awareness state | level: %.2f | coherence: %.2f | drift: %.2f | breath: %.3fs%s\n",
               awareness_snapshot.awareness_level,
               awareness_snapshot.self_coherence,
               awareness_snapshot.drift,
               breath,
               awareness_auto_tune_enabled() ? "" : " (manual)");
    }

    if (opts && opts->show_coherence && coherence_field) {
        double delay_ms = coherence_last_delay() * 1000.0;
        if (delay_ms < 0.0) {
            delay_ms = 0.0;
        }
        int delay_whole = (int)(delay_ms + 0.5);
        printf("coh=%.2f | energy=%.2f | res=%.2f | stab=%.2f | aware=%.2f | delay=%dms\n",
               coherence_field->coherence,
               coherence_field->energy_smooth,
               coherence_field->resonance_smooth,
               coherence_field->stability_avg,
               coherence_field->awareness_level,
               delay_whole);
    }

    if (opts && opts->show_council) {
        printf("council | decision: %.2f | variance: %.2f\n", council.decision, council.variance);
        for (size_t i = 0; i < 3; ++i) {
            printf("  %s vote: %.2f\n", council.agents[i].name, council.agents[i].vote);
        }
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
    bus_register_sensor(SENSOR_INHALE);
    bus_register_sensor(SENSOR_REFLECT);
    bus_register_sensor(SENSOR_EXHALE);
    symbol_layer_init();
    awareness_init();
    awareness_set_auto_tune(opts.auto_tune);
    coherence_init();
    coherence_set_target(opts.target_coherence);
    coherence_enable_logging(opts.climate_log);
    council_init();
    council_summon();
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
