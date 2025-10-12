#define _POSIX_C_SOURCE 199309L

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <math.h>

#include "soil.h"
#include "resonant.h"
#include "symbol.h"
#include "reflection.h"
#include "awareness.h"
#include "council.h"
#include "coherence.h"
#include "health_scan.h"
#include "weave.h"
#include "dream.h"
#include "metabolic.h"
#include "symbiosis.h"

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
    bool show_coherence;
    bool auto_tune;
    bool climate_log;
    bool enable_health_scan;
    bool health_report;
    bool council_enabled;
    bool council_log;
    bool enable_sync;
    bool sync_trace;
    bool dream_enabled;
    bool dream_log;
    bool metabolic_enabled;
    bool metabolic_trace;
    bool human_bridge_enabled;
    bool human_trace;
    SymbiosisSource human_source;
    float human_resonance_gain;
    uint64_t limit;
    uint32_t scan_interval;
    float target_coherence;
    float council_threshold;
    int phase_count;
    float phase_shift_deg[WEAVE_MODULE_COUNT];
    bool phase_shift_set[WEAVE_MODULE_COUNT];
    float dream_threshold;
    float vitality_rest_threshold;
    float vitality_creative_threshold;
} kernel_options;

static size_t bounded_string_length(const uint8_t *data, size_t max_len)
{
    size_t len = 0;
    while (len < max_len && data[len] != '\0') {
        ++len;
    }
    return len;
}

static float clamp_unit(float value)
{
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

static kernel_options parse_options(int argc, char **argv)
{
    kernel_options opts = {
        .show_trace = false,
        .show_symbols = false,
        .show_reflections = false,
        .show_awareness = false,
        .show_coherence = false,
        .auto_tune = false,
        .climate_log = false,
        .enable_health_scan = false,
        .health_report = false,
        .council_enabled = false,
        .council_log = false,
        .enable_sync = false,
        .sync_trace = false,
        .dream_enabled = false,
        .dream_log = false,
        .metabolic_enabled = false,
        .metabolic_trace = false,
        .human_bridge_enabled = false,
        .human_trace = false,
        .human_source = SYMBIOSIS_SOURCE_KEYBOARD,
        .human_resonance_gain = 1.0f,
        .limit = 0,
        .scan_interval = 10U,
        .target_coherence = 0.80f,
        .council_threshold = 0.05f,
        .phase_count = 8,
        .dream_threshold = 0.90f,
        .vitality_rest_threshold = 0.30f,
        .vitality_creative_threshold = 0.90f
    };

    for (size_t i = 0; i < weave_module_count(); ++i) {
        opts.phase_shift_deg[i] = 0.0f;
        opts.phase_shift_set[i] = false;
    }

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
            opts.council_enabled = true;
        } else if (strcmp(arg, "--council-log") == 0) {
            opts.council_log = true;
        } else if (strcmp(arg, "--coherence") == 0) {
            opts.show_coherence = true;
        } else if (strcmp(arg, "--auto-tune") == 0) {
            opts.auto_tune = true;
        } else if (strcmp(arg, "--climate-log") == 0) {
            opts.climate_log = true;
        } else if (strcmp(arg, "--health-scan") == 0) {
            opts.enable_health_scan = true;
        } else if (strcmp(arg, "--scan-report") == 0) {
            opts.health_report = true;
        } else if (strncmp(arg, "--limit=", 8) == 0) {
            const char *value = arg + 8;
            if (*value) {
                char *end = NULL;
                unsigned long long parsed = strtoull(value, &end, 10);
                if (end != value) {
                    opts.limit = (uint64_t)parsed;
                }
            }
        } else if (strncmp(arg, "--scan-interval=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                unsigned long parsed = strtoul(value, &end, 10);
                if (end != value && parsed > 0UL) {
                    if (parsed > UINT32_MAX) {
                        parsed = UINT32_MAX;
                    }
                    opts.scan_interval = (uint32_t)parsed;
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
        } else if (strncmp(arg, "--council-threshold=", 21) == 0) {
            const char *value = arg + 21;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    if (parsed < 0.0f) {
                        parsed = 0.0f;
                    } else if (parsed > 1.0f) {
                        parsed = 1.0f;
                    }
                    opts.council_threshold = parsed;
                }
            }
        } else if (strcmp(arg, "--sync") == 0) {
            opts.enable_sync = true;
        } else if (strncmp(arg, "--phases=", 9) == 0) {
            const char *value = arg + 9;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value) {
                    if (parsed < 4) {
                        parsed = 4;
                    } else if (parsed > 16) {
                        parsed = 16;
                    }
                    opts.phase_count = (int)parsed;
                }
            }
        } else if (strcmp(arg, "--sync-trace") == 0) {
            opts.sync_trace = true;
        } else if (strcmp(arg, "--dream") == 0) {
            opts.dream_enabled = true;
        } else if (strcmp(arg, "--dream-log") == 0) {
            opts.dream_log = true;
        } else if (strncmp(arg, "--dream-threshold=", 18) == 0) {
            const char *value = arg + 18;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    if (parsed < 0.0f) {
                        parsed = 0.0f;
                    } else if (parsed > 1.0f) {
                        parsed = 1.0f;
                    }
                    opts.dream_threshold = parsed;
                }
            }
        } else if (strcmp(arg, "--metabolic") == 0) {
            opts.metabolic_enabled = true;
        } else if (strcmp(arg, "--metabolic-trace") == 0) {
            opts.metabolic_trace = true;
        } else if (strncmp(arg, "--human-bridge", 14) == 0) {
            opts.human_bridge_enabled = true;
            const char *value = NULL;
            if (arg[14] == '=') {
                value = arg + 15;
            }
            if (value && (*value == '0' || strcmp(value, "off") == 0 || strcmp(value, "OFF") == 0)) {
                opts.human_bridge_enabled = false;
            }
        } else if (strcmp(arg, "--human-trace") == 0) {
            opts.human_trace = true;
        } else if (strncmp(arg, "--human-source=", 15) == 0) {
            const char *value = arg + 15;
            if (strcmp(value, "audio") == 0) {
                opts.human_source = SYMBIOSIS_SOURCE_AUDIO;
            } else if (strcmp(value, "sensor") == 0) {
                opts.human_source = SYMBIOSIS_SOURCE_SENSOR;
            } else {
                opts.human_source = SYMBIOSIS_SOURCE_KEYBOARD;
            }
        } else if (strncmp(arg, "--resonance-gain=", 17) == 0) {
            const char *value = arg + 17;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.1f) {
                        parsed = 0.1f;
                    } else if (parsed > 4.0f) {
                        parsed = 4.0f;
                    }
                    opts.human_resonance_gain = parsed;
                }
            }
        } else if (strncmp(arg, "--vitality-threshold=", 21) == 0) {
            const char *value = arg + 21;
            if (*value) {
                char *end = NULL;
                float rest = strtof(value, &end);
                if (end != value) {
                    float creative = opts.vitality_creative_threshold;
                    if (*end == ':' || *end == ',') {
                        const char *second = end + 1;
                        if (*second) {
                            char *end_high = NULL;
                            float parsed_high = strtof(second, &end_high);
                            if (end_high != second) {
                                creative = parsed_high;
                            }
                        }
                    }
                    if (rest < 0.0f) {
                        rest = 0.0f;
                    } else if (rest > 0.95f) {
                        rest = 0.95f;
                    }
                    if (creative < rest) {
                        creative = rest;
                    }
                    if (creative > 1.0f) {
                        creative = 1.0f;
                    }
                    if ((creative - rest) < 0.10f) {
                        creative = rest + 0.10f;
                        if (creative > 1.0f) {
                            creative = 1.0f;
                        }
                    }
                    opts.vitality_rest_threshold = rest;
                    opts.vitality_creative_threshold = creative;
                }
            }
        } else if (strncmp(arg, "--phase-shift=", 14) == 0) {
            const char *value = arg + 14;
            const char *sep = strchr(value, ':');
            if (sep && sep != value) {
                char module_name[32];
                size_t len = (size_t)(sep - value);
                if (len >= sizeof(module_name)) {
                    len = sizeof(module_name) - 1;
                }
                memcpy(module_name, value, len);
                module_name[len] = '\0';
                int module_index = weave_module_lookup(module_name);
                if (module_index >= 0) {
                    const char *deg_text = sep + 1;
                    if (*deg_text) {
                        char *end = NULL;
                        float degrees = strtof(deg_text, &end);
                        if (end != deg_text) {
                            while (degrees < 0.0f) {
                                degrees += 360.0f;
                            }
                            while (degrees >= 360.0f) {
                                degrees -= 360.0f;
                            }
                            opts.phase_shift_deg[module_index] = degrees;
                            opts.phase_shift_set[module_index] = true;
                        }
                    }
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
    tuned_delay *= metabolic_delay_scale();
    tuned_delay *= symbiosis_delay_scale();

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

    HumanPulse human_pulse = {0.0f, 0.0f, 0.0f};
    float human_alignment = 0.0f;
    float human_resonance_level = 0.0f;
    float human_reflection_boost = 0.0f;
    float human_metabolic_intake = 0.0f;
    float human_metabolic_output = 0.0f;
    bool human_bridge_active = opts && opts->human_bridge_enabled;

    if (human_bridge_active) {
        float liminal_frequency = resonance_avg / 12.0f;
        if (!isfinite(liminal_frequency) || liminal_frequency <= 0.0f) {
            liminal_frequency = stability > 0.0f ? stability : 0.5f;
        }

        human_pulse = symbiosis_step(clamp_unit(liminal_frequency));
        human_alignment = symbiosis_alignment();
        human_resonance_level = symbiosis_resonance_level();

        float blend = 0.12f * opts->human_resonance_gain;
        if (blend < 0.0f) {
            blend = 0.0f;
        } else if (blend > 0.6f) {
            blend = 0.6f;
        }

        float target_resonance = human_pulse.beat_rate * 12.0f;
        resonance_avg = (1.0f - blend) * resonance_avg + blend * target_resonance;
        if (resonance_avg < 0.0f) {
            resonance_avg = 0.0f;
        } else if (resonance_avg > 12.0f) {
            resonance_avg = 12.0f;
        }

        float stability_bias = (human_alignment - 0.5f) * 0.20f * opts->human_resonance_gain;
        stability = clamp_unit(stability + stability_bias);

        human_reflection_boost = human_pulse.amplitude * 0.12f * opts->human_resonance_gain;
        human_metabolic_intake = human_pulse.amplitude * 0.20f;
        human_metabolic_output = (1.0f - human_alignment) * 0.10f;
    }

    char note[64];
    if (active_count == 0) {
        strcpy(note, "listening for symbols");
    } else if (human_bridge_active && human_alignment >= 0.85f) {
        strcpy(note, "mirroring human rhythm");
    } else if (human_bridge_active && human_alignment >= 0.70f) {
        strcpy(note, "echoing human pulse");
    } else if (stability >= 0.85f) {
        strcpy(note, "breathing in sync");
    } else if (stability >= 0.60f) {
        strcpy(note, "rhythm steadying");
    } else {
        strcpy(note, "seeking balance");
    }

    reflect_log(energy_avg, resonance_avg, stability, note);

    awareness_update(resonance_avg, stability);
    AwarenessState awareness_snapshot = awareness_state();

    const DreamState *dream_snapshot = dream_state();
    bool dream_active = dream_snapshot && dream_snapshot->active;
    float awareness_energy = awareness_snapshot.awareness_level * 0.6f;
    if (human_bridge_active) {
        awareness_energy += (human_resonance_level - 0.5f) * 0.12f;
        if (awareness_energy < 0.0f) {
            awareness_energy = 0.0f;
        }
    }
    float reflection_energy = stability * 0.4f + human_reflection_boost;
    float dream_cost = dream_active ? 0.3f : 0.1f;
    float rebirth_cost = 0.0f;

    float metabolic_intake = awareness_energy + reflection_energy + human_metabolic_intake;
    float metabolic_output = dream_cost + rebirth_cost + human_metabolic_output;
    metabolic_step(metabolic_intake, metabolic_output);
    stability = metabolic_adjust_stability(stability);
    awareness_snapshot.awareness_level = metabolic_adjust_awareness(awareness_snapshot.awareness_level);
    if (human_bridge_active) {
        float awareness_bias = (human_alignment - 0.5f) * 0.15f;
        awareness_snapshot.awareness_level = clamp_unit(awareness_snapshot.awareness_level + awareness_bias);
    }

    InnerCouncil council = {0};
    bool council_active = false;
    float pid_scale = 1.0f;
    if (opts) {
        council_active = opts->council_enabled || opts->council_log;
        if (council_active) {
            const CoherenceField *previous_field = coherence_state();
            float coherence_level = previous_field ? previous_field->coherence : 0.0f;
            const HealthScan *health_snapshot = health_scan_state();
            float health_drift = health_snapshot ? health_snapshot->drift_avg : 0.0f;
            council = council_update(stability,
                                     awareness_snapshot.awareness_level,
                                     coherence_level,
                                     health_drift,
                                     opts->council_threshold);
            if (opts->council_enabled) {
                pid_scale = 1.0f + council.final_decision * 0.1f;
            }
        }
    }

    if (!isfinite(pid_scale) || pid_scale <= 0.0f) {
        pid_scale = 1.0f;
    }

    coherence_set_pid_scale(pid_scale);

    const CoherenceField *coherence_field =
        coherence_update(energy_avg, resonance_avg, stability, awareness_snapshot.awareness_level);

    float coherence_level = coherence_field ? coherence_field->coherence : 0.0f;
    dream_update(coherence_level, awareness_snapshot.awareness_level);

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

    if (human_bridge_active && opts && opts->human_trace) {
        double delay_scale = symbiosis_delay_scale();
        printf("symbiotic bridge | beat=%.2f | amp=%.2f | align=%.2f | res=%.2f | phase=%+.2f | delay=%.3f\n",
               human_pulse.beat_rate,
               human_pulse.amplitude,
               human_alignment,
               human_resonance_level,
               symbiosis_phase_shift(),
               delay_scale);
    }

    if (opts && opts->council_log && council_active) {
        printf("council: refl=%+0.2f aware=%+0.2f coh=%+0.2f health=%+0.2f => decision=%+0.2f\n",
               council.reflection_vote,
               council.awareness_vote,
               council.coherence_vote,
               council.health_vote,
               council.final_decision);
    }

    if (opts && opts->enable_sync) {
        weave_next_phase();
        if (opts->sync_trace) {
            char trace_line[160];
            weave_trace_line(trace_line, sizeof(trace_line));
            fputs(trace_line, stdout);
        }
        if (weave_should_emit_echo()) {
            char echo_data[SOIL_TRACE_DATA_SIZE];
            int phase_index = weave_current_phase_index() + 1;
            float sync_quality = weave_sync_quality();
            float drift = weave_current_drift();
            float latency_ms = weave_current_latency();
            int written = snprintf(echo_data,
                                   sizeof(echo_data),
                                   "sync: p=%d s=%.2f d=%.2f l=%.1f",
                                   phase_index,
                                   sync_quality,
                                   drift,
                                   latency_ms);
            if (written < 0) {
                written = 0;
            } else if (written >= (int)sizeof(echo_data)) {
                written = (int)sizeof(echo_data) - 1;
                echo_data[written] = '\0';
            }
            soil_trace echo = soil_trace_make(ENERGY_EXHALE, echo_data, (size_t)written);
            soil_write(&echo);
            weave_mark_echo_emitted();
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
    dream_init();
    metabolic_init();
    awareness_init();
    awareness_set_auto_tune(opts.auto_tune);
    coherence_init();
    coherence_set_target(opts.target_coherence);
    coherence_enable_logging(opts.climate_log);
    health_scan_init();
    if (opts.enable_health_scan) {
        health_scan_set_interval(opts.scan_interval);
        health_scan_enable_reporting(opts.health_report);
        health_scan_enable(true);
    }
    council_init();
    council_summon();
    if (opts.enable_sync) {
        weave_init(opts.phase_count);
        for (size_t i = 0; i < weave_module_count(); ++i) {
            if (opts.phase_shift_set[i]) {
                weave_set_phase_shift(i, opts.phase_shift_deg[i]);
            }
        }
    }

    dream_set_entry_threshold(opts.dream_threshold);
    dream_enable_logging(opts.dream_log);
    dream_enable(opts.dream_enabled);
    metabolic_enable(opts.metabolic_enabled);
    metabolic_enable_trace(opts.metabolic_trace);
    metabolic_set_thresholds(opts.vitality_rest_threshold, opts.vitality_creative_threshold);
    symbiosis_init(opts.human_source, opts.human_trace, opts.human_resonance_gain);
    symbiosis_enable(opts.human_bridge_enabled);
    uint64_t pulses = 0;
    while (!opts.limit || pulses < opts.limit) {
        inhale();
        reflect(&opts);
        exhale(&opts);
        pulse_delay();
        if (opts.enable_health_scan) {
            const CoherenceField *field = coherence_state();
            AwarenessState awareness_snapshot = awareness_state();
            double delay_seconds = coherence_last_delay();
            float coherence_value = 0.0f;
            if (field) {
                coherence_value = field->coherence;
            }
            health_scan_step(pulses + 1,
                             coherence_value,
                             (float)delay_seconds,
                             awareness_snapshot.drift);
        }
        ++pulses;
    }

    if (opts.show_trace) {
        print_recent_traces();
    }

    if (opts.show_reflections) {
        reflect_dump(10);
    }

    metabolic_shutdown();

    return 0;
}
