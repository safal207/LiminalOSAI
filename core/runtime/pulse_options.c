#include "pulse_options.h"

#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "options_defaults.h"
#include "runtime_values.h"

static void parse_affinity_config(Affinity *aff, const char *value)
{
    if (!aff || !value) {
        return;
    }

    char buffer[128];
    strncpy(buffer, value, sizeof(buffer) - 1U);
    buffer[sizeof(buffer) - 1U] = '\0';

    char *token = strtok(buffer, ",");
    while (token) {
        while (*token == ' ') {
            ++token;
        }
        char *colon = strchr(token, ':');
        if (colon && colon[1] != '\0') {
            *colon = '\0';
            const char *name = token;
            const char *val_text = colon + 1;
            char *end = NULL;
            float parsed = strtof(val_text, &end);
            if (end != val_text && isfinite(parsed)) {
                float clamped = clamp_unit(parsed);
                if (strcmp(name, "care") == 0) {
                    aff->care = clamped;
                } else if (strcmp(name, "respect") == 0) {
                    aff->respect = clamped;
                } else if (strcmp(name, "presence") == 0) {
                    aff->presence = clamped;
                }
            }
        }
        token = strtok(NULL, ",");
    }
}

static void parse_kiss_thresholds(kernel_options *opts, const char *value)
{
    if (!opts || !value) {
        return;
    }

    char buffer[128];
    strncpy(buffer, value, sizeof(buffer) - 1U);
    buffer[sizeof(buffer) - 1U] = '\0';

    char *token = strtok(buffer, ",");
    while (token) {
        while (*token && isspace((unsigned char)*token)) {
            ++token;
        }
        char *colon = strchr(token, ':');
        if (colon && colon[1] != '\0') {
            *colon = '\0';
            const char *name = token;
            const char *val_text = colon + 1;
            while (*val_text && isspace((unsigned char)*val_text)) {
                ++val_text;
            }
            char *end = NULL;
            float parsed = strtof(val_text, &end);
            if (end != val_text && isfinite(parsed)) {
                float clamped = clamp_unit(parsed);
                if (strcmp(name, "trust") == 0 || strcmp(name, "tr") == 0) {
                    opts->kiss_trust_threshold = clamped;
                } else if (strcmp(name, "pres") == 0 || strcmp(name, "presence") == 0) {
                    opts->kiss_presence_threshold = clamped;
                } else if (strcmp(name, "harm") == 0 || strcmp(name, "harmony") == 0) {
                    opts->kiss_harmony_threshold = clamped;
                }
            }
        }
        token = strtok(NULL, ",");
    }
}

kernel_options pulse_options_parse(int argc, char **argv)
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
        .balancer_enabled = false,
        .metabolic_enabled = false,
        .metabolic_trace = false,
        .human_bridge_enabled = false,
        .human_trace = false,
        .human_source = SYMBIOSIS_SOURCE_KEYBOARD,
        .human_resonance_gain = 1.0f,
        .empathic_enabled = false,
        .empathic_trace = false,
        .anticipation_trace = false,
        .anticipation2_enabled = false,
        .ant2_trace = false,
        .ant2_gain = 0.6f,
        .emotional_source = EMPATHIC_SOURCE_AUDIO,
        .empathy_gain = 1.0f,
        .emotional_memory_enabled = false,
        .memory_trace = false,
        .recognition_threshold = 0.18f,
        .emotion_trace_path = {0},
        .limit = 0,
        .scan_interval = 10U,
        .target_coherence = 0.80f,
        .collective_enabled = false,
        .collective_trace = false,
        .collective_memory_enabled = false,
        .collective_memory_trace = false,
        .cm_snapshot_interval = 20,
        .cm_path = {0},
        .group_target = 0.82f,
        .ensemble_mode = ENSEMBLE_STRATEGY_MEDIAN,
        .council_threshold = 0.05f,
        .phase_count = 8,
        .dream_threshold = 0.90f,
        .vitality_rest_threshold = 0.30f,
        .vitality_creative_threshold = 0.90f,
        .affinity_enabled = false,
        .bond_trace_enabled = false,
        .affinity_config = {0.0f, 0.0f, 0.0f},
        .allow_align_consent = 0.2f,
        .mirror_enabled = false,
        .mirror_trace = false,
        .mirror_softness = 0.5f,
        .mirror_amp_min = MIRROR_GAIN_AMP_MIN_DEFAULT,
        .mirror_amp_max = MIRROR_GAIN_AMP_MAX_DEFAULT,
        .mirror_tempo_min = MIRROR_GAIN_TEMPO_MIN_DEFAULT,
        .mirror_tempo_max = MIRROR_GAIN_TEMPO_MAX_DEFAULT,
        .introspect_enabled = false,
        .harmony_enabled = false,
        .qel_enabled = false,
        .qel_retro_gain = 0.0f,
        .entangle_ctx = 0U,
        .astro_enabled = false,
        .astro_trace = false,
        .astro_rate = 0.010f,
        .astro_tone_init = 0.0f,
        .astro_memory_init = 0.0f,
        .astro_tone_set = false,
        .astro_memory_set = false,
        .trs_enabled = false,
        .trs_alpha = 0.3f,
        .trs_warmup = 5,
        .trs_adapt_enabled = false,
        .trs_alpha_min = 0.10f,
        .trs_alpha_max = 0.60f,
        .trs_target_delta = 0.015f,
        .trs_kp = 0.4f,
        .trs_ki = 0.05f,
        .trs_kd = 0.1f,
        .kiss_enabled = false,
        .kiss_trust_threshold = 0.80f,
        .kiss_presence_threshold = 0.70f,
        .kiss_harmony_threshold = 0.85f,
        .kiss_warmup_cycles = 10,
        .kiss_refractory_cycles = 5,
        .kiss_alpha = 0.25f,
        .consent_gate_open_threshold = 0.75f,
        .consent_gate_close_threshold = 0.60f,
        .consent_gate_hysteresis = 0.05f,
        .consent_gate_bias = 0.0f,
        .consent_gate_warmup_cycles = 8,
        .consent_gate_refractory_cycles = 6,
        .vse_enabled = false,
        .vse_trace = false,
        .vse_temp = 1.0f,
        .vse_intent = 0.6f,
        .vse_importance = 0.4f,
        .vse_allowance = 0.3f,
        .vse_lambda_p = 0.2f,
        .vse_lambda_x = 0.4f,
        .vse_allowance_hold = 0.0f,
        .vse_allowance_pulse = 0.0f,
        .strict_order = false,
        .dry_run = false
    };

    for (size_t i = 0; i < weave_module_count(); ++i) {
        opts.phase_shift_deg[i] = 0.0f;
        opts.phase_shift_set[i] = false;
    }

    affinity_default(&opts.affinity_config);

    if (!opts.cm_path[0]) {
        const char *default_path = "soil/collective_memory.jsonl";
        strncpy(opts.cm_path, default_path, sizeof(opts.cm_path) - 1);
        opts.cm_path[sizeof(opts.cm_path) - 1] = '\0';
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
        } else if (strcmp(arg, "--collective") == 0) {
            opts.collective_enabled = true;
        } else if (strcmp(arg, "--collective-trace") == 0) {
            opts.collective_trace = true;
        } else if (strcmp(arg, "--collective-memory") == 0) {
            opts.collective_memory_enabled = true;
        } else if (strcmp(arg, "--cm-trace") == 0) {
            opts.collective_memory_trace = true;
        } else if (strncmp(arg, "--cm-path=", 10) == 0) {
            const char *value = arg + 10;
            if (value && *value) {
                strncpy(opts.cm_path, value, sizeof(opts.cm_path) - 1);
                opts.cm_path[sizeof(opts.cm_path) - 1] = '\0';
            }
        } else if (strncmp(arg, "--cm-snapshot-interval=", 24) == 0) {
            const char *value = arg + 24;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed > 0) {
                    if (parsed > INT_MAX) {
                        parsed = INT_MAX;
                    }
                    opts.cm_snapshot_interval = (int)parsed;
                }
            }
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
        } else if (strncmp(arg, "--group-target=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    if (parsed < 0.0f) {
                        parsed = 0.0f;
                    } else if (parsed > 1.0f) {
                        parsed = 1.0f;
                    }
                    opts.group_target = parsed;
                }
            }
        } else if (strncmp(arg, "--ensemble-strategy=", 20) == 0) {
            const char *value = arg + 20;
            if (value && *value) {
                if (strcmp(value, "avg") == 0) {
                    opts.ensemble_mode = ENSEMBLE_STRATEGY_AVG;
                } else if (strcmp(value, "median") == 0) {
                    opts.ensemble_mode = ENSEMBLE_STRATEGY_MEDIAN;
                } else if (strcmp(value, "leader") == 0) {
                    opts.ensemble_mode = ENSEMBLE_STRATEGY_LEADER;
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
        } else if (strcmp(arg, "--dreamsync") == 0) {
            opts.dream_enabled = true;
            opts.enable_sync = true;
        } else if (strcmp(arg, "--dream-log") == 0) {
            opts.dream_log = true;
        } else if (strcmp(arg, "--balancer") == 0) {
            opts.balancer_enabled = true;
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
        } else if (strcmp(arg, "--empathic") == 0) {
            opts.empathic_enabled = true;
        } else if (strcmp(arg, "--empathic-trace") == 0) {
            opts.empathic_trace = true;
        } else if (strcmp(arg, "--anticipation") == 0) {
            opts.empathic_enabled = true;
            opts.anticipation_trace = true; // merged by Codex
        } else if (strcmp(arg, "--anticipation2") == 0) {
            opts.anticipation2_enabled = true;
        } else if (strcmp(arg, "--ant2-trace") == 0) {
            opts.anticipation2_enabled = true;
            opts.ant2_trace = true;
        } else if (strncmp(arg, "--ant2-gain=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.0f) {
                        parsed = 0.0f;
                    } else if (parsed > 1.0f) {
                        parsed = 1.0f;
                    }
                    opts.anticipation2_enabled = true;
                    opts.ant2_gain = parsed;
                }
            }
        } else if (strcmp(arg, "--affinity") == 0) {
            opts.affinity_enabled = true;
        } else if (strncmp(arg, "--affinity-cfg=", 15) == 0) {
            const char *value = arg + 15;
            if (value && *value) {
                parse_affinity_config(&opts.affinity_config, value);
            }
        } else if (strncmp(arg, "--allow-align=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.0f) {
                        parsed = 0.0f;
                    } else if (parsed > 1.0f) {
                        parsed = 1.0f;
                    }
                    opts.allow_align_consent = parsed;
                }
            }
        } else if (strcmp(arg, "--bond-trace") == 0) {
            opts.bond_trace_enabled = true;
        } else if (strcmp(arg, "--mirror") == 0) {
            opts.mirror_enabled = true;
        } else if (strcmp(arg, "--mirror-trace") == 0) {
            opts.mirror_trace = true;
        } else if (strcmp(arg, "--introspect") == 0) {
            opts.introspect_enabled = true;
        } else if (strcmp(arg, "--harmony") == 0) {
            opts.harmony_enabled = true;
        } else if (strcmp(arg, "--qel") == 0) {
            opts.qel_enabled = true;
        } else if (strncmp(arg, "--qel-retro=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.qel_retro_gain = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--entangle-ctx=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                unsigned long parsed = strtoul(value, &end, 0);
                if (end != value) {
                    opts.entangle_ctx = (uint32_t)parsed;
                }
            }
        } else if (strcmp(arg, "--astro") == 0) {
            opts.astro_enabled = true;
        } else if (strcmp(arg, "--astro-trace") == 0) {
            opts.astro_trace = true;
            opts.astro_enabled = true;
        } else if (strncmp(arg, "--astro-rate=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.astro_rate = clamp_range(parsed, 0.005f, 0.020f);
                }
            }
        } else if (strncmp(arg, "--astro-tone=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.astro_tone_init = clamp_unit(parsed);
                    opts.astro_tone_set = true;
                }
            }
        } else if (strncmp(arg, "--astro-mem=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.astro_memory_init = clamp_unit(parsed);
                    opts.astro_memory_set = true;
                }
            }
        } else if (strcmp(arg, "--kiss") == 0) {
            opts.kiss_enabled = true;
        } else if (strncmp(arg, "--kiss-thr=", 11) == 0) {
            const char *value = arg + 11;
            if (value && *value) {
                parse_kiss_thresholds(&opts, value);
            }
        } else if (strncmp(arg, "--kiss-warmup=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed >= 0L) {
                    if (parsed > 255L) {
                        parsed = 255L;
                    }
                    opts.kiss_warmup_cycles = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--kiss-refrac=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed >= 0L) {
                    if (parsed > 255L) {
                        parsed = 255L;
                    }
                    opts.kiss_refractory_cycles = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--kiss-alpha=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed) && parsed > 0.0f) {
                    if (parsed > 1.0f) {
                        parsed = 1.0f;
                    }
                    opts.kiss_alpha = parsed;
                }
            }
        } else if (strncmp(arg, "--gate-open=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.0f) {
                        parsed = 0.0f;
                    } else if (parsed > 1.0f) {
                        parsed = 1.0f;
                    }
                    opts.consent_gate_open_threshold = parsed;
                }
            }
        } else if (strncmp(arg, "--gate-close=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.0f) {
                        parsed = 0.0f;
                    } else if (parsed > 1.0f) {
                        parsed = 1.0f;
                    }
                    opts.consent_gate_close_threshold = parsed;
                }
            }
        } else if (strncmp(arg, "--gate-hyst=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.0f) {
                        parsed = 0.0f;
                    } else if (parsed > 0.5f) {
                        parsed = 0.5f;
                    }
                    opts.consent_gate_hysteresis = parsed;
                }
            }
        } else if (strncmp(arg, "--gate-bias=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < -0.5f) {
                        parsed = -0.5f;
                    } else if (parsed > 0.5f) {
                        parsed = 0.5f;
                    }
                    opts.consent_gate_bias = parsed;
                }
            }
        } else if (strncmp(arg, "--gate-warmup=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed >= 0L) {
                    if (parsed > 255L) {
                        parsed = 255L;
                    }
                    opts.consent_gate_warmup_cycles = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--gate-refrac=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed >= 0L) {
                    if (parsed > 255L) {
                        parsed = 255L;
                    }
                    opts.consent_gate_refractory_cycles = (int)parsed;
                }
            }
        } else if (strcmp(arg, "--vse") == 0) {
            opts.vse_enabled = true;
        } else if (strcmp(arg, "--vse-trace") == 0) {
            opts.vse_enabled = true;
            opts.vse_trace = true;
        } else if (strncmp(arg, "--vse-temp=", 11) == 0) {
            const char *value = arg + 11;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.vse_temp = clamp_range(parsed, 0.2f, 1.5f);
                    opts.vse_enabled = true;
                }
            }
        } else if (strncmp(arg, "--vse-intent=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.vse_intent = clamp_unit(parsed);
                    opts.vse_enabled = true;
                }
            }
        } else if (strncmp(arg, "--vse-importance=", 17) == 0) {
            const char *value = arg + 17;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.vse_importance = clamp_unit(parsed);
                    opts.vse_enabled = true;
                }
            }
        } else if (strncmp(arg, "--vse-allow=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.vse_allowance = clamp_unit(parsed);
                    opts.vse_enabled = true;
                }
            }
        } else if (strncmp(arg, "--vse-lambda-p=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.vse_lambda_p = clamp_range(parsed, 0.0f, 2.0f);
                    opts.vse_enabled = true;
                }
            }
        } else if (strncmp(arg, "--vse-lambda-x=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.vse_lambda_x = clamp_range(parsed, 0.0f, 2.0f);
                    opts.vse_enabled = true;
                }
            }
        } else if (strncmp(arg, "--allow-hold=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.vse_allowance_hold = clamp_unit(parsed);
                    opts.vse_enabled = true;
                }
            }
        } else if (strncmp(arg, "--allow=", 8) == 0) {
            const char *value = arg + 8;
            if (value && *value) {
                if ((value[0] == 'n' || value[0] == 'N') &&
                    (value[1] == 'o' || value[1] == 'O') &&
                    (value[2] == 'w' || value[2] == 'W') &&
                    value[3] == '\0') {
                    opts.vse_allowance_pulse += 0.1f;
                } else {
                    char *end = NULL;
                    float parsed = strtof(value, &end);
                    if (end != value && isfinite(parsed)) {
                        opts.vse_allowance_pulse += parsed;
                    }
                }
                if (opts.vse_allowance_pulse > 1.0f) {
                    opts.vse_allowance_pulse = 1.0f;
                } else if (opts.vse_allowance_pulse < -1.0f) {
                    opts.vse_allowance_pulse = -1.0f;
                }
                opts.vse_enabled = true;
            }
        } else if (strcmp(arg, "--trs") == 0) {
            opts.trs_enabled = true;
        } else if (strncmp(arg, "--trs-alpha=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.05f) {
                        parsed = 0.05f;
                    } else if (parsed > 0.8f) {
                        parsed = 0.8f;
                    }
                    opts.trs_alpha = parsed;
                }
            }
        } else if (strncmp(arg, "--trs-warmup=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value) {
                    if (parsed < 0) {
                        parsed = 0;
                    } else if (parsed > 10) {
                        parsed = 10;
                    }
                    opts.trs_warmup = (int)parsed;
                }
            }
        } else if (strcmp(arg, "--trs-adapt") == 0) {
            opts.trs_adapt_enabled = true;
            opts.trs_enabled = true;
        } else if (strncmp(arg, "--trs-alpha-min=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.trs_alpha_min = parsed;
                    opts.trs_adapt_enabled = true;
                    opts.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--trs-alpha-max=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.trs_alpha_max = parsed;
                    opts.trs_adapt_enabled = true;
                    opts.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--trs-target-delta=", 20) == 0) {
            const char *value = arg + 20;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.trs_target_delta = parsed;
                    opts.trs_adapt_enabled = true;
                    opts.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--trs-kp=", 9) == 0) {
            const char *value = arg + 9;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.trs_kp = parsed;
                    opts.trs_adapt_enabled = true;
                    opts.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--trs-ki=", 9) == 0) {
            const char *value = arg + 9;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.trs_ki = parsed;
                    opts.trs_adapt_enabled = true;
                    opts.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--trs-kd=", 9) == 0) {
            const char *value = arg + 9;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.trs_kd = parsed;
                    opts.trs_adapt_enabled = true;
                    opts.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--mirror-soft=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.1f) {
                        parsed = 0.1f;
                    } else if (parsed > 0.9f) {
                        parsed = 0.9f;
                    }
                    opts.mirror_softness = parsed;
                }
            }
        } else if (strncmp(arg, "--amp-min=", 10) == 0) {
            const char *value = arg + 10;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.mirror_amp_min = parsed;
                }
            }
        } else if (strncmp(arg, "--amp-max=", 10) == 0) {
            const char *value = arg + 10;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.mirror_amp_max = parsed;
                }
            }
        } else if (strncmp(arg, "--tempo-min=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.mirror_tempo_min = parsed;
                }
            }
        } else if (strncmp(arg, "--tempo-max=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    opts.mirror_tempo_max = parsed;
                }
            }
        } else if (strcmp(arg, "--strict-order") == 0) {
            opts.strict_order = true;
        } else if (strcmp(arg, "--dry-run") == 0) {
            opts.dry_run = true;
        } else if (strncmp(arg, "--emotional-source=", 20) == 0) {
            const char *value = arg + 20;
            if (strcmp(value, "text") == 0) {
                opts.emotional_source = EMPATHIC_SOURCE_TEXT;
            } else if (strcmp(value, "sensor") == 0) {
                opts.emotional_source = EMPATHIC_SOURCE_SENSOR;
            } else {
                opts.emotional_source = EMPATHIC_SOURCE_AUDIO;
            }
        } else if (strncmp(arg, "--empathy-gain=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.2f) {
                        parsed = 0.2f;
                    } else if (parsed > 3.5f) {
                        parsed = 3.5f;
                    }
                    opts.empathy_gain = parsed;
                }
            }
        } else if (strcmp(arg, "--emotional-memory") == 0) {
            opts.emotional_memory_enabled = true;
        } else if (strcmp(arg, "--memory-trace") == 0) {
            opts.memory_trace = true;
        } else if (strncmp(arg, "--emotion-trace-path=", 21) == 0) {
            const char *value = arg + 21;
            if (value && *value) {
                strncpy(opts.emotion_trace_path, value, sizeof(opts.emotion_trace_path) - 1U);
                opts.emotion_trace_path[sizeof(opts.emotion_trace_path) - 1U] = '\0';
            }
        } else if (strncmp(arg, "--recognition-threshold=", 24) == 0) {
            const char *value = arg + 24;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.01f) {
                        parsed = 0.01f;
                    } else if (parsed > 1.5f) {
                        parsed = 1.5f;
                    }
                    opts.recognition_threshold = parsed;
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
                            degrees = fmodf(degrees, 360.0f);
                            if (degrees < 0.0f) {
                                degrees += 360.0f;
                            }
                            if (degrees >= 360.0f) {
                                degrees = 0.0f;
                            }
                            opts.phase_shift_deg[module_index] = degrees;
                            opts.phase_shift_set[module_index] = true;
                        }
                    }
                }
            }
        }
    }

    normalize_bounds(&opts.mirror_amp_min, &opts.mirror_amp_max, MIRROR_GAIN_AMP_MIN_DEFAULT, MIRROR_GAIN_AMP_MAX_DEFAULT);
    normalize_bounds(&opts.mirror_tempo_min,
                     &opts.mirror_tempo_max,
                     MIRROR_GAIN_TEMPO_MIN_DEFAULT,
                     MIRROR_GAIN_TEMPO_MAX_DEFAULT);

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

    if ((opts.harmony_enabled || opts.dream_enabled) && !opts.introspect_enabled) {
        opts.introspect_enabled = true;
    }

    if (opts.astro_trace) {
        opts.astro_enabled = true;
    }
    if (opts.astro_enabled) {
        if (!opts.introspect_enabled) {
            opts.introspect_enabled = true;
        }
        if (!opts.harmony_enabled) {
            opts.harmony_enabled = true;
        }
    }

    return opts;
}
