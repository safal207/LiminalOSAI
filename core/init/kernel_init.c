#define _POSIX_C_SOURCE 199309L

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/time.h>

#include "pulse_kernel.h"
#include "soil.h"
#include "resonant.h"
#include "symbol.h"
#include "reflection.h"
#include "awareness.h"
#include "council.h"
#include "coherence.h"
#include "collective.h"
#include "collective_memory.h"
#include "affinity.h"
#include "health_scan.h"
#include "weave.h"
#include "dream.h"
#include "dream_balance.h"
#include "dream_coupler.h"
#include "metabolic.h"
#include "symbiosis.h"
#include "empathic.h"
#include "emotion_memory.h"
#include "anticipation_v2.h"
#include "mirror.h"
#include "introspect.h"
#include "harmony.h"
#include "astro_sync.h"
#include "kiss.h"
#include "consent_gate.h"
#include "vse.h"
#include "qel.h"
#include "string_utils.h"

static const float MIRROR_GAIN_AMP_MIN_DEFAULT = 0.5f;
static const float MIRROR_GAIN_AMP_MAX_DEFAULT = 1.2f;
static const float MIRROR_GAIN_TEMPO_MIN_DEFAULT = 0.8f;
static const float MIRROR_GAIN_TEMPO_MAX_DEFAULT = 1.2f;

static float sanitize_positive(float value, float fallback)
{
    if (!isfinite(value) || value <= 0.0f) {
        return fallback;
    }
    return value;
}

static void normalize_bounds(float *min_value, float *max_value, float default_min, float default_max)
{
    if (!min_value || !max_value) {
        return;
    }
    float min_sanitized = sanitize_positive(*min_value, default_min);
    float max_sanitized = sanitize_positive(*max_value, default_max);
    if (min_sanitized > max_sanitized) {
        float tmp = min_sanitized;
        min_sanitized = max_sanitized;
        max_sanitized = tmp;
    }
    *min_value = min_sanitized;
    *max_value = max_sanitized;
}

/* Вспомогательные функции для парсинга опций */
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

static float clamp_range(float value, float lo, float hi)
{
    if (value < lo) {
        return lo;
    }
    if (value > hi) {
        return hi;
    }
    return value;
}

kernel_options kernel_parse_options(int argc, char **argv)
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
        } else if (strcmp(arg, "--sync") == 0) {
            opts.enable_sync = true;
        } else if (strcmp(arg, "--sync-trace") == 0) {
            opts.sync_trace = true;
        } else if (strncmp(arg, "--phase-count=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed > 0 && parsed <= WEAVE_MODULE_COUNT) {
                    opts.phase_count = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--phase-shift-", 14) == 0) {
            const char *rest = arg + 14;
            size_t len = strlen(rest);
            if (len > 2 && strcmp(rest + len - 2, "deg") == 0) {
                char module_name[64];
                size_t name_len = len - 2;
                if (name_len >= sizeof(module_name)) {
                    name_len = sizeof(module_name) - 1;
                }
                memcpy(module_name, rest, name_len);
                module_name[name_len] = '\0';
                WeaveModule mod = weave_module_from_name(module_name);
                if (mod < WEAVE_MODULE_COUNT) {
                    const char *value = arg + 14 + name_len + 2;
                    if (*value == '=') {
                        ++value;
                    }
                    if (*value) {
                        char *end = NULL;
                        float parsed = strtof(value, &end);
                        if (end != value) {
                            opts.phase_shift_deg[mod] = parsed;
                            opts.phase_shift_set[mod] = true;
                        }
                    }
                }
            }
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
                    opts.dream_threshold = clamp_unit(parsed);
                }
            }
        } else if (strcmp(arg, "--metabolic") == 0) {
            opts.metabolic_enabled = true;
        } else if (strcmp(arg, "--metabolic-trace") == 0) {
            opts.metabolic_trace = true;
        } else if (strncmp(arg, "--vitality-rest=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.vitality_rest_threshold = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--vitality-creative=", 20) == 0) {
            const char *value = arg + 20;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.vitality_creative_threshold = clamp_unit(parsed);
                }
            }
        } else if (strcmp(arg, "--human-bridge") == 0) {
            opts.human_bridge_enabled = true;
        } else if (strcmp(arg, "--human-trace") == 0) {
            opts.human_trace = true;
        } else if (strncmp(arg, "--human-source=", 15) == 0) {
            const char *value = arg + 15;
            if (strcmp(value, "keyboard") == 0) {
                opts.human_source = SYMBIOSIS_SOURCE_KEYBOARD;
            } else if (strcmp(value, "audio") == 0) {
                opts.human_source = SYMBIOSIS_SOURCE_AUDIO;
            } else if (strcmp(value, "mock") == 0) {
                opts.human_source = SYMBIOSIS_SOURCE_MOCK;
            }
        } else if (strncmp(arg, "--human-gain=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.human_resonance_gain = parsed;
                }
            }
        } else if (strcmp(arg, "--empathic") == 0) {
            opts.empathic_enabled = true;
        } else if (strcmp(arg, "--empathic-trace") == 0) {
            opts.empathic_trace = true;
        } else if (strncmp(arg, "--empathic-source=", 18) == 0) {
            const char *value = arg + 18;
            if (strcmp(value, "audio") == 0) {
                opts.emotional_source = EMPATHIC_SOURCE_AUDIO;
            } else if (strcmp(value, "mock") == 0) {
                opts.emotional_source = EMPATHIC_SOURCE_MOCK;
            }
        } else if (strncmp(arg, "--empathy-gain=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.empathy_gain = parsed;
                }
            }
        } else if (strcmp(arg, "--emotional-memory") == 0) {
            opts.emotional_memory_enabled = true;
        } else if (strcmp(arg, "--memory-trace") == 0) {
            opts.memory_trace = true;
        } else if (strncmp(arg, "--recognition-threshold=", 24) == 0) {
            const char *value = arg + 24;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.recognition_threshold = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--emotion-trace-path=", 21) == 0) {
            const char *value = arg + 21;
            if (value && *value) {
                strncpy(opts.emotion_trace_path, value, sizeof(opts.emotion_trace_path) - 1);
                opts.emotion_trace_path[sizeof(opts.emotion_trace_path) - 1] = '\0';
            }
        } else if (strcmp(arg, "--anticipation2") == 0) {
            opts.anticipation2_enabled = true;
        } else if (strcmp(arg, "--ant2-trace") == 0) {
            opts.ant2_trace = true;
        } else if (strncmp(arg, "--ant2-gain=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.ant2_gain = parsed;
                }
            }
        } else if (strcmp(arg, "--affinity") == 0) {
            opts.affinity_enabled = true;
        } else if (strcmp(arg, "--bond-trace") == 0) {
            opts.bond_trace_enabled = true;
        } else if (strncmp(arg, "--affinity-influence=", 23) == 0) {
            const char *value = arg + 23;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.affinity_config.influence = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--affinity-cohesion=", 22) == 0) {
            const char *value = arg + 22;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.affinity_config.cohesion = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--affinity-safety=", 20) == 0) {
            const char *value = arg + 20;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.affinity_config.safety = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--allow-consent=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.allow_align_consent = clamp_unit(parsed);
                }
            }
        } else if (strcmp(arg, "--mirror") == 0) {
            opts.mirror_enabled = true;
        } else if (strcmp(arg, "--mirror-trace") == 0) {
            opts.mirror_trace = true;
        } else if (strncmp(arg, "--mirror-softness=", 18) == 0) {
            const char *value = arg + 18;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.mirror_softness = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--mirror-amp-min=", 17) == 0) {
            const char *value = arg + 17;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.mirror_amp_min = parsed;
                }
            }
        } else if (strncmp(arg, "--mirror-amp-max=", 17) == 0) {
            const char *value = arg + 17;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.mirror_amp_max = parsed;
                }
            }
        } else if (strncmp(arg, "--mirror-tempo-min=", 19) == 0) {
            const char *value = arg + 19;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.mirror_tempo_min = parsed;
                }
            }
        } else if (strncmp(arg, "--mirror-tempo-max=", 19) == 0) {
            const char *value = arg + 19;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.mirror_tempo_max = parsed;
                }
            }
        } else if (strcmp(arg, "--introspect") == 0) {
            opts.introspect_enabled = true;
        } else if (strcmp(arg, "--harmony") == 0) {
            opts.harmony_enabled = true;
        } else if (strcmp(arg, "--qel") == 0) {
            opts.qel_enabled = true;
        } else if (strncmp(arg, "--qel-retro-gain=", 17) == 0) {
            const char *value = arg + 17;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
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
        } else if (strncmp(arg, "--astro-rate=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.astro_rate = parsed;
                }
            }
        } else if (strncmp(arg, "--astro-tone=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.astro_tone_init = parsed;
                    opts.astro_tone_set = true;
                }
            }
        } else if (strncmp(arg, "--astro-memory=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.astro_memory_init = parsed;
                    opts.astro_memory_set = true;
                }
            }
        } else if (strcmp(arg, "--trs") == 0) {
            opts.trs_enabled = true;
        } else if (strncmp(arg, "--trs-alpha=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.trs_alpha = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--trs-warmup=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed >= 0) {
                    opts.trs_warmup = (int)parsed;
                }
            }
        } else if (strcmp(arg, "--trs-adapt") == 0) {
            opts.trs_adapt_enabled = true;
        } else if (strncmp(arg, "--trs-alpha-min=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.trs_alpha_min = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--trs-alpha-max=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.trs_alpha_max = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--trs-target-delta=", 19) == 0) {
            const char *value = arg + 19;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.trs_target_delta = parsed;
                }
            }
        } else if (strncmp(arg, "--trs-kp=", 9) == 0) {
            const char *value = arg + 9;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.trs_kp = parsed;
                }
            }
        } else if (strncmp(arg, "--trs-ki=", 9) == 0) {
            const char *value = arg + 9;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.trs_ki = parsed;
                }
            }
        } else if (strncmp(arg, "--trs-kd=", 9) == 0) {
            const char *value = arg + 9;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.trs_kd = parsed;
                }
            }
        } else if (strcmp(arg, "--kiss") == 0) {
            opts.kiss_enabled = true;
        } else if (strncmp(arg, "--kiss-trust=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.kiss_trust_threshold = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--kiss-presence=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.kiss_presence_threshold = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--kiss-harmony=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.kiss_harmony_threshold = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--kiss-warmup=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed >= 0) {
                    opts.kiss_warmup_cycles = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--kiss-refractory=", 18) == 0) {
            const char *value = arg + 18;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed >= 0) {
                    opts.kiss_refractory_cycles = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--kiss-alpha=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.kiss_alpha = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--consent-open=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.consent_gate_open_threshold = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--consent-close=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.consent_gate_close_threshold = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--consent-hysteresis=", 21) == 0) {
            const char *value = arg + 21;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.consent_gate_hysteresis = parsed;
                }
            }
        } else if (strncmp(arg, "--consent-bias=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.consent_gate_bias = parsed;
                }
            }
        } else if (strncmp(arg, "--consent-warmup=", 17) == 0) {
            const char *value = arg + 17;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed >= 0) {
                    opts.consent_gate_warmup_cycles = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--consent-refractory=", 21) == 0) {
            const char *value = arg + 21;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed >= 0) {
                    opts.consent_gate_refractory_cycles = (int)parsed;
                }
            }
        } else if (strcmp(arg, "--vse") == 0) {
            opts.vse_enabled = true;
        } else if (strcmp(arg, "--vse-trace") == 0) {
            opts.vse_trace = true;
        } else if (strncmp(arg, "--vse-temp=", 11) == 0) {
            const char *value = arg + 11;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.vse_temp = clamp_range(parsed, 0.2f, 1.5f);
                }
            }
        } else if (strncmp(arg, "--vse-intent=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.vse_intent = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--vse-importance=", 17) == 0) {
            const char *value = arg + 17;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.vse_importance = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--vse-allowance=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.vse_allowance = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--vse-lambda-p=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.vse_lambda_p = parsed;
                }
            }
        } else if (strncmp(arg, "--vse-lambda-x=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.vse_lambda_x = parsed;
                }
            }
        } else if (strncmp(arg, "--vse-allowance-hold=", 21) == 0) {
            const char *value = arg + 21;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.vse_allowance_hold = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--vse-allowance-pulse=", 22) == 0) {
            const char *value = arg + 22;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value) {
                    opts.vse_allowance_pulse = clamp_unit(parsed);
                }
            }
        } else if (strcmp(arg, "--strict-order") == 0) {
            opts.strict_order = true;
        } else if (strcmp(arg, "--dry-run") == 0) {
            opts.dry_run = true;
        } else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            fprintf(stdout, "liminal_core [OPTIONS]\n");
            fprintf(stdout, "Options:\n");
            fprintf(stdout, "  --trace              Показать трассировку soil\n");
            fprintf(stdout, "  --symbols            Показать символьный слой\n");
            fprintf(stdout, "  --reflect            Показать отражения\n");
            fprintf(stdout, "  --awareness          Показать awareness\n");
            fprintf(stdout, "  --coherence          Показать coherence\n");
            fprintf(stdout, "  --council            Включить council\n");
            fprintf(stdout, "  --council-log        Лог council\n");
            fprintf(stdout, "  --auto-tune          Автонастройка awareness\n");
            fprintf(stdout, "  --collective         Включить collective\n");
            fprintf(stdout, "  --collective-trace   Трассировка collective\n");
            fprintf(stdout, "  --collective-memory  Включить collective memory\n");
            fprintf(stdout, "  --cm-trace           Трассировка collective memory\n");
            fprintf(stdout, "  --cm-path=PATH       Путь к collective memory\n");
            fprintf(stdout, "  --cm-snapshot-interval=N Интервал снимков CM\n");
            fprintf(stdout, "  --climate-log        Лог климата\n");
            fprintf(stdout, "  --health-scan        Сканирование здоровья\n");
            fprintf(stdout, "  --scan-report        Отчёт health scan\n");
            fprintf(stdout, "  --limit=N            Лимит пульсов\n");
            fprintf(stdout, "  --scan-interval=N    Интервал сканирования\n");
            fprintf(stdout, "  --target=X           Целевая когерентность\n");
            fprintf(stdout, "  --sync               Включить синхронизацию\n");
            fprintf(stdout, "  --sync-trace         Трассировка синхронизации\n");
            fprintf(stdout, "  --phase-count=N      Количество фаз\n");
            fprintf(stdout, "  --phase-shift-Xdeg=N Сдвиг фазы модуля X\n");
            fprintf(stdout, "  --dream              Включить dream\n");
            fprintf(stdout, "  --dream-log          Лог dream\n");
            fprintf(stdout, "  --dream-threshold=X  Порог входа в dream\n");
            fprintf(stdout, "  --metabolic          Включить metabolic\n");
            fprintf(stdout, "  --metabolic-trace    Трассировка metabolic\n");
            fprintf(stdout, "  --vitality-rest=X    Порог vitality rest\n");
            fprintf(stdout, "  --vitality-creative=X Порог vitality creative\n");
            fprintf(stdout, "  --human-bridge       Включить human bridge\n");
            fprintf(stdout, "  --human-trace        Трассировка human bridge\n");
            fprintf(stdout, "  --human-source=X     Источник human (keyboard/audio/mock)\n");
            fprintf(stdout, "  --human-gain=X       Усиление human resonance\n");
            fprintf(stdout, "  --empathic           Включить empathic\n");
            fprintf(stdout, "  --empathic-trace     Трассировка empathic\n");
            fprintf(stdout, "  --empathic-source=X  Источник empathic (audio/mock)\n");
            fprintf(stdout, "  --empathy-gain=X     Усиление empathy\n");
            fprintf(stdout, "  --emotional-memory   Включить emotional memory\n");
            fprintf(stdout, "  --memory-trace       Трассировка memory\n");
            fprintf(stdout, "  --recognition-threshold=X Порог распознавания\n");
            fprintf(stdout, "  --emotion-trace-path=PATH Путь к emotion trace\n");
            fprintf(stdout, "  --anticipation2      Включить anticipation v2\n");
            fprintf(stdout, "  --ant2-trace         Трассировка ant2\n");
            fprintf(stdout, "  --ant2-gain=X        Усиление ant2\n");
            fprintf(stdout, "  --affinity           Включить affinity\n");
            fprintf(stdout, "  --bond-trace         Трассировка bond\n");
            fprintf(stdout, "  --affinity-influence=X Влияние affinity\n");
            fprintf(stdout, "  --affinity-cohesion=X Сплочённость affinity\n");
            fprintf(stdout, "  --affinity-safety=X  Безопасность affinity\n");
            fprintf(stdout, "  --allow-consent=X    Разрешение на согласование\n");
            fprintf(stdout, "  --mirror             Включить mirror\n");
            fprintf(stdout, "  --mirror-trace       Трассировка mirror\n");
            fprintf(stdout, "  --mirror-softness=X  Мягкость mirror\n");
            fprintf(stdout, "  --mirror-amp-min=X   Мин. усиление амплитуды\n");
            fprintf(stdout, "  --mirror-amp-max=X   Макс. усиление амплитуды\n");
            fprintf(stdout, "  --mirror-tempo-min=X Мин. усиление темпа\n");
            fprintf(stdout, "  --mirror-tempo-max=X Макс. усиление темпа\n");
            fprintf(stdout, "  --introspect         Включить introspect\n");
            fprintf(stdout, "  --harmony            Включить harmony\n");
            fprintf(stdout, "  --qel                Включить QEL\n");
            fprintf(stdout, "  --qel-retro-gain=X   Ретро-усиление QEL\n");
            fprintf(stdout, "  --entangle-ctx=X     Контекст entanglement\n");
            fprintf(stdout, "  --astro              Включить astro_sync\n");
            fprintf(stdout, "  --astro-trace        Трассировка astro\n");
            fprintf(stdout, "  --astro-rate=X       Скорость astro\n");
            fprintf(stdout, "  --astro-tone=X       Начальный тон astro\n");
            fprintf(stdout, "  --astro-memory=X     Начальная память astro\n");
            fprintf(stdout, "  --trs                Включить TRS фильтр\n");
            fprintf(stdout, "  --trs-alpha=X        Альфа TRS\n");
            fprintf(stdout, "  --trs-warmup=N       Прогрев TRS\n");
            fprintf(stdout, "  --trs-adapt          Адаптивный TRS\n");
            fprintf(stdout, "  --trs-alpha-min=X    Мин. альфа TRS\n");
            fprintf(stdout, "  --trs-alpha-max=X    Макс. альфа TRS\n");
            fprintf(stdout, "  --trs-target-delta=X Целевая дельта TRS\n");
            fprintf(stdout, "  --trs-kp=X           Kp TRS PID\n");
            fprintf(stdout, "  --trs-ki=X           Ki TRS PID\n");
            fprintf(stdout, "  --trs-kd=X           Kd TRS PID\n");
            fprintf(stdout, "  --kiss               Включить KISS cascade\n");
            fprintf(stdout, "  --kiss-trust=X       Порог доверия KISS\n");
            fprintf(stdout, "  --kiss-presence=X    Порог присутствия KISS\n");
            fprintf(stdout, "  --kiss-harmony=X     Порог гармонии KISS\n");
            fprintf(stdout, "  --kiss-warmup=N      Прогрев KISS\n");
            fprintf(stdout, "  --kiss-refractory=N  Рефрактерный период KISS\n");
            fprintf(stdout, "  --kiss-alpha=X       Альфа KISS\n");
            fprintf(stdout, "  --consent-open=X     Порог открытия consent gate\n");
            fprintf(stdout, "  --consent-close=X    Порог закрытия consent gate\n");
            fprintf(stdout, "  --consent-hysteresis=X Гистерезис consent gate\n");
            fprintf(stdout, "  --consent-bias=X     Смещение consent gate\n");
            fprintf(stdout, "  --consent-warmup=N   Прогрев consent gate\n");
            fprintf(stdout, "  --consent-refractory=N Рефрактерный период consent gate\n");
            fprintf(stdout, "  --vse                Включить VSE\n");
            fprintf(stdout, "  --vse-trace          Трассировка VSE\n");
            fprintf(stdout, "  --vse-temp=X         Температура VSE\n");
            fprintf(stdout, "  --vse-intent=X       Намерение VSE\n");
            fprintf(stdout, "  --vse-importance=X   Важность VSE\n");
            fprintf(stdout, "  --vse-allowance=X    Допуск VSE\n");
            fprintf(stdout, "  --vse-lambda-p=X     Lambda P VSE\n");
            fprintf(stdout, "  --vse-lambda-x=X     Lambda X VSE\n");
            fprintf(stdout, "  --vse-allowance-hold=X Удержание допуска VSE\n");
            fprintf(stdout, "  --vse-allowance-pulse=X Пульс допуска VSE\n");
            fprintf(stdout, "  --strict-order       Строгий порядок exhale\n");
            fprintf(stdout, "  --dry-run            Сухой запуск (без выполнения)\n");
            fprintf(stdout, "  --help, -h           Показать эту справку\n");
            exit(0);
        }
    }

    /* Нормализация границ mirror gain */
    normalize_bounds(&opts.mirror_amp_min, &opts.mirror_amp_max,
                     MIRROR_GAIN_AMP_MIN_DEFAULT, MIRROR_GAIN_AMP_MAX_DEFAULT);
    normalize_bounds(&opts.mirror_tempo_min, &opts.mirror_tempo_max,
                     MIRROR_GAIN_TEMPO_MIN_DEFAULT, MIRROR_GAIN_TEMPO_MAX_DEFAULT);

    return opts;
}
