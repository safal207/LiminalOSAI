#include "substrate_options.h"
#include "erb.h"

#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "options_defaults.h"
#include "runtime_values.h"

static bool parse_float_range(const char *spec, float *out_min, float *out_max)
{
    if (!spec || !out_min || !out_max) {
        return false;
    }
    char *end = NULL;
    float min_value = strtof(spec, &end);
    if (end == spec || *end != ':') {
        return false;
    }
    const char *max_part = end + 1;
    float max_value = strtof(max_part, &end);
    if (end == max_part) {
        return false;
    }
    if (!isfinite(min_value) || !isfinite(max_value)) {
        return false;
    }
    *out_min = min_value;
    *out_max = max_value;
    return true;
}

static bool parse_int_range(const char *spec, int *out_min, int *out_max)
{
    if (!spec || !out_min || !out_max) {
        return false;
    }
    char *end = NULL;
    long min_value = strtol(spec, &end, 10);
    if (end == spec || *end != ':') {
        return false;
    }
    const char *max_part = end + 1;
    long max_value = strtol(max_part, &end, 10);
    if (end == max_part) {
        return false;
    }
    *out_min = (int)min_value;
    *out_max = (int)max_value;
    return true;
}

static void parse_kiss_thresholds(substrate_config *cfg, const char *value)
{
    if (!cfg || !value) {
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
                if (parsed < 0.0f) {
                    parsed = 0.0f;
                } else if (parsed > 1.0f) {
                    parsed = 1.0f;
                }
                if (strcmp(name, "trust") == 0 || strcmp(name, "tr") == 0) {
                    cfg->kiss_trust_threshold = parsed;
                } else if (strcmp(name, "pres") == 0 || strcmp(name, "presence") == 0) {
                    cfg->kiss_presence_threshold = parsed;
                } else if (strcmp(name, "harm") == 0 || strcmp(name, "harmony") == 0) {
                    cfg->kiss_harmony_threshold = parsed;
                }
            }
        }
        token = strtok(NULL, ",");
    }
}

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

substrate_config substrate_options_parse(int argc, char **argv)
{
    substrate_config cfg;
    cfg.run_substrate = false;
    cfg.adaptive = false;
    cfg.trace = false;
    cfg.human_bridge = false;
    cfg.lip_port = 0U;
    cfg.lip_test = false;
    cfg.lip_trace = false;
    cfg.lip_interval_ms = 1000U;
    cfg.lip_host[0] = '\0';
    cfg.empathic_enabled = false;
    cfg.empathic_trace = false;
    cfg.anticipation_trace = false;
    cfg.anticipation2_enabled = false;
    cfg.ant2_trace = false;
    cfg.ant2_gain = 0.6f;
    cfg.emotional_source = EMPATHIC_SOURCE_AUDIO;
    cfg.empathy_gain = 1.0f;
    cfg.emotional_memory_enabled = false;
    cfg.memory_trace = false;
    cfg.recognition_threshold = 0.18f;
    cfg.emotion_trace_path[0] = '\0';
    cfg.cycle_limit = 6U;
    cfg.affinity_enabled = false;
    cfg.bond_trace = false;
    affinity_default(&cfg.affinity_config);
    cfg.allow_align_consent = 0.2f;
    cfg.mirror_amp_min = MIRROR_GAIN_AMP_MIN_DEFAULT;
    cfg.mirror_amp_max = MIRROR_GAIN_AMP_MAX_DEFAULT;
    cfg.mirror_tempo_min = MIRROR_GAIN_TEMPO_MIN_DEFAULT;
    cfg.mirror_tempo_max = MIRROR_GAIN_TEMPO_MAX_DEFAULT;
    cfg.strict_order = false;
    cfg.dry_run = false;
    cfg.introspect_enabled = false;
    cfg.harmony_enabled = false;
    cfg.qel_enabled = false;
    cfg.qel_retro_gain = 0.0f;
    cfg.entangle_ctx = 0U;
    cfg.dream_enabled = false;
    cfg.dream_replay_enabled = false;
    cfg.astro_enabled = false;
    cfg.astro_trace = false;
    cfg.astro_rate = 0.010f;
    cfg.astro_tone_init = 0.0f;
    cfg.astro_memory_init = 0.0f;
    cfg.astro_tone_set = false;
    cfg.astro_memory_set = false;
    cfg.dream_replay_cycles = 16;
    cfg.dream_replay_rate = 0.2f;
    cfg.dream_replay_decay = 0.01f;
    cfg.dream_replay_trace = false;
    cfg.bridge_enabled = false;
    cfg.bridge_plasticity = 0.65f;
    cfg.bridge_retention = 0.75f;
    cfg.bridge_recovery = 0.03f;
    cfg.trs_enabled = false;
    cfg.trs_alpha = 0.3f;
    cfg.trs_warmup = 5;
    cfg.trs_adapt_enabled = false;
    cfg.trs_alpha_min = 0.10f;
    cfg.trs_alpha_max = 0.60f;
    cfg.trs_target_delta = 0.015f;
    cfg.trs_kp = 0.4f;
    cfg.trs_ki = 0.05f;
    cfg.trs_kd = 0.1f;
    cfg.kiss_enabled = false;
    cfg.kiss_trust_threshold = 0.80f;
    cfg.kiss_presence_threshold = 0.70f;
    cfg.kiss_harmony_threshold = 0.85f;
    cfg.kiss_warmup_cycles = 10;
    cfg.kiss_refractory_cycles = 5;
    cfg.kiss_alpha = 0.25f;
    cfg.consent_gate_open_threshold = 0.75f;
    cfg.consent_gate_close_threshold = 0.60f;
    cfg.consent_gate_hysteresis = 0.05f;
    cfg.consent_gate_bias = 0.0f;
    cfg.consent_gate_warmup_cycles = 8;
    cfg.consent_gate_refractory_cycles = 6;
    cfg.fee_enabled = false;
    cfg.flow_alpha = 0.6f;
    cfg.flow_gamma = 0.25f;
    cfg.vse_enabled = false;
    cfg.vse_trace = false;
    cfg.vse_temp = 1.0f;
    cfg.vse_intent = 0.6f;
    cfg.vse_importance = 0.4f;
    cfg.vse_allowance = 0.3f;
    cfg.vse_lambda_p = 0.2f;
    cfg.vse_lambda_x = 0.4f;
    cfg.vse_allowance_hold = 0.0f;
    cfg.vse_allowance_pulse = 0.0f;
    cfg.erb_enabled = false;
    cfg.erb_pre = 24;
    cfg.erb_post = 32;
    cfg.erb_spike = 0.06f;
    cfg.erb_replay_mode = ERB_REPLAY_NONE;
    cfg.erb_replay_idx = 0U;
    cfg.erb_replay_tag_mask = 0U;
    cfg.erb_replay_speed = 1.0f;
    cfg.tune_enabled = false;
    cfg.tune_apply = false;
    cfg.tune_report = false;
    cfg.tune_trials = 60;
    cfg.tune_refine = 10;
    cfg.tune_max_runs = 200;
    cfg.tune_alpha_min = 0.1f;
    cfg.tune_alpha_max = 0.6f;
    cfg.tune_warm_min = 0;
    cfg.tune_warm_max = 6;
    cfg.tune_align_min = 0.4f;
    cfg.tune_align_max = 0.8f;
    cfg.tune_save_path[0] = '\0';
    cfg.tune_load_path[0] = '\0';
    cfg.tune_seed = 42;
    cfg.tune_select_n = 0;
    cfg.tune_source_mode = TUNE_SOURCE_LATEST;
    cfg.tune_source_idx = 0U;
    cfg.tune_source_mask = 0U;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "--substrate") == 0) {
            cfg.run_substrate = true;
        } else if (strcmp(arg, "--adaptive") == 0) {
            cfg.adaptive = true;
        } else if (strcmp(arg, "--trace") == 0) {
            cfg.trace = true;
        } else if (strncmp(arg, "--lip-port=", 11) == 0) {
            const char *value = arg + 11;
            unsigned long parsed = strtoul(value, NULL, 10);
            if (parsed <= UINT16_MAX) {
                cfg.lip_port = (uint16_t)parsed;
            }
        } else if (strcmp(arg, "--lip-test") == 0) {
            cfg.lip_test = true;
        } else if (strcmp(arg, "--lip-trace") == 0) {
            cfg.lip_trace = true;
        } else if (strncmp(arg, "--lip-interval=", 15) == 0) {
            const char *value = arg + 15;
            unsigned long parsed = strtoul(value, NULL, 10);
            if (parsed > 0UL && parsed <= 60000UL) {
                cfg.lip_interval_ms = (unsigned int)parsed;
            }
        } else if (strncmp(arg, "--lip-host=", 11) == 0) {
            const char *value = arg + 11;
            if (value && *value) {
                strncpy(cfg.lip_host, value, sizeof(cfg.lip_host) - 1U);
                cfg.lip_host[sizeof(cfg.lip_host) - 1U] = '\0';
            }
        } else if (strcmp(arg, "--erb") == 0) {
            cfg.erb_enabled = true;
        } else if (strncmp(arg, "--erb-pre=", 10) == 0) {
            const char *value = arg + 10;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value) {
                    if (parsed < 0L) {
                        parsed = 0L;
                    } else if (parsed > (long)(ERB_MAX_LEN - 1)) {
                        parsed = (long)(ERB_MAX_LEN - 1);
                    }
                    cfg.erb_pre = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--erb-post=", 11) == 0) {
            const char *value = arg + 11;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value) {
                    if (parsed < 0L) {
                        parsed = 0L;
                    } else if (parsed > (long)(ERB_MAX_LEN - 1)) {
                        parsed = (long)(ERB_MAX_LEN - 1);
                    }
                    cfg.erb_post = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--erb-spike=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed) && parsed >= 0.0f) {
                    cfg.erb_spike = parsed;
                }
            }
        } else if (strncmp(arg, "--erb-replay=", 13) == 0) {
            const char *value = arg + 13;
            if (value && *value) {
                if (strcmp(value, "latest") == 0 || strcmp(value, "LATEST") == 0) {
                    cfg.erb_replay_mode = ERB_REPLAY_LATEST;
                } else if (strcmp(value, "ALL") == 0 || strcmp(value, "all") == 0) {
                    cfg.erb_replay_mode = ERB_REPLAY_ALL;
                } else if (strncmp(value, "idx:", 4) == 0) {
                    const char *idx_value = value + 4;
                    char *end = NULL;
                    unsigned long parsed = strtoul(idx_value, &end, 10);
                    if (end != idx_value) {
                        cfg.erb_replay_mode = ERB_REPLAY_INDEX;
                        cfg.erb_replay_idx = (uint32_t)parsed;
                    }
                } else if (strncmp(value, "tag:", 4) == 0) {
                    const char *tag_spec = value + 4;
                    uint32_t mask = erb_parse_tag_mask(tag_spec);
                    if (mask != 0U) {
                        cfg.erb_replay_mode = ERB_REPLAY_TAG;
                        cfg.erb_replay_tag_mask = mask;
                    }
                }
            }
        } else if (strncmp(arg, "--erb-replay-speed=", sizeof("--erb-replay-speed=") - 1) == 0) {
            const char *value = arg + (sizeof("--erb-replay-speed=") - 1);
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed) && parsed > 0.0f) {
                    cfg.erb_replay_speed = parsed;
                }
            }
        } else if (strcmp(arg, "--tune") == 0) {
            cfg.tune_enabled = true;
        } else if (strncmp(arg, "--tune-source=", 14) == 0) {
            const char *value = arg + 14;
            if (value && *value) {
                cfg.tune_enabled = true;
                if (strcmp(value, "latest") == 0 || strcmp(value, "LATEST") == 0) {
                    cfg.tune_source_mode = TUNE_SOURCE_LATEST;
                } else if (strcmp(value, "ALL") == 0 || strcmp(value, "all") == 0) {
                    cfg.tune_source_mode = TUNE_SOURCE_ALL;
                } else if (strncmp(value, "idx:", 4) == 0) {
                    const char *idx_value = value + 4;
                    char *end = NULL;
                    unsigned long parsed = strtoul(idx_value, &end, 10);
                    if (end != idx_value) {
                        cfg.tune_source_mode = TUNE_SOURCE_INDEX;
                        cfg.tune_source_idx = (uint32_t)parsed;
                    }
                } else if (strncmp(value, "tag:", 4) == 0) {
                    const char *tag_spec = value + 4;
                    uint32_t mask = erb_parse_tag_mask(tag_spec);
                    if (mask != 0U) {
                        cfg.tune_source_mode = TUNE_SOURCE_TAG;
                        cfg.tune_source_mask = mask;
                    }
                }
            }
        } else if (strncmp(arg, "--tune-trials=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed > 0L) {
                    if (parsed > INT_MAX) {
                        parsed = INT_MAX;
                    }
                    cfg.tune_trials = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--tune-refine=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed >= 0L) {
                    if (parsed > INT_MAX) {
                        parsed = INT_MAX;
                    }
                    cfg.tune_refine = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--tune-max-runs=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed > 0L) {
                    if (parsed > INT_MAX) {
                        parsed = INT_MAX;
                    }
                    cfg.tune_max_runs = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--tune-alpha=", 13) == 0) {
            const char *value = arg + 13;
            float min_v = 0.0f;
            float max_v = 0.0f;
            if (parse_float_range(value, &min_v, &max_v)) {
                cfg.tune_alpha_min = min_v;
                cfg.tune_alpha_max = max_v;
            }
        } else if (strncmp(arg, "--tune-warm=", 12) == 0) {
            const char *value = arg + 12;
            int min_v = 0;
            int max_v = 0;
            if (parse_int_range(value, &min_v, &max_v)) {
                if (min_v < 0) {
                    min_v = 0;
                }
                if (max_v > 10) {
                    max_v = 10;
                }
                cfg.tune_warm_min = min_v;
                cfg.tune_warm_max = max_v;
            }
        } else if (strncmp(arg, "--tune-align=", 13) == 0) {
            const char *value = arg + 13;
            float min_v = 0.0f;
            float max_v = 0.0f;
            if (parse_float_range(value, &min_v, &max_v)) {
                cfg.tune_align_min = min_v;
                cfg.tune_align_max = max_v;
            }
        } else if (strncmp(arg, "--tune-save=", 12) == 0) {
            const char *value = arg + 12;
            if (value && *value) {
                strncpy(cfg.tune_save_path, value, sizeof(cfg.tune_save_path) - 1U);
                cfg.tune_save_path[sizeof(cfg.tune_save_path) - 1U] = '\0';
            }
        } else if (strncmp(arg, "--tune-load=", 12) == 0) {
            const char *value = arg + 12;
            if (value && *value) {
                strncpy(cfg.tune_load_path, value, sizeof(cfg.tune_load_path) - 1U);
                cfg.tune_load_path[sizeof(cfg.tune_load_path) - 1U] = '\0';
            }
        } else if (strcmp(arg, "--tune-apply") == 0) {
            cfg.tune_apply = true;
        } else if (strcmp(arg, "--tune-report") == 0) {
            cfg.tune_report = true;
        } else if (strncmp(arg, "--tune-seed=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value) {
                    cfg.tune_seed = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--tune-count=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed >= 0L) {
                    if (parsed > INT_MAX) {
                        parsed = INT_MAX;
                    }
                    cfg.tune_select_n = (int)parsed;
                }
            }
        } else if (strncmp(arg, "--human-bridge", 14) == 0) {
            cfg.human_bridge = true;
            const char *value = NULL;
            if (arg[14] == '=') {
                value = arg + 15;
            } else if (i + 1 < argc && argv[i + 1][0] != '-') {
                value = argv[i + 1];
                ++i;
            }
            if (value && (strcmp(value, "off") == 0 || strcmp(value, "0") == 0)) {
                cfg.human_bridge = false;
            }
        } else if (strcmp(arg, "--empathic") == 0) {
            cfg.empathic_enabled = true;
        } else if (strcmp(arg, "--empathic-trace") == 0) {
            cfg.empathic_trace = true;
        } else if (strcmp(arg, "--anticipation") == 0) {
            cfg.empathic_enabled = true;
            cfg.empathic_trace = true;
            cfg.anticipation_trace = true; // merged by Codex
        } else if (strcmp(arg, "--anticipation2") == 0) {
            cfg.anticipation2_enabled = true;
        } else if (strcmp(arg, "--ant2-trace") == 0) {
            cfg.anticipation2_enabled = true;
            cfg.ant2_trace = true;
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
                    cfg.anticipation2_enabled = true;
                    cfg.ant2_gain = parsed;
                }
            }
        } else if (strcmp(arg, "--affinity") == 0) {
            cfg.affinity_enabled = true;
        } else if (strncmp(arg, "--affinity-cfg=", 15) == 0) {
            const char *value = arg + 15;
            if (value && *value) {
                parse_affinity_config(&cfg.affinity_config, value);
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
                    cfg.allow_align_consent = parsed;
                }
            }
        } else if (strncmp(arg, "--amp-min=", 10) == 0) {
            const char *value = arg + 10;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.mirror_amp_min = parsed;
                }
            }
        } else if (strncmp(arg, "--amp-max=", 10) == 0) {
            const char *value = arg + 10;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.mirror_amp_max = parsed;
                }
            }
        } else if (strncmp(arg, "--tempo-min=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.mirror_tempo_min = parsed;
                }
            }
        } else if (strncmp(arg, "--tempo-max=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.mirror_tempo_max = parsed;
                }
            }
        } else if (strcmp(arg, "--introspect") == 0) {
            cfg.introspect_enabled = true;
        } else if (strcmp(arg, "--harmony") == 0) {
            cfg.harmony_enabled = true;
        } else if (strcmp(arg, "--qel") == 0) {
            cfg.qel_enabled = true;
        } else if (strncmp(arg, "--qel-retro=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.qel_retro_gain = clamp_unit(parsed);
                }
            }
        } else if (strncmp(arg, "--entangle-ctx=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                unsigned long parsed = strtoul(value, &end, 0);
                if (end != value) {
                    cfg.entangle_ctx = (uint32_t)parsed;
                }
            }
        } else if (strcmp(arg, "--trs") == 0) {
            cfg.trs_enabled = true;
        } else if (strcmp(arg, "--astro") == 0) {
            cfg.astro_enabled = true;
        } else if (strcmp(arg, "--astro-trace") == 0) {
            cfg.astro_trace = true;
            cfg.astro_enabled = true;
        } else if (strncmp(arg, "--astro-rate=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.astro_rate = clamp_range(parsed, 0.005f, 0.020f);
                }
            }
        } else if (strncmp(arg, "--astro-tone=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.astro_tone_init = clamp_unit(parsed);
                    cfg.astro_tone_set = true;
                }
            }
        } else if (strncmp(arg, "--astro-mem=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.astro_memory_init = clamp_unit(parsed);
                    cfg.astro_memory_set = true;
                }
            }
        } else if (strcmp(arg, "--kiss") == 0) {
            cfg.kiss_enabled = true;
        } else if (strncmp(arg, "--kiss-thr=", 11) == 0) {
            const char *value = arg + 11;
            if (value && *value) {
                parse_kiss_thresholds(&cfg, value);
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
                    cfg.kiss_warmup_cycles = (int)parsed;
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
                    cfg.kiss_refractory_cycles = (int)parsed;
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
                    cfg.kiss_alpha = parsed;
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
                    cfg.consent_gate_open_threshold = parsed;
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
                    cfg.consent_gate_close_threshold = parsed;
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
                    cfg.consent_gate_hysteresis = parsed;
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
                    cfg.consent_gate_bias = parsed;
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
                    cfg.consent_gate_warmup_cycles = (int)parsed;
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
                    cfg.consent_gate_refractory_cycles = (int)parsed;
                }
            }
        } else if (strcmp(arg, "--fee") == 0) {
            cfg.fee_enabled = true;
        } else if (strncmp(arg, "--flow-alpha=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.flow_alpha = clamp_range(parsed, 0.0f, 1.0f);
                    cfg.fee_enabled = true;
                }
            }
        } else if (strncmp(arg, "--flow-gamma=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.flow_gamma = clamp_range(parsed, 0.0f, 1.0f);
                    cfg.fee_enabled = true;
                }
            }
        } else if (strcmp(arg, "--vse") == 0) {
            cfg.vse_enabled = true;
        } else if (strcmp(arg, "--vse-trace") == 0) {
            cfg.vse_enabled = true;
            cfg.vse_trace = true;
        } else if (strncmp(arg, "--vse-temp=", 11) == 0) {
            const char *value = arg + 11;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.vse_temp = clamp_range(parsed, 0.2f, 1.5f);
                    cfg.vse_enabled = true;
                }
            }
        } else if (strncmp(arg, "--vse-intent=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.vse_intent = clamp_unit(parsed);
                    cfg.vse_enabled = true;
                }
            }
        } else if (strncmp(arg, "--vse-importance=", 17) == 0) {
            const char *value = arg + 17;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.vse_importance = clamp_unit(parsed);
                    cfg.vse_enabled = true;
                }
            }
        } else if (strncmp(arg, "--vse-allow=", 12) == 0) {
            const char *value = arg + 12;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.vse_allowance = clamp_unit(parsed);
                    cfg.vse_enabled = true;
                }
            }
        } else if (strncmp(arg, "--vse-lambda-p=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.vse_lambda_p = clamp_range(parsed, 0.0f, 2.0f);
                    cfg.vse_enabled = true;
                }
            }
        } else if (strncmp(arg, "--vse-lambda-x=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.vse_lambda_x = clamp_range(parsed, 0.0f, 2.0f);
                    cfg.vse_enabled = true;
                }
            }
        } else if (strncmp(arg, "--allow-hold=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.vse_allowance_hold = clamp_unit(parsed);
                    cfg.vse_enabled = true;
                }
            }
        } else if (strncmp(arg, "--allow=", 8) == 0) {
            const char *value = arg + 8;
            if (value && *value) {
                if ((value[0] == 'n' || value[0] == 'N') &&
                    (value[1] == 'o' || value[1] == 'O') &&
                    (value[2] == 'w' || value[2] == 'W') &&
                    value[3] == '\0') {
                    cfg.vse_allowance_pulse += 0.1f;
                } else {
                    char *end = NULL;
                    float parsed = strtof(value, &end);
                    if (end != value && isfinite(parsed)) {
                        cfg.vse_allowance_pulse += parsed;
                    }
                }
                if (cfg.vse_allowance_pulse > 1.0f) {
                    cfg.vse_allowance_pulse = 1.0f;
                } else if (cfg.vse_allowance_pulse < -1.0f) {
                    cfg.vse_allowance_pulse = -1.0f;
                }
                cfg.vse_enabled = true;
            }
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
                    cfg.trs_alpha = parsed;
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
                    cfg.trs_warmup = (int)parsed;
                }
            }
        } else if (strcmp(arg, "--trs-adapt") == 0) {
            cfg.trs_adapt_enabled = true;
            cfg.trs_enabled = true;
        } else if (strncmp(arg, "--trs-alpha-min=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.trs_alpha_min = parsed;
                    cfg.trs_adapt_enabled = true;
                    cfg.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--trs-alpha-max=", 16) == 0) {
            const char *value = arg + 16;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.trs_alpha_max = parsed;
                    cfg.trs_adapt_enabled = true;
                    cfg.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--trs-target-delta=", sizeof("--trs-target-delta=") - 1) == 0) {
            const char *value = arg + (sizeof("--trs-target-delta=") - 1);
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.trs_target_delta = parsed;
                    cfg.trs_adapt_enabled = true;
                    cfg.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--trs-kp=", 9) == 0) {
            const char *value = arg + 9;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.trs_kp = parsed;
                    cfg.trs_adapt_enabled = true;
                    cfg.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--trs-ki=", 9) == 0) {
            const char *value = arg + 9;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.trs_ki = parsed;
                    cfg.trs_adapt_enabled = true;
                    cfg.trs_enabled = true;
                }
            }
        } else if (strncmp(arg, "--trs-kd=", 9) == 0) {
            const char *value = arg + 9;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.trs_kd = parsed;
                    cfg.trs_adapt_enabled = true;
                    cfg.trs_enabled = true;
                }
            }
        } else if (strcmp(arg, "--dream") == 0) {
            cfg.dream_enabled = true;
        } else if (strcmp(arg, "--dream-replay") == 0) {
            cfg.dream_replay_enabled = true;
        } else if (strncmp(arg, "--dream-cycles=", 15) == 0) {
            const char *value = arg + 15;
            if (*value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end != value && parsed > 0) {
                    if (parsed > 256) {
                        parsed = 256;
                    }
                    cfg.dream_replay_cycles = (int)parsed;
                    cfg.dream_replay_enabled = true;
                }
            }
        } else if (strncmp(arg, "--dream-rate=", 13) == 0) {
            const char *value = arg + 13;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.dream_replay_rate = clamp_range(parsed, 0.05f, 0.8f);
                    cfg.dream_replay_enabled = true;
                }
            }
        } else if (strncmp(arg, "--dream-decay=", 14) == 0) {
            const char *value = arg + 14;
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.0f) {
                        parsed = 0.0f;
                    } else if (parsed > 0.1f) {
                        parsed = 0.1f;
                    }
                    cfg.dream_replay_decay = parsed;
                    cfg.dream_replay_enabled = true;
                }
            }
        } else if (strcmp(arg, "--dream-trace") == 0) {
            cfg.dream_replay_trace = true;
            cfg.dream_replay_enabled = true;
        } else if (strcmp(arg, "--bridge") == 0) {
            cfg.bridge_enabled = true;
        } else if (strncmp(arg, "--bridge-plasticity=", sizeof("--bridge-plasticity=") - 1) == 0) {
            const char *value = arg + (sizeof("--bridge-plasticity=") - 1);
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.bridge_plasticity = clamp_unit(parsed);
                    cfg.bridge_enabled = true;
                }
            }
        } else if (strncmp(arg, "--bridge-retention=", sizeof("--bridge-retention=") - 1) == 0) {
            const char *value = arg + (sizeof("--bridge-retention=") - 1);
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    cfg.bridge_retention = clamp_unit(parsed);
                    cfg.bridge_enabled = true;
                }
            }
        } else if (strncmp(arg, "--bridge-recovery=", sizeof("--bridge-recovery=") - 1) == 0) {
            const char *value = arg + (sizeof("--bridge-recovery=") - 1);
            if (*value) {
                char *end = NULL;
                float parsed = strtof(value, &end);
                if (end != value && isfinite(parsed)) {
                    if (parsed < 0.0f) {
                        parsed = 0.0f;
                    } else if (parsed > 0.2f) {
                        parsed = 0.2f;
                    }
                    cfg.bridge_recovery = parsed;
                    cfg.bridge_enabled = true;
                }
            }
        } else if (strcmp(arg, "--strict-order") == 0) {
            cfg.strict_order = true;
        } else if (strcmp(arg, "--dry-run") == 0) {
            cfg.dry_run = true;
        } else if (strcmp(arg, "--bond-trace") == 0) {
            cfg.bond_trace = true;
        } else if (strncmp(arg, "--emotional-source=", sizeof("--emotional-source=") - 1) == 0) {
            const char *value = arg + (sizeof("--emotional-source=") - 1);
            if (strcmp(value, "text") == 0) {
                cfg.emotional_source = EMPATHIC_SOURCE_TEXT;
            } else if (strcmp(value, "sensor") == 0) {
                cfg.emotional_source = EMPATHIC_SOURCE_SENSOR;
            } else {
                cfg.emotional_source = EMPATHIC_SOURCE_AUDIO;
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
                    cfg.empathy_gain = parsed;
                }
            }
        } else if (strcmp(arg, "--emotional-memory") == 0) {
            cfg.emotional_memory_enabled = true;
        } else if (strcmp(arg, "--memory-trace") == 0) {
            cfg.memory_trace = true;
        } else if (strncmp(arg, "--emotion-trace-path=", 21) == 0) {
            const char *value = arg + 21;
            if (value && *value) {
                strncpy(cfg.emotion_trace_path, value, sizeof(cfg.emotion_trace_path) - 1U);
                cfg.emotion_trace_path[sizeof(cfg.emotion_trace_path) - 1U] = '\0';
            }
        } else if (strncmp(arg, "--limit=", 8) == 0) {
            const char *value = arg + 8;
            if (value && *value) {
                unsigned long parsed = strtoul(value, NULL, 10);
                if (parsed > 0UL && parsed <= 100000UL) {
                    cfg.cycle_limit = (unsigned int)parsed;
                }
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
                    cfg.recognition_threshold = parsed;
                }
            }
        }
    }

    normalize_bounds(&cfg.mirror_amp_min, &cfg.mirror_amp_max, MIRROR_GAIN_AMP_MIN_DEFAULT, MIRROR_GAIN_AMP_MAX_DEFAULT);
    normalize_bounds(&cfg.mirror_tempo_min,
                     &cfg.mirror_tempo_max,
                     MIRROR_GAIN_TEMPO_MIN_DEFAULT,
                     MIRROR_GAIN_TEMPO_MAX_DEFAULT);

    if (cfg.bridge_enabled) {
        if (!cfg.dream_replay_enabled) {
            cfg.dream_replay_enabled = true;
        }
        if (!cfg.harmony_enabled) {
            cfg.harmony_enabled = true;
        }
    }

    if ((cfg.harmony_enabled || cfg.dream_enabled || cfg.dream_replay_enabled) && !cfg.introspect_enabled) {
        cfg.introspect_enabled = true;
    }

    if (cfg.astro_trace) {
        cfg.astro_enabled = true;
    }
    if (cfg.astro_enabled) {
        if (!cfg.introspect_enabled) {
            cfg.introspect_enabled = true;
        }
        if (!cfg.harmony_enabled) {
            cfg.harmony_enabled = true;
        }
    }
    if ((cfg.dream_replay_enabled || cfg.bridge_enabled) && !cfg.harmony_enabled) {
        cfg.harmony_enabled = true;
    }

    return cfg;
}
