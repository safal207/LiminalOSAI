#ifndef LIMINAL_PULSE_OPTIONS_H
#define LIMINAL_PULSE_OPTIONS_H

#include <stdbool.h>
#include <stdint.h>

#include "affinity.h"
#include "collective_memory.h"
#include "empathic.h"
#include "symbiosis.h"
#include "weave.h"

#ifndef EMOTION_TRACE_PATH_MAX
#define EMOTION_TRACE_PATH_MAX 256
#endif

typedef enum {
    ENSEMBLE_STRATEGY_AVG = 0,
    ENSEMBLE_STRATEGY_MEDIAN,
    ENSEMBLE_STRATEGY_LEADER
} ensemble_strategy;

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
    bool balancer_enabled;
    bool metabolic_enabled;
    bool metabolic_trace;
    bool human_bridge_enabled;
    bool human_trace;
    SymbiosisSource human_source;
    float human_resonance_gain;
    bool empathic_enabled;
    bool empathic_trace;
    bool anticipation_trace;
    bool anticipation2_enabled;
    bool ant2_trace;
    float ant2_gain;
    EmpathicSource emotional_source;
    float empathy_gain;
    bool emotional_memory_enabled;
    bool memory_trace;
    float recognition_threshold;
    char emotion_trace_path[EMOTION_TRACE_PATH_MAX];
    uint64_t limit;
    uint32_t scan_interval;
    float target_coherence;
    bool collective_enabled;
    bool collective_trace;
    bool collective_memory_enabled;
    bool collective_memory_trace;
    int cm_snapshot_interval;
    char cm_path[CM_PATH_MAX];
    float group_target;
    ensemble_strategy ensemble_mode;
    float council_threshold;
    int phase_count;
    float phase_shift_deg[WEAVE_MODULE_COUNT];
    bool phase_shift_set[WEAVE_MODULE_COUNT];
    float dream_threshold;
    float vitality_rest_threshold;
    float vitality_creative_threshold;
    bool affinity_enabled;
    bool bond_trace_enabled;
    Affinity affinity_config;
    float allow_align_consent;
    bool mirror_enabled;
    bool mirror_trace;
    float mirror_softness;
    float mirror_amp_min;
    float mirror_amp_max;
    float mirror_tempo_min;
    float mirror_tempo_max;
    bool introspect_enabled;
    bool harmony_enabled;
    bool qel_enabled;
    float qel_retro_gain;
    uint32_t entangle_ctx;
    bool astro_enabled;
    bool astro_trace;
    float astro_rate;
    float astro_tone_init;
    float astro_memory_init;
    bool astro_tone_set;
    bool astro_memory_set;
    bool trs_enabled;
    float trs_alpha;
    int trs_warmup;
    bool trs_adapt_enabled;
    float trs_alpha_min;
    float trs_alpha_max;
    float trs_target_delta;
    float trs_kp;
    float trs_ki;
    float trs_kd;
    bool kiss_enabled;
    float kiss_trust_threshold;
    float kiss_presence_threshold;
    float kiss_harmony_threshold;
    int kiss_warmup_cycles;
    int kiss_refractory_cycles;
    float kiss_alpha;
    float consent_gate_open_threshold;
    float consent_gate_close_threshold;
    float consent_gate_hysteresis;
    float consent_gate_bias;
    int consent_gate_warmup_cycles;
    int consent_gate_refractory_cycles;
    bool vse_enabled;
    bool vse_trace;
    float vse_temp;
    float vse_intent;
    float vse_importance;
    float vse_allowance;
    float vse_lambda_p;
    float vse_lambda_x;
    float vse_allowance_hold;
    float vse_allowance_pulse;
    bool strict_order;
    bool dry_run;
} kernel_options;

/* Entry validation precedes semantic parsing. This function retains the
 * existing defaults, clamping, dependencies and unknown-option behavior. */
kernel_options pulse_options_parse(int argc, char **argv);

#endif /* LIMINAL_PULSE_OPTIONS_H */
