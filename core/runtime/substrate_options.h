#ifndef LIMINAL_SUBSTRATE_OPTIONS_H
#define LIMINAL_SUBSTRATE_OPTIONS_H

#include <stdbool.h>
#include <stdint.h>

#include "affinity.h"
#include "empathic.h"

#ifndef EMOTION_TRACE_PATH_MAX
#define EMOTION_TRACE_PATH_MAX 256
#endif

typedef enum {
    ERB_REPLAY_NONE = 0,
    ERB_REPLAY_LATEST,
    ERB_REPLAY_INDEX,
    ERB_REPLAY_TAG,
    ERB_REPLAY_ALL
} ErbReplayMode;

typedef enum {
    TUNE_SOURCE_NONE = 0,
    TUNE_SOURCE_LATEST,
    TUNE_SOURCE_INDEX,
    TUNE_SOURCE_TAG,
    TUNE_SOURCE_ALL
} TuneSourceMode;

typedef struct {
    bool run_substrate;
    bool adaptive;
    bool trace;
    bool human_bridge;
    uint16_t lip_port;
    bool lip_test;
    bool lip_trace;
    unsigned int lip_interval_ms;
    char lip_host[128];
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
    unsigned int cycle_limit;
    bool affinity_enabled;
    bool bond_trace;
    Affinity affinity_config;
    float allow_align_consent;
    float mirror_amp_min;
    float mirror_amp_max;
    float mirror_tempo_min;
    float mirror_tempo_max;
    bool strict_order;
    bool dry_run;
    bool introspect_enabled;
    bool harmony_enabled;
    bool qel_enabled;
    float qel_retro_gain;
    uint32_t entangle_ctx;
    bool dream_enabled;
    bool dream_replay_enabled;
    bool astro_enabled;
    bool astro_trace;
    float astro_rate;
    float astro_tone_init;
    float astro_memory_init;
    bool astro_tone_set;
    bool astro_memory_set;
    int dream_replay_cycles;
    float dream_replay_rate;
    float dream_replay_decay;
    bool dream_replay_trace;
    bool bridge_enabled;
    float bridge_plasticity;
    float bridge_retention;
    float bridge_recovery;
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
    bool fee_enabled;
    float flow_alpha;
    float flow_gamma;
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
    bool erb_enabled;
    int erb_pre;
    int erb_post;
    float erb_spike;
    ErbReplayMode erb_replay_mode;
    uint32_t erb_replay_idx;
    uint32_t erb_replay_tag_mask;
    float erb_replay_speed;
    bool tune_enabled;
    bool tune_apply;
    bool tune_report;
    int tune_trials;
    int tune_refine;
    int tune_max_runs;
    float tune_alpha_min;
    float tune_alpha_max;
    int tune_warm_min;
    int tune_warm_max;
    float tune_align_min;
    float tune_align_max;
    char tune_save_path[256];
    char tune_load_path[256];
    int tune_seed;
    int tune_select_n;
    TuneSourceMode tune_source_mode;
    uint32_t tune_source_idx;
    uint32_t tune_source_mask;
} substrate_config;

/* Entry validation precedes semantic parsing. Repeated options, clamping
 * and the runtime-specific dependency rules retain their existing meaning. */
substrate_config substrate_options_parse(int argc, char **argv);

#endif /* LIMINAL_SUBSTRATE_OPTIONS_H */
