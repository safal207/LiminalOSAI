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
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

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
#include "metabolic.h"
#include "symbiosis.h"
#include "empathic.h"
#include "emotion_memory.h"
#include "anticipation_v2.h"
#include "mirror.h"

#define ENERGY_INHALE   3U
#define ENERGY_REFLECT  5U
#define ENERGY_EXHALE   2U

#define SENSOR_INHALE   1
#define SENSOR_REFLECT  2
#define SENSOR_EXHALE   3

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

static float clamp_range(float value, float min_value, float max_value)
{
    if (!isfinite(value)) {
        return min_value;
    }
    if (value < min_value) {
        return min_value;
    }
    if (value > max_value) {
        return max_value;
    }
    return value;
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

static RGraph collective_graph = {0};
static bool collective_active = false;
static bool collective_trace_enabled = false;
static ensemble_strategy collective_strategy = ENSEMBLE_STRATEGY_MEDIAN;
static float collective_target_level = 0.82f;
static float collective_pending_adjust = 0.0f;
static int collective_node_capacity = 0;
static int collective_edge_capacity = 0;
static const int COLLECTIVE_DEFAULT_NODES = 16;
static bool collective_memory_enabled = false;
static bool collective_memory_trace_enabled = false;
static bool collective_memory_initialized = false;
static bool collective_signature_ready = false;
static uint32_t collective_signature_value = 0;
static CMemRing collective_memory_ring = {{0.0f}, {0.0f}, 0, 0};
static char collective_memory_store_path[CM_PATH_MAX] = {0};
static CMemTrace *collective_memory_match_trace = NULL;
static float collective_memory_match_score = 0.0f;
static float collective_warmup_adjust = 0.0f;
static int collective_warmup_cycles_remaining = 0;
static uint64_t collective_cycle_count = 0;
static bool collective_flag_anticipation = false;
static bool collective_flag_dream = false;
static bool collective_flag_balancer = false;
static const int COLLECTIVE_WARMUP_LIMIT = 4;

static bool affinity_layer_enabled = false;
static Affinity affinity_profile = {0.0f, 0.0f, 0.0f};
static BondGate bond_gate_state = {0.0f, 0.0f, 0.0f, 0.0f};
static float explicit_consent_level = 0.2f;
static bool ant2_module_enabled = false;
static Ant2 ant2_state;
static float ant2_delay_factor = 1.0f;
static const float ANT2_BASE_DELAY = 0.1f;
static bool mirror_module_enabled = false;
static float mirror_gain_amp = 1.0f;
static float mirror_gain_tempo = 1.0f;

typedef struct {
    AwarenessState awareness_snapshot;
    const CoherenceField *coherence_field;
    float coherence_level;
    DreamAlignmentBalance dream_balance;
    InnerCouncil council;
    bool council_active;
    bool human_bridge_active;
    HumanPulse human_pulse;
    float human_alignment;
    float human_resonance_level;
    bool empathic_layer_active;
    EmpathicResponse empathic_response;
    float anticipation_field;
    float anticipation_level;
    float anticipation_micro;
    float anticipation_trend;
    float resonance_for_coherence;
    float stability_for_coherence;
    float awareness_for_coherence;
    float energy_avg;
    float resonance_avg;
    float stability;
} AwarenessCoherenceFeedback;

static const char *ensemble_strategy_name(ensemble_strategy mode)
{
    switch (mode) {
    case ENSEMBLE_STRATEGY_AVG:
        return "avg";
    case ENSEMBLE_STRATEGY_LEADER:
        return "leader";
    case ENSEMBLE_STRATEGY_MEDIAN:
    default:
        return "median";
    }
}

static void collective_begin_cycle(void)
{
    collective_pending_adjust = 0.0f;
    if (!collective_active) {
        return;
    }
    if (!collective_graph.nodes || !collective_graph.edges) {
        return;
    }
    collective_graph.n_nodes = 0;
    collective_graph.n_edges = 0;
}

static int collective_add_node(const char *id, float vitality, float pulse)
{
    if (!collective_active || !collective_graph.nodes) {
        return -1;
    }
    if (collective_graph.n_nodes >= collective_node_capacity || collective_node_capacity <= 0) {
        return -1;
    }

    float vitality_clamped = clamp_unit(isfinite(vitality) ? vitality : 0.0f);
    if (vitality_clamped <= 0.0f) {
        return -1;
    }

    RNode *node = &collective_graph.nodes[collective_graph.n_nodes];
    memset(node, 0, sizeof(*node));
    if (id && *id) {
        size_t len = strlen(id);
        if (len >= sizeof(node->id)) {
            len = sizeof(node->id) - 1;
        }
        memcpy(node->id, id, len);
        node->id[len] = '\0';
    } else {
        snprintf(node->id, sizeof(node->id), "n%d", collective_graph.n_nodes);
    }
    node->vitality = vitality_clamped;
    node->pulse = clamp_unit(isfinite(pulse) ? pulse : 0.0f);
    ++collective_graph.n_nodes;
    return collective_graph.n_nodes - 1;
}

static void collective_connect_complete(void)
{
    if (!collective_active || !collective_graph.edges || collective_graph.n_nodes < 2) {
        collective_graph.n_edges = 0;
        return;
    }

    int edge_index = 0;
    for (int i = 0; i < collective_graph.n_nodes - 1; ++i) {
        for (int j = i + 1; j < collective_graph.n_nodes; ++j) {
            if (edge_index >= collective_edge_capacity) {
                collective_graph.n_edges = edge_index;
                return;
            }
            REdge *edge = &collective_graph.edges[edge_index++];
            edge->a = i;
            edge->b = j;
            edge->harmony = 0.0f;
            edge->flux = 0.0f;
        }
    }
    collective_graph.n_edges = edge_index;
}

typedef struct {
    float harmony;
    float flux;
} weighted_edge;

static int compare_weighted_edge(const void *lhs, const void *rhs)
{
    const weighted_edge *a = (const weighted_edge *)lhs;
    const weighted_edge *b = (const weighted_edge *)rhs;
    if (a->harmony < b->harmony) {
        return -1;
    }
    if (a->harmony > b->harmony) {
        return 1;
    }
    return 0;
}

static float collective_weighted_median(const RGraph *graph)
{
    if (!graph || graph->n_edges <= 0) {
        return 0.0f;
    }

    int count = graph->n_edges;
    weighted_edge *copies = (weighted_edge *)malloc((size_t)count * sizeof(weighted_edge));
    if (!copies) {
        return graph->group_coh;
    }

    int actual = 0;
    float total_flux = 0.0f;
    for (int i = 0; i < count; ++i) {
        const REdge *edge = &graph->edges[i];
        if (!edge || edge->flux <= 0.0f) {
            continue;
        }
        copies[actual].harmony = clamp_unit(edge->harmony);
        copies[actual].flux = edge->flux;
        total_flux += edge->flux;
        ++actual;
    }

    if (actual == 0 || total_flux <= 0.0f) {
        free(copies);
        return graph->group_coh;
    }

    qsort(copies, (size_t)actual, sizeof(weighted_edge), compare_weighted_edge);
    float target = total_flux * 0.5f;
    float accum = 0.0f;
    float median = copies[actual - 1].harmony;
    for (int i = 0; i < actual; ++i) {
        accum += copies[i].flux;
        if (accum >= target) {
            median = copies[i].harmony;
            break;
        }
    }

    free(copies);
    return clamp_unit(median);
}

static float collective_leader_pulse(const RGraph *graph)
{
    if (!graph || graph->n_nodes <= 0) {
        return 0.0f;
    }
    float best_vitality = -1.0f;
    float leader_pulse = 0.0f;
    for (int i = 0; i < graph->n_nodes; ++i) {
        const RNode *node = &graph->nodes[i];
        if (!node) {
            continue;
        }
        if (node->vitality > best_vitality) {
            best_vitality = node->vitality;
            leader_pulse = node->pulse;
        }
    }
    if (best_vitality <= 0.0f) {
        return 0.0f;
    }
    return clamp_unit(leader_pulse);
}

static float collective_effective_coherence(const RGraph *graph)
{
    if (!graph) {
        return 0.0f;
    }

    float base = clamp_unit(graph->group_coh);
    switch (collective_strategy) {
    case ENSEMBLE_STRATEGY_AVG:
        return base;
    case ENSEMBLE_STRATEGY_LEADER: {
        float leader = collective_leader_pulse(graph);
        if (leader <= 0.0f) {
            return base;
        }
        return clamp_unit(0.6f * base + 0.4f * leader);
    }
    case ENSEMBLE_STRATEGY_MEDIAN:
    default: {
        float median = collective_weighted_median(graph);
        if (median <= 0.0f) {
            return base;
        }
        return clamp_unit(0.5f * base + 0.5f * median);
    }
    }
}

static FILE *collective_log_open(void)
{
    if (mkdir("logs", 0777) != 0) {
        if (errno != EEXIST) {
            return NULL;
        }
    }
    return fopen("logs/collective_trace.log", "a");
}

static void collective_trace_log(const RGraph *graph, float adjust)
{
    if (!collective_trace_enabled || !graph) {
        return;
    }

    FILE *fp = collective_log_open();
    if (!fp) {
        return;
    }

    fprintf(fp,
            "{\"nodes\":%d,\"edges\":%d,\"group_coh\":%.2f,\"adjust\":%.3f,\"strategy\":\"%s\"}\n",
            graph->n_nodes,
            graph->n_edges,
            graph->group_coh,
            adjust,
            ensemble_strategy_name(collective_strategy));
    fclose(fp);
}

static void collective_memory_log_echo(uint32_t signature, float match_score, const CMemTrace *match, float warmup)
{
    if (!collective_memory_trace_enabled && !collective_trace_enabled) {
        return;
    }
    FILE *fp = collective_log_open();
    if (!fp) {
        return;
    }
    float coh = match ? match->group_coh_avg : 0.0f;
    float adj = match ? match->adjust_avg : 0.0f;
    fprintf(fp,
            "memory_echo: sig=0x%08" PRIX32 " match=%.2f coh_avg=%.2f adj_avg=%+.2f warmup=%+.2f\n",
            signature,
            match_score,
            coh,
            adj,
            warmup);
    fclose(fp);
}

static void collective_memory_log_snapshot(const CMemTrace *snapshot)
{
    if (!snapshot) {
        return;
    }
    if (!collective_memory_trace_enabled && !collective_trace_enabled) {
        return;
    }
    FILE *fp = collective_log_open();
    if (!fp) {
        return;
    }
    fprintf(fp,
            "snapshot:    coh_avg=%.2f adj_avg=%+.2f vol=%.3f saved=%s\n",
            snapshot->group_coh_avg,
            snapshot->adjust_avg,
            snapshot->volatility,
            collective_memory_store_path[0] ? collective_memory_store_path : "soil/collective_memory.jsonl");
    fclose(fp);
}

typedef struct {
    uint8_t version;
    uint8_t strategy;
    uint8_t flags;
    uint8_t reserved;
    uint16_t nodes;
    uint16_t edges;
    int16_t vitality_q;
    int16_t leader_q;
    int16_t average_q;
    int16_t median_q;
} CollectiveSignatureContext;

static uint32_t collective_compute_signature(const RGraph *graph)
{
    CollectiveSignatureContext ctx = {0};
    ctx.version = 1;
    ctx.strategy = (uint8_t)collective_strategy;
    uint8_t flags = 0;
    if (collective_flag_anticipation) {
        flags |= 0x01u;
    }
    if (collective_flag_dream) {
        flags |= 0x02u;
    }
    if (collective_flag_balancer) {
        flags |= 0x04u;
    }
    ctx.flags = flags;
    if (graph) {
        if (graph->n_nodes < 0) {
            ctx.nodes = 0;
        } else if (graph->n_nodes > UINT16_MAX) {
            ctx.nodes = UINT16_MAX;
        } else {
            ctx.nodes = (uint16_t)graph->n_nodes;
        }
        if (graph->n_edges < 0) {
            ctx.edges = 0;
        } else if (graph->n_edges > UINT16_MAX) {
            ctx.edges = UINT16_MAX;
        } else {
            ctx.edges = (uint16_t)graph->n_edges;
        }

        if (graph->n_nodes > 0) {
            double vitality_sum = 0.0;
            double pulse_sum = 0.0;
            for (int i = 0; i < graph->n_nodes; ++i) {
                const RNode *node = &graph->nodes[i];
                vitality_sum += clamp_unit(isfinite(node->vitality) ? node->vitality : 0.0f);
                pulse_sum += clamp_unit(isfinite(node->pulse) ? node->pulse : 0.0f);
            }
            float vitality_avg = (float)(vitality_sum / (double)graph->n_nodes);
            float pulse_avg = (float)(pulse_sum / (double)graph->n_nodes);
            vitality_avg = cm_clamp(vitality_avg, 0.0f, 1.0f);
            pulse_avg = cm_clamp(pulse_avg, 0.0f, 1.0f);
            ctx.vitality_q = (int16_t)lrintf(vitality_avg * 100.0f);
            ctx.average_q = (int16_t)lrintf(pulse_avg * 100.0f);
        }

        float leader = cm_clamp(collective_leader_pulse(graph), 0.0f, 1.0f);
        float median = cm_clamp(collective_weighted_median(graph), 0.0f, 1.0f);
        ctx.leader_q = (int16_t)lrintf(leader * 100.0f);
        ctx.median_q = (int16_t)lrintf(median * 100.0f);
    }

    return cm_signature_hash(&ctx, sizeof(ctx));
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
        .mirror_softness = 0.5f
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
    double delay_after_coherence = base_delay * coherence_delay_scale();
    if (!isfinite(delay_after_coherence) || delay_after_coherence <= 0.0) {
        delay_after_coherence = base_delay;
    }

    double awareness_scaled = awareness_adjust_delay(delay_after_coherence);
    double awareness_factor = 1.0;
    if (delay_after_coherence > 0.0) {
        awareness_factor = awareness_scaled / delay_after_coherence;
    }
    if (!isfinite(awareness_factor) || awareness_factor <= 0.0) {
        awareness_factor = 1.0;
    }

    float awareness_adj = (float)(1.0 - awareness_factor);
    if (!isfinite(awareness_adj)) {
        awareness_adj = 0.0f;
    }

    double final_factor = awareness_factor;
    if (collective_active) {
        float collective_adj = collective_pending_adjust;
        if (!isfinite(collective_adj)) {
            collective_adj = 0.0f;
        }
        if (affinity_layer_enabled) {
            float gated_adj = bond_gate_apply(collective_adj, &bond_gate_state);
            if (bond_gate_log_enabled()) {
                bond_gate_trace(&affinity_profile, &bond_gate_state, gated_adj);
            }
            collective_adj = gated_adj;
        }
        if (fabsf(collective_adj) > 0.0001f) {
            float total_adj = collective_adj;
            if (fabsf(awareness_adj) > 0.0001f) {
                total_adj = 0.5f * awareness_adj + 0.5f * collective_adj;
            }
            if (total_adj > 0.95f) {
                total_adj = 0.95f;
            } else if (total_adj < -0.95f) {
                total_adj = -0.95f;
            }
            final_factor = 1.0 - (double)total_adj;
        }
    }

    if (!isfinite(final_factor)) {
        final_factor = 1.0;
    }
    if (collective_memory_enabled && collective_cycle_count <= 1 && fabsf(collective_warmup_adjust) > 0.0001f) {
        double warm_factor = 1.0 - (double)collective_warmup_adjust;
        if (warm_factor < 0.5) {
            warm_factor = 0.5;
        } else if (warm_factor > 1.5) {
            warm_factor = 1.5;
        }
        final_factor *= warm_factor;
    }
    double baseline_factor = final_factor;
    if (ant2_module_enabled) {
        double adjusted_factor = final_factor * (double)ant2_delay_factor;
        float feedback_delta_rel = 0.0f;
        if (baseline_factor > 0.0) {
            feedback_delta_rel = (float)(adjusted_factor / baseline_factor - 1.0);
        }
        ant2_feedback_adjust(&ant2_state, feedback_delta_rel, ANT2_FEEDBACK_WINDUP_THRESHOLD);
        final_factor = adjusted_factor;
    }
    if (final_factor < 0.1) {
        final_factor = 0.1;
    } else if (final_factor > 2.0) {
        final_factor = 2.0;
    }

    double tuned_delay = delay_after_coherence * final_factor;
    collective_pending_adjust = 0.0f;

    tuned_delay *= metabolic_delay_scale();
    tuned_delay *= symbiosis_delay_scale();
    tuned_delay *= empathic_delay_scale();

    if (isfinite(mirror_gain_tempo) && mirror_gain_tempo > 0.0f) {
        tuned_delay /= (double)mirror_gain_tempo;
    }

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

static float anticipation2_feedforward(const kernel_options *opts)
{
    float cycle_influence = affinity_layer_enabled ? clamp_unit(bond_gate_state.influence) : 1.0f;

    if (ant2_module_enabled) {
        float target_coh = opts ? opts->target_coherence : 0.8f;
        const CoherenceField *previous_field = coherence_state();
        float actual_coh = previous_field ? clamp_unit(previous_field->coherence) : target_coh;
        double last_delay = coherence_last_delay();
        float delay_norm = 1.0f;
        if (isfinite(last_delay) && ANT2_BASE_DELAY > 0.0f) {
            delay_norm = (float)(last_delay / ANT2_BASE_DELAY);
        }
        if (!isfinite(delay_norm) || delay_norm < 0.0f) {
            delay_norm = 1.0f;
        }
        float pred_coh = 0.0f;
        float pred_delay = 0.0f;
        float ff = 0.0f;
        ant2_delay_factor = ant2_feedforward(&ant2_state,
                                             target_coh,
                                             actual_coh,
                                             delay_norm,
                                             cycle_influence,
                                             &pred_coh,
                                             &pred_delay,
                                             &ff);
    } else {
        ant2_delay_factor = 1.0f;
    }

    symbol_set_affinity_scale(cycle_influence);
    return cycle_influence;
}

static AwarenessCoherenceFeedback
awareness_coherence_feedback(const kernel_options *opts,
                             float energy_avg,
                             float resonance_avg,
                             float stability,
                             size_t active_count)
{
    AwarenessCoherenceFeedback feedback = {0};

    HumanPulse human_pulse = {0.0f, 0.0f, 0.0f};
    float human_alignment = 0.0f;
    float human_resonance_level = 0.0f;
    float human_reflection_boost = 0.0f;
    float human_metabolic_intake = 0.0f;
    float human_metabolic_output = 0.0f;
    bool human_bridge_active = opts && opts->human_bridge_enabled;
    EmpathicResponse empathic_response = (EmpathicResponse){0};
    bool empathic_layer_active = opts && opts->empathic_enabled;
    bool emotional_memory_active = opts && opts->emotional_memory_enabled;
    float anticipation_field = 0.5f;
    float anticipation_level = 0.5f;
    float anticipation_micro = 0.5f;
    float anticipation_trend = 0.5f;

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

    if (empathic_layer_active) {
        float alignment_hint = human_bridge_active ? human_alignment : stability;
        float resonance_hint = clamp_unit(resonance_avg / 12.0f);
        if (emotional_memory_active) {
            float boost = emotion_memory_resonance_boost();
            if (boost > 0.0f) {
                resonance_hint = clamp_unit(resonance_hint + boost);
            }
        }
        empathic_response = empathic_step(opts->target_coherence, alignment_hint, resonance_hint);
        coherence_set_target(empathic_response.target_coherence);
        anticipation_field = empathic_response.field.anticipation;
        anticipation_level = empathic_response.anticipation_level;
        anticipation_micro = empathic_response.micro_pattern_signal;
        anticipation_trend = empathic_response.prediction_trend;
        if (opts->anticipation_trace) {
            printf("anticipation_bridge: field=%.2f level=%.2f micro=%.2f trend=%.2f target=%.2f\n",
                   anticipation_field,
                   anticipation_level,
                   anticipation_micro,
                   anticipation_trend,
                   empathic_response.target_coherence);
        }
    }

    if (emotional_memory_active) {
        EmotionField field_snapshot = empathic_layer_active ? empathic_response.field : empathic_field();
        emotion_memory_update(field_snapshot);
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
    DreamAlignmentBalance dream_balance = (DreamAlignmentBalance){0.0f, 0.0f, 0.5f};
    float awareness_energy = awareness_snapshot.awareness_level * 0.6f;
    if (human_bridge_active) {
        awareness_energy += (human_resonance_level - 0.5f) * 0.12f;
        if (awareness_energy < 0.0f) {
            awareness_energy = 0.0f;
        }
    }
    float reflection_energy = stability * 0.4f + human_reflection_boost;
    if (empathic_layer_active) {
        awareness_energy = clamp_unit(awareness_energy + (empathic_response.field.warmth - 0.5f) * 0.08f);
        reflection_energy = clamp_unit(reflection_energy + (0.5f - empathic_response.field.tension) * 0.05f);
        awareness_energy = clamp_unit(awareness_energy + (anticipation_field - 0.5f) * 0.06f);
    }
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

    InnerCouncil council = (InnerCouncil){0};
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
                                     anticipation_field,
                                     anticipation_level,
                                     anticipation_micro,
                                     anticipation_trend,
                                     opts->council_threshold);
            if (opts->council_enabled) {
                pid_scale = 1.0f + council.final_decision * 0.1f;
            }
        }
    }

    dream_balance = dream_alignment_balance(council_active ? &council : NULL,
                                            dream_snapshot,
                                            anticipation_field,
                                            anticipation_level,
                                            anticipation_trend);
    anticipation_level = clamp_unit(anticipation_level * 0.7f + dream_balance.anticipation_sync * 0.3f);
    anticipation_field = clamp_unit(anticipation_field * 0.8f + dream_balance.anticipation_sync * 0.2f);
    anticipation_trend = clamp_unit(anticipation_trend * 0.85f + dream_balance.balance_strength * 0.08f +
                                    dream_balance.anticipation_sync * 0.07f);
    if (council_active) {
        pid_scale += dream_balance.balance_strength * 0.05f;
    } else {
        pid_scale += dream_balance.balance_strength * 0.02f;
    }

    if (!isfinite(pid_scale) || pid_scale <= 0.0f) {
        pid_scale = 1.0f;
    }

    coherence_set_pid_scale(pid_scale);

    float resonance_for_coherence = resonance_avg;
    float stability_for_coherence = stability;
    float awareness_for_coherence = awareness_snapshot.awareness_level;
    if (empathic_layer_active) {
        float anticipation_bias = (anticipation_level - 0.5f) * 2.0f;
        float micro_bias = (anticipation_micro - 0.5f) * 1.2f;
        float trend_bias = (anticipation_trend - 0.5f) * 1.5f;
        resonance_for_coherence += (anticipation_bias + micro_bias + trend_bias);
        if (resonance_for_coherence < 0.0f) {
            resonance_for_coherence = 0.0f;
        } else if (resonance_for_coherence > 12.0f) {
            resonance_for_coherence = 12.0f;
        }
        stability_for_coherence = clamp_unit(stability + (anticipation_level - 0.5f) * 0.12f);
        awareness_for_coherence =
            clamp_unit(awareness_snapshot.awareness_level + (anticipation_trend - 0.5f) * 0.10f);
    }

    resonance_for_coherence += dream_balance.balance_strength * 0.6f;
    if (resonance_for_coherence < 0.0f) {
        resonance_for_coherence = 0.0f;
    } else if (resonance_for_coherence > 12.0f) {
        resonance_for_coherence = 12.0f;
    }
    stability_for_coherence = clamp_unit(stability_for_coherence + dream_balance.coherence_bias);
    awareness_for_coherence = clamp_unit(awareness_for_coherence + dream_balance.coherence_bias * 0.5f);

    const CoherenceField *coherence_field =
        coherence_update(energy_avg, resonance_for_coherence, stability_for_coherence, awareness_for_coherence);

    float coherence_level = coherence_field ? coherence_field->coherence : 0.0f;
    if (empathic_layer_active) {
        coherence_level = empathic_apply_coherence(coherence_level);
    }
    dream_update(coherence_level,
                 awareness_snapshot.awareness_level,
                 anticipation_field,
                 anticipation_level,
                 anticipation_micro,
                 anticipation_trend,
                 dream_balance.balance_strength);

    feedback.awareness_snapshot = awareness_snapshot;
    feedback.coherence_field = coherence_field;
    feedback.coherence_level = coherence_level;
    feedback.dream_balance = dream_balance;
    feedback.council = council;
    feedback.council_active = council_active;
    feedback.human_bridge_active = human_bridge_active;
    feedback.human_pulse = human_pulse;
    feedback.human_alignment = human_alignment;
    feedback.human_resonance_level = human_resonance_level;
    feedback.empathic_layer_active = empathic_layer_active;
    feedback.empathic_response = empathic_response;
    feedback.anticipation_field = anticipation_field;
    feedback.anticipation_level = anticipation_level;
    feedback.anticipation_micro = anticipation_micro;
    feedback.anticipation_trend = anticipation_trend;
    feedback.resonance_for_coherence = resonance_for_coherence;
    feedback.stability_for_coherence = stability_for_coherence;
    feedback.awareness_for_coherence = awareness_for_coherence;
    feedback.energy_avg = energy_avg;
    feedback.resonance_avg = resonance_avg;
    feedback.stability = stability;

    return feedback;
}

static void collective_adjust(const AwarenessCoherenceFeedback *feedback)
{
    if (!collective_active) {
        return;
    }

    if (!collective_graph.nodes || !collective_graph.edges) {
        collective_pending_adjust = 0.0f;
        return;
    }

    const AwarenessState *awareness_snapshot = &feedback->awareness_snapshot;
    const CoherenceField *coherence_field = feedback->coherence_field;
    float coherence_level = feedback->coherence_level;
    float stability_for_coherence = feedback->stability_for_coherence;
    const DreamAlignmentBalance *dream_balance = &feedback->dream_balance;
    bool council_active = feedback->council_active;
    const InnerCouncil *council = &feedback->council;
    bool human_bridge_active = feedback->human_bridge_active;
    const HumanPulse *human_pulse = &feedback->human_pulse;
    float human_alignment = feedback->human_alignment;
    bool empathic_layer_active = feedback->empathic_layer_active;
    const EmpathicResponse *empathic_response = &feedback->empathic_response;
    float anticipation_level = feedback->anticipation_level;
    float anticipation_trend = feedback->anticipation_trend;
    float anticipation_field = feedback->anticipation_field;

    float awareness_vitality = clamp_unit(awareness_snapshot->awareness_level);
    if (awareness_vitality > 0.0f) {
        collective_add_node("awareness", awareness_vitality, clamp_unit(awareness_snapshot->self_coherence));
    }

    float coherence_vitality = clamp_unit(coherence_level);
    float coherence_pulse = coherence_field ? clamp_unit(coherence_field->resonance_smooth) : coherence_vitality;
    if (coherence_vitality > 0.0f) {
        collective_add_node("coherence", coherence_vitality, coherence_pulse);
    }

    float stability_vitality = clamp_unit(stability_for_coherence);
    if (stability_vitality > 0.0f) {
        collective_add_node("stability", stability_vitality, stability_vitality);
    }

    float dream_vitality = clamp_unit(fabsf(dream_balance->balance_strength));
    if (dream_vitality > 0.0f) {
        float dream_pulse = clamp_unit(0.5f + 0.5f * dream_balance->anticipation_sync);
        collective_add_node("dream", dream_vitality, dream_pulse);
    }

    if (council_active) {
        float council_vitality = clamp_unit(fabsf(council->final_decision));
        if (council_vitality > 0.0f) {
            float council_pulse = clamp_unit(0.5f + 0.5f * council->final_decision);
            collective_add_node("council", council_vitality, council_pulse);
        }
    }

    if (human_bridge_active) {
        float human_vitality = clamp_unit(human_alignment);
        if (human_vitality > 0.0f) {
            float human_pulse_norm = clamp_unit(human_pulse->beat_rate * 0.5f);
            collective_add_node("human", human_vitality, human_pulse_norm);
        }
    }

    if (empathic_layer_active) {
        float empathy_vitality = clamp_unit(empathic_response->field.harmony);
        if (empathy_vitality > 0.0f) {
            float empathy_pulse = clamp_unit(empathic_response->field.anticipation);
            collective_add_node("empathy", empathy_vitality, empathy_pulse);
        }
    }

    float anticipation_vitality = clamp_unit((anticipation_level + anticipation_trend) * 0.5f);
    if (anticipation_vitality > 0.0f) {
        collective_add_node("anticipation", anticipation_vitality, clamp_unit(anticipation_field));
    }

    collective_connect_complete();
    rgraph_update_edges(&collective_graph);
    rgraph_compute_coh(&collective_graph);
    collective_graph.group_coh = collective_effective_coherence(&collective_graph);

    if (collective_memory_enabled) {
        collective_signature_value = collective_compute_signature(&collective_graph);
        collective_signature_ready = true;
        if (!collective_memory_initialized) {
            const char *store_path = collective_memory_store_path[0] ? collective_memory_store_path
                                                                     : "soil/collective_memory.jsonl";
            collective_memory_match_trace = cm_best_match(collective_signature_value, store_path);
            if (collective_memory_match_trace) {
                collective_memory_match_score =
                    cm_signature_similarity(collective_signature_value, collective_memory_match_trace->signature);
                int distance =
                    cm_signature_distance(collective_signature_value, collective_memory_match_trace->signature);
                float match_coh = collective_memory_match_trace->group_coh_avg;
                if (!isfinite(match_coh)) {
                    match_coh = collective_target_level;
                }
                match_coh = cm_clamp(match_coh, 0.0f, 1.0f);
                float blended = 0.5f * 0.82f + 0.5f * match_coh;
                collective_target_level = clamp_unit(blended);
                float warmup = collective_memory_match_trace->adjust_avg;
                if (!isfinite(warmup)) {
                    warmup = 0.0f;
                }
                warmup = cm_clamp(warmup, -0.05f, 0.05f);
                if (distance > 4) {
                    warmup = 0.0f;
                }
                collective_warmup_adjust = warmup;
                collective_warmup_cycles_remaining = warmup != 0.0f ? COLLECTIVE_WARMUP_LIMIT : 0;
            } else {
                collective_memory_match_score = 0.0f;
                collective_warmup_adjust = 0.0f;
                collective_warmup_cycles_remaining = 0;
            }
            collective_memory_initialized = true;
            collective_memory_log_echo(collective_signature_value,
                                       collective_memory_match_score,
                                       collective_memory_match_trace,
                                       collective_warmup_adjust);
        }
    } else {
        collective_signature_ready = false;
    }

    float adjust = rgraph_ensemble_adjust(&collective_graph, collective_target_level);
    collective_pending_adjust = adjust;
    if (collective_graph.n_edges > 0 && fabsf(adjust) > 0.0001f) {
        bus_emit_wave("ensemble", fabsf(adjust));
    }
    collective_trace_log(&collective_graph, adjust);
    if (collective_memory_enabled && collective_signature_ready) {
        cm_ring_push(&collective_memory_ring, collective_graph.group_coh, adjust);
        if (collective_warmup_cycles_remaining > 0) {
            --collective_warmup_cycles_remaining;
            if (collective_warmup_cycles_remaining == 0) {
                collective_warmup_adjust = 0.0f;
            }
        }
        if (cm_should_snapshot(&collective_memory_ring)) {
            CMemTrace snapshot = cm_build_snapshot(&collective_memory_ring, collective_signature_value);
            const char *store_path = collective_memory_store_path[0] ? collective_memory_store_path
                                                                     : "soil/collective_memory.jsonl";
            cm_store(&snapshot, store_path);
            collective_memory_log_snapshot(&snapshot);
        }
    }
}

static void exhale(const kernel_options *opts)
{
    soil_decay();

    float cycle_influence = anticipation2_feedforward(opts);

    const char *label = "exhale";
    soil_trace trace = soil_trace_make(ENERGY_EXHALE, label, strlen(label));
    soil_write(&trace);

    static const char exhale_signal[] = "ebb";

    collective_begin_cycle();

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

    if (affinity_layer_enabled) {
        energy_avg *= cycle_influence;
        resonance_avg *= cycle_influence;
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

    if (affinity_layer_enabled) {
        stability *= cycle_influence;
        if (stability > 1.0f) {
            stability = 1.0f;
        }
    }

    AwarenessCoherenceFeedback feedback =
        awareness_coherence_feedback(opts, energy_avg, resonance_avg, stability, active_count);

    energy_avg = feedback.energy_avg;
    resonance_avg = feedback.resonance_avg;
    stability = feedback.stability;

    AwarenessState awareness_snapshot = feedback.awareness_snapshot;
    const CoherenceField *coherence_field = feedback.coherence_field;
    float coherence_level = feedback.coherence_level;
    DreamAlignmentBalance dream_balance = feedback.dream_balance;
    InnerCouncil council = feedback.council;
    bool council_active = feedback.council_active;
    bool human_bridge_active = feedback.human_bridge_active;
    HumanPulse human_pulse = feedback.human_pulse;
    float human_alignment = feedback.human_alignment;
    float human_resonance_level = feedback.human_resonance_level;

    collective_adjust(&feedback);

    if (affinity_layer_enabled) {
        float field_coherence = coherence_field ? clamp_unit(coherence_field->coherence) : 0.0f;
        float explicit_consent = clamp_unit(explicit_consent_level);
        float implicit_consent = 0.0f;
        if (human_bridge_active) {
            implicit_consent = clamp_unit(human_alignment);
            if (explicit_consent < 0.6f && implicit_consent > 0.6f) {
                implicit_consent = 0.6f;
            }
        }
        float consent_level = explicit_consent;
        if (implicit_consent > consent_level) {
            consent_level = implicit_consent;
        }
        bond_gate_update(&bond_gate_state, &affinity_profile, consent_level, field_coherence);
        bool allow_personal = bond_gate_state.consent >= 0.3f && bond_gate_state.influence > 0.0f;
        dream_set_affinity_gate(bond_gate_state.influence, allow_personal);
        cycle_influence = clamp_unit(bond_gate_state.influence);
    } else {
        dream_set_affinity_gate(1.0f, true);
        cycle_influence = 1.0f;
    }

    if (mirror_module_enabled) {
        float mirror_energy = active_count > 0 ? clamp_unit(energy_avg / 12.0f) : 0.0f;
        float mirror_calm = clamp_unit(stability);
        float mirror_tempo = 0.0f;
        if (coherence_field) {
            mirror_tempo = clamp_unit(coherence_field->resonance_smooth / 12.0f);
        } else {
            mirror_tempo = active_count > 0 ? clamp_unit(resonance_avg / 12.0f) : 0.0f;
        }
        float mirror_consent = affinity_layer_enabled ? bond_gate_state.consent : 1.0f;
        float mirror_influence = affinity_layer_enabled ? cycle_influence : 1.0f;
        if (mirror_consent < 0.3f || mirror_influence < 0.3f) {
            mirror_reset();
            mirror_gain_amp = 1.0f;
            mirror_gain_tempo = 1.0f;
        } else {
            MirrorGains mirror_gains =
                mirror_update(mirror_influence, mirror_energy, mirror_calm, mirror_tempo, mirror_consent);
            mirror_gain_amp = clamp_range(mirror_gains.gain_amp, 0.5f, 1.2f);
            mirror_gain_tempo = clamp_range(mirror_gains.gain_tempo, 0.8f, 1.2f);
            if (fabsf(mirror_gain_amp - 1.0f) > 0.0001f) {
                symbol_scale_active(mirror_gain_amp);
            }
        }
    } else {
        mirror_gain_amp = 1.0f;
        mirror_gain_tempo = 1.0f;
    }

    if (collective_active) {
        ++collective_cycle_count;
    }

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
               coherence_level,
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
        printf("council: refl=%+0.2f aware=%+0.2f coh=%+0.2f health=%+0.2f anti=%+0.2f (field=%+0.2f level=%+0.2f micro=%+0.2f trend=%+0.2f) bal=%+0.2f => decision=%+0.2f\n",
               council.reflection_vote,
               council.awareness_vote,
               council.coherence_vote,
               council.health_vote,
               council.anticipation_vote,
               council.anticipation_field_vote,
               council.anticipation_level_vote,
               council.anticipation_micro_vote,
               council.anticipation_trend_vote,
               dream_balance.balance_strength,
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

    resonant_msg exhale_msg =
        resonant_msg_make(SENSOR_EXHALE, RESONANT_BROADCAST_ID, ENERGY_EXHALE, exhale_signal, sizeof(exhale_signal) - 1);
    bus_emit(&exhale_msg);

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

    collective_active = opts.collective_enabled || opts.collective_trace;
    collective_trace_enabled = opts.collective_trace;
    collective_strategy = opts.ensemble_mode;
    collective_target_level = clamp_unit(opts.group_target);
    collective_pending_adjust = 0.0f;
    collective_memory_enabled = collective_active && opts.collective_memory_enabled;
    collective_memory_trace_enabled = opts.collective_memory_trace;
    collective_memory_initialized = false;
    collective_signature_ready = false;
    collective_memory_match_score = 0.0f;
    collective_warmup_adjust = 0.0f;
    collective_warmup_cycles_remaining = 0;
    collective_cycle_count = 0;
    if (collective_memory_match_trace) {
        cm_trace_free(collective_memory_match_trace);
        collective_memory_match_trace = NULL;
    }
    collective_flag_anticipation = opts.anticipation_trace;
    collective_flag_dream = opts.dream_enabled;
    collective_flag_balancer = opts.balancer_enabled;
    if (collective_memory_enabled) {
        strncpy(collective_memory_store_path, opts.cm_path, sizeof(collective_memory_store_path) - 1);
        collective_memory_store_path[sizeof(collective_memory_store_path) - 1] = '\0';
        cm_ring_reset(&collective_memory_ring);
        cm_set_snapshot_interval(opts.cm_snapshot_interval);
    } else {
        collective_memory_store_path[0] = '\0';
    }
    if (collective_active) {
        collective_node_capacity = COLLECTIVE_DEFAULT_NODES;
        if (collective_node_capacity < 2) {
            collective_node_capacity = 2;
        }
        collective_edge_capacity = (collective_node_capacity * (collective_node_capacity - 1)) / 2;
        rgraph_init(&collective_graph, collective_node_capacity, collective_edge_capacity);
    } else {
        collective_node_capacity = 0;
        collective_edge_capacity = 0;
    }

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
    empathic_init(opts.emotional_source, opts.empathic_trace, opts.empathy_gain);
    empathic_enable(opts.empathic_enabled);
    emotion_memory_configure(opts.emotional_memory_enabled,
                             opts.memory_trace,
                             opts.emotion_trace_path[0] ? opts.emotion_trace_path : NULL,
                             opts.recognition_threshold);
    symbiosis_init(opts.human_source, opts.human_trace, opts.human_resonance_gain);
    symbiosis_enable(opts.human_bridge_enabled);

    bond_gate_set_log_enabled(opts.bond_trace_enabled);
    affinity_layer_enabled = opts.affinity_enabled;
    affinity_profile = opts.affinity_config;
    explicit_consent_level = clamp_unit(opts.allow_align_consent);
    bond_gate_reset(&bond_gate_state);
    if (affinity_layer_enabled) {
        bond_gate_update(&bond_gate_state, &affinity_profile, explicit_consent_level, 0.0f);
        float initial_influence = clamp_unit(bond_gate_state.influence);
        symbol_set_affinity_scale(initial_influence);
        dream_set_affinity_gate(bond_gate_state.influence, bond_gate_state.consent >= 0.3f);
    } else {
        bond_gate_state.influence = 1.0f;
        bond_gate_state.consent = 0.0f;
        bond_gate_state.bond_coh = 0.0f;
        bond_gate_state.safety = 0.0f;
        symbol_set_affinity_scale(1.0f);
        dream_set_affinity_gate(1.0f, true);
    }

    mirror_reset();
    mirror_set_softness(opts.mirror_softness);
    mirror_set_trace(opts.mirror_trace);
    mirror_enable(opts.mirror_enabled);
    mirror_module_enabled = opts.mirror_enabled;
    mirror_gain_amp = 1.0f;
    mirror_gain_tempo = 1.0f;

    ant2_module_enabled = opts.anticipation2_enabled;
    ant2_delay_factor = 1.0f;
    if (ant2_module_enabled) {
        ant2_init(&ant2_state, opts.ant2_gain);
        ant2_set_trace(opts.ant2_trace);
    }
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
        if (opts.empathic_enabled) {
            coherence_value = empathic_coherence_value(coherence_value);
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

    emotion_memory_finalize();
    metabolic_shutdown();

    if (collective_memory_match_trace) {
        cm_trace_free(collective_memory_match_trace);
        collective_memory_match_trace = NULL;
    }

    return 0;
}
