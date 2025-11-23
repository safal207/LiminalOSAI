#include "vse.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef VSE_TRACE_PATH
#define VSE_TRACE_PATH "logs/vse_trace.jsonl"
#endif

typedef struct {
    int enabled;
    VSECfg cfg;
    float lambda_p;
    float lambda_x;
    float allowance_hold;
    float allowance_pulse;
    VNode *nodes;
    int node_count;
    unsigned long tick;
    int trace_enabled;
    FILE *trace_stream;
    float last_allowance;
} VSEContext;

static VSEContext g_vse_ctx = {0};

static float
clamp_range(float value, float min_value, float max_value)
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

static float
clamp_unit(float value)
{
    if (!isfinite(value)) {
        return 0.0f;
    }
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

static float
sanitize_value(float value, float fallback)
{
    if (!isfinite(value)) {
        return fallback;
    }
    return value;
}

static void
vse_close_trace(void)
{
    if (g_vse_ctx.trace_stream) {
        fclose(g_vse_ctx.trace_stream);
        g_vse_ctx.trace_stream = NULL;
    }
}

static void
ensure_logs_directory(void)
{
    struct stat st;
    if (stat("logs", &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return;
        }
    }
#ifdef _WIN32
    if (mkdir("logs") != 0) {
        if (errno != EEXIST) {
            return;
        }
    }
#else
    if (mkdir("logs", 0755) != 0) {
        if (errno != EEXIST) {
            return;
        }
    }
#endif
}

static void
vse_open_trace_if_needed(void)
{
    if (!g_vse_ctx.trace_enabled || g_vse_ctx.trace_stream) {
        return;
    }
    ensure_logs_directory();
    g_vse_ctx.trace_stream = fopen(VSE_TRACE_PATH, "a");
    if (!g_vse_ctx.trace_stream) {
        g_vse_ctx.trace_enabled = 0;
    }
}

static void
vse_log_choice(int choice, float score, float pendulum, float temp, float allowance)
{
    if (!g_vse_ctx.trace_enabled || !g_vse_ctx.trace_stream) {
        return;
    }
    fprintf(g_vse_ctx.trace_stream,
            "{\"tick\":%lu,\"intent\":%.3f,\"importance\":%.3f,\"allow\":%.3f,"
            "\"excess\":%.3f,\"choice\":%d,\"score\":%.3f,\"pendulum\":%.3f,\"temp\":%.3f}\n",
            g_vse_ctx.tick,
            clamp_unit(g_vse_ctx.cfg.intent),
            clamp_unit(g_vse_ctx.cfg.importance),
            clamp_unit(allowance),
            clamp_unit(g_vse_ctx.cfg.importance - allowance),
            choice,
            score,
            clamp_unit(pendulum),
            clamp_range(temp, 0.2f, 1.5f));
    fflush(g_vse_ctx.trace_stream);
}

void
vse_init(VSECfg cfg)
{
    g_vse_ctx.enabled = 1;
    g_vse_ctx.cfg.intent = clamp_unit(cfg.intent);
    g_vse_ctx.cfg.importance = clamp_unit(cfg.importance);
    g_vse_ctx.cfg.allowance = clamp_unit(cfg.allowance);
    g_vse_ctx.cfg.temp = clamp_range(sanitize_value(cfg.temp, 1.0f), 0.2f, 1.5f);
    g_vse_ctx.lambda_p = 0.2f;
    g_vse_ctx.lambda_x = 0.4f;
    g_vse_ctx.allowance_hold = clamp_unit(g_vse_ctx.allowance_hold);
    g_vse_ctx.allowance_pulse = 0.0f;
    g_vse_ctx.tick = 0UL;
    g_vse_ctx.last_allowance = g_vse_ctx.cfg.allowance;
    if (g_vse_ctx.trace_enabled && !g_vse_ctx.trace_stream) {
        vse_open_trace_if_needed();
    }
}

void
vse_finalize(void)
{
    vse_close_trace();
    if (g_vse_ctx.nodes) {
        free(g_vse_ctx.nodes);
        g_vse_ctx.nodes = NULL;
    }
    g_vse_ctx.node_count = 0;
    g_vse_ctx.enabled = 0;
    g_vse_ctx.cfg.intent = 0.0f;
    g_vse_ctx.cfg.importance = 0.0f;
    g_vse_ctx.cfg.allowance = 0.0f;
    g_vse_ctx.cfg.temp = 1.0f;
    g_vse_ctx.lambda_p = 0.2f;
    g_vse_ctx.lambda_x = 0.4f;
    g_vse_ctx.allowance_hold = 0.0f;
    g_vse_ctx.allowance_pulse = 0.0f;
    g_vse_ctx.tick = 0UL;
    g_vse_ctx.last_allowance = 0.0f;
}

void
vse_set_graph(const VNode *nodes, int n)
{
    if (g_vse_ctx.nodes) {
        free(g_vse_ctx.nodes);
        g_vse_ctx.nodes = NULL;
        g_vse_ctx.node_count = 0;
    }
    if (!nodes || n <= 0) {
        return;
    }
    VNode *copy = (VNode *)malloc((size_t)n * sizeof(VNode));
    if (!copy) {
        return;
    }
    for (int i = 0; i < n; ++i) {
        copy[i].p = clamp_unit(sanitize_value(nodes[i].p, 0.0f));
        copy[i].value = sanitize_value(nodes[i].value, 0.0f);
        copy[i].cost = sanitize_value(nodes[i].cost, 0.0f);
        if (copy[i].cost < 0.0f) {
            copy[i].cost = 0.0f;
        }
        copy[i].pendulum = clamp_unit(sanitize_value(nodes[i].pendulum, 0.0f));
    }
    g_vse_ctx.nodes = copy;
    g_vse_ctx.node_count = n;
}

void
vse_set_temperature(float temp)
{
    g_vse_ctx.cfg.temp = clamp_range(sanitize_value(temp, g_vse_ctx.cfg.temp > 0.0f ? g_vse_ctx.cfg.temp : 1.0f), 0.2f, 1.5f);
}

void
vse_set_intent(float intent)
{
    g_vse_ctx.cfg.intent = clamp_unit(intent);
}

void
vse_set_importance(float importance)
{
    g_vse_ctx.cfg.importance = clamp_unit(importance);
}

void
vse_set_allowance(float allowance)
{
    g_vse_ctx.cfg.allowance = clamp_unit(allowance);
}

void
vse_schedule_allowance(float delta)
{
    float adjusted = sanitize_value(delta, 0.0f);
    g_vse_ctx.allowance_pulse += adjusted;
    if (g_vse_ctx.allowance_pulse > 1.0f) {
        g_vse_ctx.allowance_pulse = 1.0f;
    } else if (g_vse_ctx.allowance_pulse < -1.0f) {
        g_vse_ctx.allowance_pulse = -1.0f;
    }
}

void
vse_set_allowance_hold(float hold)
{
    g_vse_ctx.allowance_hold = clamp_unit(hold);
}

void
vse_set_lambda(float lambda_p, float lambda_x)
{
    g_vse_ctx.lambda_p = clamp_range(sanitize_value(lambda_p, g_vse_ctx.lambda_p), 0.0f, 2.0f);
    g_vse_ctx.lambda_x = clamp_range(sanitize_value(lambda_x, g_vse_ctx.lambda_x), 0.0f, 2.0f);
}

void
vse_enable_trace(int enabled)
{
    g_vse_ctx.trace_enabled = enabled ? 1 : 0;
    if (g_vse_ctx.trace_enabled) {
        vse_open_trace_if_needed();
    } else {
        vse_close_trace();
    }
}

VSECfg
vse_current_cfg(void)
{
    return g_vse_ctx.cfg;
}

static int
select_choice(const float *weights, int count)
{
    if (!weights || count <= 0) {
        return -1;
    }
    float total = 0.0f;
    for (int i = 0; i < count; ++i) {
        total += weights[i];
    }
    if (!(total > 0.0f)) {
        float best_value = weights[0];
        int best_index = 0;
        for (int i = 1; i < count; ++i) {
            if (weights[i] > best_value) {
                best_value = weights[i];
                best_index = i;
            }
        }
        return best_index;
    }
    float sample = (float)rand() / (float)RAND_MAX;
    float threshold = sample * total;
    float accum = 0.0f;
    for (int i = 0; i < count; ++i) {
        accum += weights[i];
        if (threshold <= accum) {
            return i;
        }
    }
    return count - 1;
}

int
vse_pick(VSEState *st)
{
    if (!g_vse_ctx.enabled || !g_vse_ctx.nodes || g_vse_ctx.node_count <= 0) {
        return -1;
    }

    float allowance = clamp_unit(g_vse_ctx.cfg.allowance);
    float effective_allowance = allowance + g_vse_ctx.allowance_hold;
    effective_allowance = clamp_unit(effective_allowance);
    if (g_vse_ctx.allowance_pulse != 0.0f) {
        effective_allowance = clamp_unit(effective_allowance + g_vse_ctx.allowance_pulse);
        g_vse_ctx.allowance_pulse = 0.0f;
    }
    g_vse_ctx.last_allowance = effective_allowance;

    float excess = g_vse_ctx.cfg.importance - effective_allowance;
    if (!isfinite(excess)) {
        excess = 0.0f;
    }
    if (excess < 0.0f) {
        excess = 0.0f;
    } else if (excess > 1.0f) {
        excess = 1.0f;
    }

    float drive = g_vse_ctx.cfg.intent - excess;
    drive = clamp_range(drive, -1.0f, 1.0f);
    float state_bias = st ? st->bias : 0.0f;
    float combined_bias = clamp_range(drive + state_bias, -1.5f, 1.5f);

    float temp = g_vse_ctx.cfg.temp;
    if (!isfinite(temp) || temp <= 0.0f) {
        temp = 1.0f;
    }
    temp = clamp_range(temp, 0.2f, 1.5f);

    int n = g_vse_ctx.node_count;
    float *scaled = (float *)malloc((size_t)n * sizeof(float));
    float *weights = (float *)malloc((size_t)n * sizeof(float));
    float *base_scores = (float *)malloc((size_t)n * sizeof(float));
    if (!scaled || !weights || !base_scores) {
        free(scaled);
        free(weights);
        free(base_scores);
        return -1;
    }

    float max_scaled = -INFINITY;
    for (int i = 0; i < n; ++i) {
        const VNode *node = &g_vse_ctx.nodes[i];
        float prior = node->p;
        float value = sanitize_value(node->value, 0.0f);
        float cost = sanitize_value(node->cost, 0.0f);
        if (cost < 0.0f) {
            cost = 0.0f;
        }
        float pendulum = node->pendulum;
        float base = value - cost;
        base += (prior - 0.5f) * 0.3f;
        base += combined_bias * 0.4f;
        base -= g_vse_ctx.lambda_p * pendulum;
        base -= g_vse_ctx.lambda_x * excess;
        if (pendulum > 0.7f) {
            float reduction = pendulum > 0.9f ? 0.4f : 0.3f;
            base *= (1.0f - reduction);
        }
        if (!isfinite(base)) {
            base = -1.0e6f;
        }
        base_scores[i] = base;
        float scaled_value = base / temp;
        if (!isfinite(scaled_value)) {
            scaled_value = base;
        }
        scaled[i] = scaled_value;
        if (scaled_value > max_scaled) {
            max_scaled = scaled_value;
        }
    }

    if (!isfinite(max_scaled)) {
        max_scaled = 0.0f;
    }

    for (int i = 0; i < n; ++i) {
        float weight = expf(scaled[i] - max_scaled);
        if (!isfinite(weight) || weight < 0.0f) {
            weight = 0.0f;
        }
        weights[i] = weight;
    }

    int choice = select_choice(weights, n);

    if (st) {
        st->excess = excess;
        st->bias = clamp_range(combined_bias * 0.5f, -0.8f, 0.8f);
    }

    if (choice >= 0 && choice < n) {
        vse_log_choice(choice,
                       base_scores[choice],
                       g_vse_ctx.nodes[choice].pendulum,
                       temp,
                       effective_allowance);
    }
    ++g_vse_ctx.tick;

    free(scaled);
    free(weights);
    free(base_scores);

    return choice;
}

void
vse_feedback(VSEState *st, float outcome)
{
    if (!g_vse_ctx.enabled || !st) {
        return;
    }
    float delta = sanitize_value(outcome, 0.0f);
    if (delta > 1.0f) {
        delta = 1.0f;
    } else if (delta < -1.0f) {
        delta = -1.0f;
    }
    float release = 0.015f;
    if (delta > 0.0f) {
        release += delta * 0.05f;
    }
    float rebound = delta < 0.0f ? (-delta) * 0.05f : 0.0f;
    float new_importance = g_vse_ctx.cfg.importance - release + rebound;
    if (new_importance < g_vse_ctx.cfg.allowance) {
        new_importance = g_vse_ctx.cfg.allowance;
    }
    g_vse_ctx.cfg.importance = clamp_unit(new_importance);

    float measured_excess = g_vse_ctx.cfg.importance - g_vse_ctx.last_allowance;
    if (!isfinite(measured_excess)) {
        measured_excess = 0.0f;
    }
    st->excess = clamp_unit(measured_excess);
    st->bias = clamp_range(st->bias + delta * 0.05f, -0.8f, 0.8f);
}
