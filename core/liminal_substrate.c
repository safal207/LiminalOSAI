#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#ifdef __unix__
#include <unistd.h>
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

typedef struct {
    float breath_rate;
    float breath_position;
    float memory_trace;
    float resonance;
    float sync_quality;
    float vitality;
    float phase_offset;
    uint32_t cycles;
    bool adaptive_profile;
    bool human_affinity_active;
} liminal_state;

typedef struct {
    char type[24];
    float freq;
    float phase;
    char intent[24];
} lip_event;

typedef struct {
    bool run_substrate;
    bool adaptive;
    bool trace;
    bool human_bridge;
    uint16_t lip_port;
} substrate_config;

static void rebirth(liminal_state *state)
{
    state->breath_rate = 0.72f;
    state->breath_position = 0.0f;
    state->memory_trace = 0.0f;
    state->resonance = 0.50f;
    state->sync_quality = 0.50f;
    state->vitality = 0.60f;
    state->phase_offset = 0.0f;
    state->cycles = 0U;
    state->adaptive_profile = false;
    state->human_affinity_active = false;
}

static void remember(liminal_state *state, float imprint)
{
    const float blend = 0.18f;
    state->memory_trace = state->memory_trace * (1.0f - blend) + imprint * blend;
    if (state->memory_trace > 1.0f) {
        state->memory_trace = 1.0f;
    } else if (state->memory_trace < -1.0f) {
        state->memory_trace = -1.0f;
    }
}

static void rest(liminal_state *state)
{
    state->vitality += 0.02f;
    if (state->vitality > 1.0f) {
        state->vitality = 1.0f;
    }
    state->breath_rate *= 0.995f;
    if (state->breath_rate < 0.20f) {
        state->breath_rate = 0.20f;
    }
}

static void reflect(liminal_state *state)
{
    state->resonance = 0.6f * state->resonance + 0.4f * state->memory_trace;
    if (state->resonance < 0.0f) {
        state->resonance = 0.0f;
    } else if (state->resonance > 1.0f) {
        state->resonance = 1.0f;
    }
}

static void pulse(liminal_state *state, float delta)
{
    state->breath_position += state->breath_rate * delta;
    if (state->breath_position >= 1.0f) {
        state->breath_position -= (float)floor(state->breath_position);
        state->cycles += 1U;
    }
    state->sync_quality = 0.70f * state->sync_quality + 0.30f * (1.0f - fabsf(0.5f - state->breath_position));
}

static lip_event resonance_event(float freq, float phase, const char *intent)
{
    lip_event ev;
    memset(&ev, 0, sizeof(ev));
    strncpy(ev.type, "resonance", sizeof(ev.type) - 1U);
    ev.freq = freq;
    ev.phase = phase;
    strncpy(ev.intent, intent, sizeof(ev.intent) - 1U);
    return ev;
}

static void emit_lip_event(const lip_event *event)
{
    printf("{ \"type\": \"%s\", \"freq\": %.3f, \"phase\": %.3f, \"intent\": \"%s\" }\n",
           event->type,
           event->freq,
           event->phase,
           event->intent);
}

static void auto_adapt(liminal_state *state, bool trace)
{
#ifdef __unix__
    long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    long page_size = sysconf(_SC_PAGESIZE);
    long phys_pages = sysconf(_SC_PHYS_PAGES);
    if (cpu_count < 1) {
        cpu_count = 1;
    }
    float cpu_factor = (float)cpu_count;
    float ram_mb = 0.0f;
    if (page_size > 0 && phys_pages > 0) {
        ram_mb = (float)(phys_pages) * (float)page_size / (1024.0f * 1024.0f);
    }
    float ram_factor = ram_mb > 0.0f ? fminf(ram_mb / 512.0f, 4.0f) : 1.0f;
#else
    float cpu_factor = 1.0f;
    float ram_factor = 1.0f;
#endif
    state->breath_rate = 0.40f + 0.05f * cpu_factor;
    state->memory_trace = fminf(0.10f * ram_factor, 0.8f);
    state->adaptive_profile = true;
    if (trace) {
        printf("[auto-adapt] cpu_factor=%.2f ram_factor=%.2f breath_rate=%.2f memory=%.2f\n",
               cpu_factor,
               ram_factor,
               state->breath_rate,
               state->memory_trace);
    }
}

static void human_affinity_bridge(liminal_state *state, bool trace)
{
    const char *heart_env = getenv("LIMINAL_HEART_RATE");
    float heart_rate = 68.0f;
    if (heart_env && *heart_env) {
        heart_rate = strtof(heart_env, NULL);
    }
    float normalized = heart_rate / 100.0f;
    if (normalized < 0.2f) {
        normalized = 0.2f;
    } else if (normalized > 2.4f) {
        normalized = 2.4f;
    }
    state->breath_rate = 0.5f * state->breath_rate + 0.5f * normalized;
    state->phase_offset = fmodf(state->phase_offset + normalized * 0.1f, 1.0f);
    state->human_affinity_active = true;
    if (trace) {
        printf("[human-bridge] heart=%.2f normalized=%.2f new_breath=%.2f\n",
               heart_rate,
               normalized,
               state->breath_rate);
    }
}

static substrate_config parse_args(int argc, char **argv)
{
    substrate_config cfg;
    cfg.run_substrate = false;
    cfg.adaptive = false;
    cfg.trace = false;
    cfg.human_bridge = false;
    cfg.lip_port = 0U;

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
        }
    }

    return cfg;
}

static void substrate_loop(liminal_state *state, const substrate_config *cfg)
{
    const unsigned int max_cycles = 6U;
    if (cfg->lip_port != 0U) {
        printf("[substrate] listening for LIP resonance on port %u\n", cfg->lip_port);
    }
    while (state->cycles < max_cycles) {
        pulse(state, 0.25f);
        reflect(state);
        rest(state);
        remember(state, state->resonance * 0.75f + state->breath_position * 0.25f);
        float phase = fmodf(state->breath_position + state->phase_offset, 1.0f);
        lip_event event = resonance_event(state->breath_rate, phase, "align");
        emit_lip_event(&event);
        printf("resonance: sync=%.3f phase=%.2f\n", state->sync_quality, phase);
        if (cfg->human_bridge && !state->human_affinity_active && state->cycles >= 2U) {
            human_affinity_bridge(state, cfg->trace);
        }
        if (cfg->trace) {
            printf("[trace] cycle=%u breath=%.3f resonance=%.3f memory=%.3f vitality=%.3f\n",
                   state->cycles,
                   state->breath_rate,
                   state->resonance,
                   state->memory_trace,
                   state->vitality);
        }
    }
}

int main(int argc, char **argv)
{
    substrate_config cfg = parse_args(argc, argv);
    if (!cfg.run_substrate) {
        fprintf(stderr, "Liminal Substrate: use --substrate to start the universal core.\n");
        return 1;
    }

    liminal_state state;
    rebirth(&state);

    if (cfg.adaptive) {
        auto_adapt(&state, cfg.trace);
    }
    if (cfg.trace) {
        printf("[boot] adaptive=%s human_bridge=%s lip_port=%u\n",
               cfg.adaptive ? "on" : "off",
               cfg.human_bridge ? "on" : "off",
               (unsigned)cfg.lip_port);
    }

    substrate_loop(&state, &cfg);

    if (cfg.human_bridge && state.human_affinity_active) {
        printf("[bridge] human affinity synchronized. breath=%.3f phase=%.2f\n",
               state.breath_rate,
               fmodf(state.breath_position + state.phase_offset, 1.0f));
    }
    if (cfg.trace) {
        printf("[shutdown] cycles=%u resonance=%.3f memory=%.3f vitality=%.3f\n",
               state.cycles,
               state.resonance,
               state.memory_trace,
               state.vitality);
    }

    return 0;
}
