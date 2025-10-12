#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#include "empathic.h"
#include "emotion_memory.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#ifndef EMOTION_TRACE_PATH_MAX
#define EMOTION_TRACE_PATH_MAX 256
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
    bool lip_test;
    bool lip_trace;
    unsigned int lip_interval_ms;
    char lip_host[128];
    bool empathic_enabled;
    bool empathic_trace;
    EmpathicSource emotional_source;
    float empathy_gain;
    bool emotional_memory_enabled;
    bool memory_trace;
    float recognition_threshold;
    char emotion_trace_path[EMOTION_TRACE_PATH_MAX];
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
    cfg.lip_test = false;
    cfg.lip_trace = false;
    cfg.lip_interval_ms = 1000U;
    cfg.lip_host[0] = '\0';
    cfg.empathic_enabled = false;
    cfg.empathic_trace = false;
    cfg.emotional_source = EMPATHIC_SOURCE_AUDIO;
    cfg.empathy_gain = 1.0f;
    cfg.emotional_memory_enabled = false;
    cfg.memory_trace = false;
    cfg.recognition_threshold = 0.18f;
    cfg.emotion_trace_path[0] = '\0';

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
        } else if (strncmp(arg, "--emotional-source=", 20) == 0) {
            const char *value = arg + 20;
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

    return cfg;
}

static void lip_sleep(unsigned int interval_ms)
{
#ifdef _WIN32
    Sleep(interval_ms);
#else
    struct timespec ts;
    ts.tv_sec = interval_ms / 1000U;
    ts.tv_nsec = (long)(interval_ms % 1000U) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

static bool json_extract_float(const char *json, const char *key, float *out)
{
    const char *pos = strstr(json, key);
    if (!pos) {
        return false;
    }
    pos += strlen(key);
    while (*pos == ' ' || *pos == '\t' || *pos == '"' || *pos == ':' ) {
        ++pos;
    }
    if (*pos == '\0') {
        return false;
    }
    char *end_ptr = NULL;
    float value = strtof(pos, &end_ptr);
    if (end_ptr == pos) {
        return false;
    }
    *out = value;
    return true;
}

static void close_socket(int fd)
{
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}

static int lip_connect_peer(const substrate_config *cfg)
{
    if (cfg->lip_host[0] == '\0') {
        return -1;
    }
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return -1;
    }
#endif
    const char *separator = strrchr(cfg->lip_host, ':');
    if (!separator) {
        return -1;
    }
    char host[96];
    size_t host_len = (size_t)(separator - cfg->lip_host);
    if (host_len >= sizeof(host)) {
        host_len = sizeof(host) - 1U;
    }
    memcpy(host, cfg->lip_host, host_len);
    host[host_len] = '\0';
    const char *port_str = separator + 1;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *result = NULL;
    int err = getaddrinfo(host, port_str, &hints, &result);
    if (err != 0 || !result) {
        return -1;
    }
    int sock_fd = -1;
    for (struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next) {
        sock_fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock_fd < 0) {
            continue;
        }
        if (connect(sock_fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close_socket(sock_fd);
        sock_fd = -1;
    }
    freeaddrinfo(result);
    return sock_fd;
}

static int lip_listen_local(uint16_t port)
{
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return -1;
    }
#endif
    int sock_fd = (int)socket(AF_INET6, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        sock_fd = (int)socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd < 0) {
            return -1;
        }
    }
    int opt = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_any;
    addr6.sin6_port = htons(port);
    if (bind(sock_fd, (struct sockaddr *)&addr6, sizeof(addr6)) != 0) {
        close_socket(sock_fd);
        sock_fd = (int)socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd < 0) {
            return -1;
        }
        setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
        struct sockaddr_in addr4;
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        addr4.sin_addr.s_addr = htonl(INADDR_ANY);
        addr4.sin_port = htons(port);
        if (bind(sock_fd, (struct sockaddr *)&addr4, sizeof(addr4)) != 0) {
            close_socket(sock_fd);
            return -1;
        }
    }
    if (listen(sock_fd, 1) != 0) {
        close_socket(sock_fd);
        return -1;
    }
    return sock_fd;
}

static int lip_accept_peer(int listen_fd)
{
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    int client_fd = (int)accept(listen_fd, (struct sockaddr *)&addr, &addr_len);
    return client_fd;
}

static void run_lip_resonance_test(liminal_state *state, const substrate_config *cfg)
{
    int peer_fd = -1;
    int listen_fd = -1;
    bool connected = false;
    if (cfg->lip_host[0] != '\0') {
        peer_fd = lip_connect_peer(cfg);
        connected = peer_fd >= 0;
    } else if (cfg->lip_port != 0U) {
        listen_fd = lip_listen_local(cfg->lip_port);
        if (listen_fd >= 0) {
            if (cfg->trace || cfg->lip_trace) {
                printf("[lip] waiting for resonance peer on port %u\n", (unsigned)cfg->lip_port);
            }
            peer_fd = lip_accept_peer(listen_fd);
            connected = peer_fd >= 0;
        }
    }
    if (!connected) {
        fprintf(stderr, "[lip] unable to establish LIP channel.\n");
        if (listen_fd >= 0) {
            close_socket(listen_fd);
        }
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    float freq = 0.68f;
    float phase = 0.27f;
    state->breath_rate = freq;
    state->breath_position = phase;
    state->phase_offset = 0.0f;

    const int max_cycles = 10;
    char buffer[256];
    for (int cycle = 0; cycle < max_cycles; ++cycle) {
        lip_event ev = resonance_event(freq, phase, "sync");
        int len = snprintf(buffer,
                           sizeof(buffer),
                           "{ \"type\": \"%s\", \"freq\": %.3f, \"phase\": %.3f, \"intent\": \"%s\" }\n",
                           ev.type,
                           ev.freq,
                           ev.phase,
                           ev.intent);
        if (len <= 0 || len >= (int)sizeof(buffer)) {
            break;
        }
        if (cfg->lip_trace) {
            printf("[lip] send: %s", buffer);
        }
        if (send(peer_fd, buffer, (size_t)len, 0) < 0) {
            break;
        }

        int received = recv(peer_fd, buffer, sizeof(buffer) - 1, 0);
        if (received <= 0) {
            break;
        }
        buffer[received] = '\0';
        if (cfg->lip_trace) {
            printf("[lip] recv: %s\n", buffer);
        }
        float ack_freq = freq;
        float ack_phase = phase;
        bool got_freq = json_extract_float(buffer, "\"freq\"", &ack_freq);
        bool got_phase = json_extract_float(buffer, "\"phase\"", &ack_phase);
        if (!got_freq || !got_phase) {
            continue;
        }

        float delta = fabsf(freq - ack_freq) + fabsf(phase - ack_phase);
        float sync_level = delta < 0.05f ? 1.0f : fmaxf(0.0f, 1.0f - delta);
        float phase_shift = ack_phase - phase;
        state->sync_quality = 0.8f * state->sync_quality + 0.2f * sync_level;
        state->resonance = sync_level;
        state->breath_rate = 0.7f * state->breath_rate + 0.3f * ack_freq;
        phase = fmodf((phase + ack_phase) * 0.5f, 1.0f);
        state->breath_position = phase;

        const char *partner = cfg->lip_host[0] != '\0' ? cfg->lip_host : "external";
        printf("resonance_test: partner=%s sync=%.3f phase_shift=%.2f\n",
               partner,
               sync_level,
               phase_shift);

        lip_sleep(cfg->lip_interval_ms);
        freq = state->breath_rate;
    }

    close_socket(peer_fd);
    if (listen_fd >= 0) {
        close_socket(listen_fd);
    }
#ifdef _WIN32
    WSACleanup();
#endif
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
        EmpathicResponse response = {0};
        if (cfg->empathic_enabled) {
            float resonance_hint = clamp_unit(state->resonance);
            if (cfg->emotional_memory_enabled) {
                float boost = emotion_memory_resonance_boost();
                if (boost > 0.0f) {
                    resonance_hint = clamp_unit(resonance_hint + boost);
                }
            }
            response = empathic_step(0.80f, state->sync_quality, resonance_hint);
            state->resonance = response.resonance;
            float scale = response.delay_scale;
            if (isfinite(scale) && scale > 0.0f) {
                float adjust = 1.0f + (scale - 1.0f) * 0.3f;
                state->breath_rate *= adjust;
                if (state->breath_rate < 0.20f) {
                    state->breath_rate = 0.20f;
                } else if (state->breath_rate > 2.4f) {
                    state->breath_rate = 2.4f;
                }
            }
            state->phase_offset = fmodf(state->phase_offset + response.coherence_bias * 2.0f, 1.0f);
            if (state->phase_offset < 0.0f) {
                state->phase_offset += 1.0f;
            }
        }
        if (cfg->emotional_memory_enabled) {
            EmotionField field_snapshot = cfg->empathic_enabled ? response.field : empathic_field();
            emotion_memory_update(field_snapshot);
            if (!cfg->empathic_enabled) {
                float boost = emotion_memory_resonance_boost();
                if (boost > 0.0f) {
                    state->resonance = clamp_unit(state->resonance + boost * 0.2f);
                }
            }
        }
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

    empathic_init(cfg.emotional_source, cfg.empathic_trace, cfg.empathy_gain);
    empathic_enable(cfg.empathic_enabled);
    emotion_memory_configure(cfg.emotional_memory_enabled,
                             cfg.memory_trace,
                             cfg.emotion_trace_path[0] ? cfg.emotion_trace_path : NULL,
                             cfg.recognition_threshold);

    if (cfg.adaptive) {
        auto_adapt(&state, cfg.trace);
    }
    if (cfg.trace) {
        printf("[boot] adaptive=%s human_bridge=%s lip_port=%u\n",
               cfg.adaptive ? "on" : "off",
               cfg.human_bridge ? "on" : "off",
               (unsigned)cfg.lip_port);
    }

    if (cfg.lip_test) {
        run_lip_resonance_test(&state, &cfg);
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

    emotion_memory_finalize();

    return 0;
}
