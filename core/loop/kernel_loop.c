#define _POSIX_C_SOURCE 199309L

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#ifdef _WIN32
#include <windows.h>
#endif

#include "kernel_loop.h"
#include "soil.h"
#include "resonant.h"
#include "awareness.h"
#include "coherence.h"
#include "collective.h"
#include "affinity.h"
#include "metabolic.h"
#include "symbiosis.h"
#include "empathic.h"
#include "mirror.h"
#include "anticipation_v2.h"
#include "astro_sync.h"
#include "dream.h"
#include "consent_gate.h"
#include "kiss.h"
#include "vse.h"
#include "qel.h"
#include "introspect.h"
#include "harmony.h"
#include "emotion_memory.h"
#include "symbol.h"
#include "reflection.h"
#include "council.h"
#include "collective_memory.h"
#include "health_scan.h"
#include "weave.h"
#include "string_utils.h"

/* Внешние состояния из pulse_kernel */
extern bool collective_active;
extern bool collective_memory_enabled;
extern bool collective_memory_trace_enabled;
extern bool ant2_module_enabled;
extern bool mirror_module_enabled;
extern bool kiss_module_enabled;
extern bool astro_layer_enabled;
extern bool affinity_layer_enabled;
extern BondGateState bond_gate_state;
extern Affinity affinity_profile;
extern bool bond_gate_log_enabled;
extern float collective_pending_adjust;
extern float collective_warmup_adjust;
extern int collective_cycle_count;
extern Ant2State ant2_state;
extern float ant2_delay_factor;
extern float mirror_gain_tempo;
extern float astro_feedback_factor;
extern QELState *g_qel_state;
extern bool g_qel_enabled;
extern uint32_t g_qel_ctx_mask;
extern float g_qel_retro_gain;

static void pulse_delay_internal(void)
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
    if (astro_layer_enabled) {
        double astro_scale = (double)astro_feedback_factor;
        if (astro_scale < 0.85) {
            astro_scale = 0.85;
        } else if (astro_scale > 1.15) {
            astro_scale = 1.15;
        }
        if (astro_scale > 0.0) {
            tuned_delay /= astro_scale;
        }
    }

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
#ifdef _WIN32
    DWORD delay_ms = (DWORD)(tuned_delay * 1000.0);
    if (delay_ms == 0 && tuned_delay > 0.0) {
        delay_ms = 1;
    }
    Sleep(delay_ms);
#else
    nanosleep(&req, NULL);
#endif
}

void kernel_pulse_delay(void)
{
    pulse_delay_internal();
}

void kernel_inhale(void)
{
    const char *label = "inhale";
    soil_trace trace = soil_trace_make(ENERGY_INHALE, label, strlen(label));
    soil_write(&trace);

    static const char inhale_signal[] = "rise";
    resonant_msg inhale_msg = resonant_msg_make(SENSOR_INHALE, SENSOR_REFLECT, ENERGY_INHALE, inhale_signal, sizeof(inhale_signal) - 1);
    bus_emit(&inhale_msg);

    fputs("inhale\n", stdout);
}

void kernel_reflect(const kernel_options *opts)
{
    (void)opts;

    const char *label = "reflect";
    soil_trace trace = soil_trace_make(ENERGY_REFLECT, label, strlen(label));
    soil_write(&trace);

    static const char reflect_signal[] = "pause";
    resonant_msg reflect_msg = resonant_msg_make(SENSOR_REFLECT, SENSOR_EXHALE, ENERGY_REFLECT, reflect_signal, sizeof(reflect_signal) - 1);
    bus_emit(&reflect_msg);

    /* Обработка отражения */
    const CoherenceField *field = coherence_state();
    AwarenessState aw_state = awareness_state();
    float coherence_val = field ? field->coherence : 0.0f;
    
    if (aw_state.drift != 0.0f) {
        float drift_magnitude = fabsf(aw_state.drift);
        if (drift_magnitude > 0.1f) {
            coherence_val *= (1.0f - drift_magnitude * 0.1f);
        }
    }

    fputs("reflect\n", stdout);
}

/* Вспомогательная функция для построения последовательности exhale */
static size_t build_exhale_sequence_internal(const kernel_options *opts, const char **steps, size_t capacity)
{
    if (!steps || capacity == 0) {
        return 0;
    }

    size_t count = 0;
    bool strict = opts && opts->strict_order;
    bool include_ant2 = strict || (opts && opts->anticipation2_enabled);
    bool include_collective = strict || (opts && (opts->collective_enabled || opts->collective_trace));
    bool include_affinity = strict || (opts && opts->affinity_enabled);
    bool include_mirror = strict || (opts && opts->mirror_enabled);
    bool include_introspect = strict || (opts && opts->introspect_enabled);
    bool include_harmony = strict || include_introspect || (opts && (opts->harmony_enabled || opts->dream_enabled));
    bool include_astro = strict || (opts && opts->astro_enabled);
    bool include_kiss = strict || (opts && opts->kiss_enabled);
    bool include_gate = true;
    bool include_vse = strict || (opts && opts->vse_enabled);
    bool include_dream = opts && opts->dream_enabled;

    if (include_ant2 && count < capacity) {
        steps[count++] = "ant2";
    }
    if (count < capacity) {
        steps[count++] = "awareness";
    }
    if (include_collective && count < capacity) {
        steps[count++] = "collective";
    }
    if (include_affinity && count < capacity) {
        steps[count++] = "affinity";
    }
    if (include_mirror && count < capacity) {
        steps[count++] = "mirror";
    }
    if (include_introspect && count < capacity) {
        steps[count++] = "introspect";
    }
    if (include_harmony && count < capacity) {
        steps[count++] = "harmony";
    }
    if (include_astro && count < capacity) {
        steps[count++] = "astro";
    }
    if (include_kiss && count < capacity) {
        steps[count++] = "kiss";
    }
    if (include_gate && count < capacity) {
        steps[count++] = "gate";
    }
    if (include_vse && count < capacity) {
        steps[count++] = "vse";
    }
    if (include_dream && count < capacity) {
        steps[count++] = "dream";
    }

    return count;
}

void kernel_exhale(const kernel_options *opts)
{
    const char *label = "exhale";
    soil_trace trace = soil_trace_make(ENERGY_EXHALE, label, strlen(label));
    soil_write(&trace);

    static const char exhale_signal[] = "fall";
    resonant_msg exhale_msg = resonant_msg_make(SENSOR_EXHALE, SENSOR_INHALE, ENERGY_EXHALE, exhale_signal, sizeof(exhale_signal) - 1);
    bus_emit(&exhale_msg);

    /* Построение последовательности exhale */
    const char *sequence_steps[32];
    size_t step_count = build_exhale_sequence_internal(opts, sequence_steps, 32);

    for (size_t i = 0; i < step_count; ++i) {
        const char *step = sequence_steps[i];
        
        if (strcmp(step, "ant2") == 0 && opts->anticipation2_enabled) {
            ant2_step(&ant2_state);
        } else if (strcmp(step, "awareness") == 0) {
            awareness_pulse();
        } else if (strcmp(step, "collective") == 0 && opts->collective_enabled) {
            /* collective шаг обрабатывается в pulse_kernel */
        } else if (strcmp(step, "affinity") == 0 && opts->affinity_enabled) {
            /* affinity шаг */
        } else if (strcmp(step, "mirror") == 0 && opts->mirror_enabled) {
            mirror_pulse();
        } else if (strcmp(step, "introspect") == 0 && opts->introspect_enabled) {
            /* introspect шаг */
        } else if (strcmp(step, "harmony") == 0 && opts->harmony_enabled) {
            /* harmony шаг */
        } else if (strcmp(step, "astro") == 0 && opts->astro_enabled) {
            /* astro шаг */
        } else if (strcmp(step, "kiss") == 0 && opts->kiss_enabled) {
            /* kiss шаг */
        } else if (strcmp(step, "gate") == 0) {
            /* consent gate шаг */
        } else if (strcmp(step, "vse") == 0 && opts->vse_enabled) {
            vse_pulse();
        } else if (strcmp(step, "dream") == 0 && opts->dream_enabled) {
            /* dream шаг */
        }
    }

    fputs("exhale\n", stdout);
}
