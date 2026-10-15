#include "runtime_trace.h"

#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include "soil.h"
#include "runtime_values.h"

static size_t bounded_string_length(const uint8_t *data, size_t max_len)
{
    size_t len = 0;
    while (len < max_len && data[len] != '\0') {
        ++len;
    }
    return len;
}

void runtime_print_soil_traces(FILE *stream)
{
    soil_trace last[5];
    size_t count = soil_recent(last, 5);

    if (count == 0) {
        fputs("Memory Soil is quiet.\n", stream);
        return;
    }

    fputs("Memory Soil traces:\n", stream);
    for (size_t i = 0; i < count; ++i) {
        char data_text[SOIL_TRACE_DATA_SIZE + 1];
        memcpy(data_text, last[i].data, SOIL_TRACE_DATA_SIZE);
        data_text[SOIL_TRACE_DATA_SIZE] = '\0';
        size_t len = bounded_string_length((const uint8_t *)data_text, SOIL_TRACE_DATA_SIZE);
        data_text[len] = '\0';

        fprintf(stream, "  [%zu] t=%" PRIu64 " energy=%u data=\"%s\"\n", i, last[i].timestamp, last[i].energy, data_text);
    }
}

void substrate_trace_analysis(FILE *stream, const liminal_state *state,
                              bool enabled, bool empathic_enabled,
                              const EmpathicResponse *response)
{
    if (!enabled) {
        return;
    }

    float resonance = clamp_unit(state->resonance);
    float sync_quality = clamp_unit(state->sync_quality);
    float coherence = clamp_unit(0.6f * resonance + 0.4f * sync_quality);
    float anticipation_level = 0.5f;
    float micro_pattern = 0.5f;
    float prediction_trend = 0.5f;
    float dream_sync = clamp_unit(sync_quality);

    if (empathic_enabled && response != NULL) {
        anticipation_level = clamp_unit(response->anticipation_level);
        micro_pattern = clamp_unit(response->micro_pattern_signal);
        prediction_trend = clamp_unit(response->prediction_trend);
        float delay_scale = response->delay_scale;
        if (isfinite(delay_scale)) {
            dream_sync = clamp_unit(0.5f + (delay_scale - 1.0f) * 0.5f);
        }
    }

    fprintf(stream, "trace_event: { \"cycle\": %u, \"coherence\": %.4f, \"resonance\": %.4f, \"sync_quality\": %.4f, \"anticipation_level\": %.4f, \"micro_pattern\": %.4f, \"prediction_trend\": %.4f, \"dream_sync\": %.4f }\n",
           state->cycles,
           coherence,
           resonance,
           sync_quality,
           anticipation_level,
           micro_pattern,
           prediction_trend,
           dream_sync);
}

void substrate_trace_shutdown(FILE *stream, const liminal_state *state,
                              bool human_bridge, bool trace)
{
    if (human_bridge && state->human_affinity_active) {
        fprintf(stream, "[bridge] human affinity synchronized. breath=%.3f phase=%.2f\n",
               state->breath_rate,
               fmodf(state->breath_position + state->phase_offset, 1.0f));
    }
    if (trace) {
        fprintf(stream, "[shutdown] cycles=%u resonance=%.3f memory=%.3f vitality=%.3f\n",
               state->cycles,
               state->resonance,
               state->memory_trace,
               state->vitality);
    }

}
