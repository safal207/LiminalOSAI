#include "symbol.h"

#include "resonant.h"
#include "soil.h"

#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SYMBOL_TABLE_CAPACITY 256
#define SYMBOL_TRACE_WINDOW   6
#define SYMBOL_SENSOR_ID      7
#define SYMBOL_LINK_CAPACITY  64

#define SYMBOL_RESONANCE_STABLE_THRESHOLD 0.9f
#define SYMBOL_STABILITY_PULSES          3U

typedef struct {
    const char *key;
    uint32_t pattern[4];
    size_t length;
    float impulse;
} symbol_pattern;

static Symbol symbol_table[SYMBOL_TABLE_CAPACITY];
static size_t symbol_count = 0;

static Symbol *current_active[SYMBOL_TABLE_CAPACITY];
static size_t current_active_count = 0;

static uint8_t symbol_stability[SYMBOL_TABLE_CAPACITY];
static bool symbol_manifested[SYMBOL_TABLE_CAPACITY];

typedef struct {
    char from_key[32];
    char to_key[32];
    float weight;
} symbol_link_entry;

static symbol_link_entry link_buffer[SYMBOL_LINK_CAPACITY];
static size_t link_count = 0;
static size_t link_cursor = 0;

static float symbol_affinity_scale = 1.0f;

static const symbol_pattern pattern_table[] = {
    { "breath_cycle",    { 3U, 5U, 2U }, 3U, 1.5f },
    { "inhale_reflect",  { 3U, 5U },     2U, 1.0f },
    { "reflect_release", { 5U, 2U },     2U, 0.9f },
};

static bool symbol_is_active(const Symbol *symbol)
{
    for (size_t i = 0; i < current_active_count; ++i) {
        if (current_active[i] == symbol) {
            return true;
        }
    }
    return false;
}

static size_t symbol_index(const Symbol *symbol)
{
    if (!symbol) {
        return SYMBOL_TABLE_CAPACITY;
    }

    ptrdiff_t offset = symbol - symbol_table;
    if (offset < 0 || (size_t)offset >= SYMBOL_TABLE_CAPACITY) {
        return SYMBOL_TABLE_CAPACITY;
    }

    return (size_t)offset;
}

static bool symbol_is_manifested(size_t index)
{
    return index < SYMBOL_TABLE_CAPACITY && symbol_manifested[index];
}

static void symbol_reset_stability(size_t index)
{
    if (index >= SYMBOL_TABLE_CAPACITY) {
        return;
    }

    symbol_stability[index] = 0U;
    symbol_manifested[index] = false;
}

static bool symbol_record_activation(Symbol *symbol, float impulse)
{
    if (!symbol) {
        return false;
    }

    size_t index = symbol_index(symbol);
    if (index >= SYMBOL_TABLE_CAPACITY) {
        return false;
    }

    float impulse_scaled = impulse * symbol_affinity_scale;
    symbol->energy += impulse_scaled;
    if (symbol->energy > 12.0f) {
        symbol->energy = 12.0f;
    }

    symbol->resonance += impulse_scaled * 0.2f;
    if (symbol->resonance > 12.0f) {
        symbol->resonance = 12.0f;
    }

    bool reached_stability = false;
    if (symbol->resonance >= SYMBOL_RESONANCE_STABLE_THRESHOLD) {
        if (symbol_stability[index] < UINT8_MAX) {
            ++symbol_stability[index];
        }

        if (symbol_stability[index] >= SYMBOL_STABILITY_PULSES) {
            if (!symbol_manifested[index]) {
                reached_stability = true;
            }
            symbol_manifested[index] = true;
        }
    } else {
        symbol_reset_stability(index);
    }

    if (symbol_is_manifested(index) && !symbol_is_active(symbol) && current_active_count < SYMBOL_TABLE_CAPACITY) {
        current_active[current_active_count++] = symbol;
    }

    return reached_stability;
}

static bool match_pattern(const symbol_pattern *pattern, const soil_trace *traces, size_t trace_count)
{
    if (!pattern || !traces || trace_count < pattern->length) {
        return false;
    }

    size_t limit = trace_count - pattern->length;
    for (size_t start = 0; start <= limit; ++start) {
        bool matched = true;
        for (size_t i = 0; i < pattern->length; ++i) {
            if (traces[start + i].energy != pattern->pattern[i]) {
                matched = false;
                break;
            }
        }
        if (matched) {
            return true;
        }
    }

    return false;
}

static void write_semantic_echo(const Symbol *symbol)
{
    if (!symbol) {
        return;
    }

    char imprint[SOIL_TRACE_DATA_SIZE];
    int written = snprintf(imprint, sizeof(imprint), "sym:%s", symbol->key);
    if (written < 0) {
        written = 0;
    }

    if ((size_t)written > SOIL_TRACE_DATA_SIZE) {
        written = (int)SOIL_TRACE_DATA_SIZE;
    }

    uint32_t echo_energy = (uint32_t)(symbol->energy >= 1.0f ? symbol->energy : 1.0f);
    soil_trace echo = soil_trace_make(echo_energy, imprint, (size_t)written);
    soil_write(&echo);
}

static void broadcast_resonance_wave(void)
{
    if (current_active_count < 2) {
        return;
    }

    float resonance_sum = 0.0f;
    for (size_t i = 0; i < current_active_count; ++i) {
        resonance_sum += current_active[i]->resonance;
    }

    float average = resonance_sum / (float)current_active_count;
    if (average <= 0.05f) {
        return;
    }

    char payload[RESONANT_MSG_DATA_SIZE];
    int written = snprintf(payload, sizeof(payload), "wave:%.2f", average);
    if (written < 0) {
        written = 0;
    }

    if ((size_t)written > RESONANT_MSG_DATA_SIZE) {
        written = (int)RESONANT_MSG_DATA_SIZE;
    }

    uint32_t wave_energy = (uint32_t)(average * 10.0f);
    if (wave_energy == 0) {
        wave_energy = 1U;
    }

    resonant_msg wave = resonant_msg_make(SYMBOL_SENSOR_ID, RESONANT_BROADCAST_ID, wave_energy, payload, (size_t)written);
    bus_emit(&wave);
}

void symbol_register(const char *key, float resonance)
{
    if (!key || *key == '\0') {
        return;
    }

    Symbol *existing = symbol_find(key);
    if (existing) {
        existing->resonance = resonance;
        existing->energy = 0.0f;
        size_t index = symbol_index(existing);
        if (index < SYMBOL_TABLE_CAPACITY) {
            symbol_reset_stability(index);
        }
        return;
    }

    if (symbol_count >= SYMBOL_TABLE_CAPACITY) {
        return;
    }

    Symbol *slot = &symbol_table[symbol_count++];
    memset(slot, 0, sizeof(*slot));
    strncpy(slot->key, key, sizeof(slot->key) - 1);
    slot->key[sizeof(slot->key) - 1] = '\0';
    slot->resonance = resonance;
    slot->energy = 0.0f;

    size_t new_index = symbol_index(slot);
    symbol_reset_stability(new_index);
}

Symbol *symbol_find(const char *key)
{
    if (!key) {
        return NULL;
    }

    for (size_t i = 0; i < symbol_count; ++i) {
        if (strncmp(symbol_table[i].key, key, sizeof(symbol_table[i].key)) == 0) {
            return &symbol_table[i];
        }
    }

    return NULL;
}

void symbol_decay(void)
{
    const float resonance_decay = 0.92f;
    const float energy_decay = 0.80f;

    for (size_t i = 0; i < symbol_count; ++i) {
        symbol_table[i].resonance *= resonance_decay;
        symbol_table[i].energy *= energy_decay;

        if (symbol_table[i].resonance < 0.01f) {
            symbol_table[i].resonance = 0.0f;
        }

        if (symbol_table[i].energy < 0.01f) {
            symbol_table[i].energy = 0.0f;
        }

        if (symbol_table[i].resonance < SYMBOL_RESONANCE_STABLE_THRESHOLD * 0.5f) {
            symbol_reset_stability(i);
        }
    }
}

void symbol_create_link(const char *from_key, const char *to_key, float weight)
{
    if (!from_key || !to_key || *from_key == '\0' || *to_key == '\0') {
        return;
    }

    if (weight < 0.0f) {
        weight = 0.0f;
    }
    if (weight > 1.0f) {
        weight = 1.0f;
    }

    symbol_link_entry *entry = &link_buffer[link_cursor % SYMBOL_LINK_CAPACITY];
    strncpy(entry->from_key, from_key, sizeof(entry->from_key) - 1U);
    entry->from_key[sizeof(entry->from_key) - 1U] = '\0';
    strncpy(entry->to_key, to_key, sizeof(entry->to_key) - 1U);
    entry->to_key[sizeof(entry->to_key) - 1U] = '\0';
    entry->weight = weight;

    link_cursor = (link_cursor + 1U) % SYMBOL_LINK_CAPACITY;
    if (link_count < SYMBOL_LINK_CAPACITY) {
        ++link_count;
    }

    Symbol *from_symbol = symbol_find(from_key);
    if (!from_symbol) {
        symbol_register(from_key, 0.3f);
        from_symbol = symbol_find(from_key);
    }

    Symbol *to_symbol = symbol_find(to_key);
    if (!to_symbol) {
        symbol_register(to_key, 0.3f);
        to_symbol = symbol_find(to_key);
    }

    if (from_symbol) {
        from_symbol->resonance += weight * 0.5f;
        if (from_symbol->resonance > 12.0f) {
            from_symbol->resonance = 12.0f;
        }
    }

    if (to_symbol) {
        to_symbol->resonance += weight * 0.5f;
        if (to_symbol->resonance > 12.0f) {
            to_symbol->resonance = 12.0f;
        }
    }
}

void symbol_set_affinity_scale(float scale)
{
    if (!isfinite(scale)) {
        scale = 0.0f;
    }
    if (scale < 0.0f) {
        scale = 0.0f;
    } else if (scale > 1.0f) {
        scale = 1.0f;
    }
    symbol_affinity_scale = scale;
}

void symbol_scale_active(float gain)
{
    if (!isfinite(gain) || gain <= 0.0f) {
        return;
    }

    for (size_t i = 0; i < current_active_count; ++i) {
        Symbol *symbol = current_active[i];
        if (!symbol) {
            continue;
        }

        symbol->energy *= gain;
        if (symbol->energy > 12.0f) {
            symbol->energy = 12.0f;
        } else if (symbol->energy < 0.0f) {
            symbol->energy = 0.0f;
        }

        symbol->resonance *= gain;
        if (symbol->resonance > 12.0f) {
            symbol->resonance = 12.0f;
        } else if (symbol->resonance < 0.0f) {
            symbol->resonance = 0.0f;
        }
    }
}

void symbol_layer_init(void)
{
    memset(symbol_table, 0, sizeof(symbol_table));
    memset(current_active, 0, sizeof(current_active));
    symbol_count = 0;
    current_active_count = 0;
    memset(symbol_stability, 0, sizeof(symbol_stability));
    memset(symbol_manifested, 0, sizeof(symbol_manifested));
    memset(link_buffer, 0, sizeof(link_buffer));
    link_count = 0;
    link_cursor = 0;
    symbol_affinity_scale = 1.0f;

    for (size_t i = 0; i < sizeof(pattern_table) / sizeof(pattern_table[0]); ++i) {
        symbol_register(pattern_table[i].key, 0.4f);
    }
}

size_t symbol_layer_pulse(void)
{
    current_active_count = 0;
    memset(current_active, 0, sizeof(current_active));

    symbol_decay();

    soil_trace window[SYMBOL_TRACE_WINDOW];
    size_t trace_count = soil_recent(window, SYMBOL_TRACE_WINDOW);

    for (size_t i = 0; i < sizeof(pattern_table) / sizeof(pattern_table[0]); ++i) {
        const symbol_pattern *pattern = &pattern_table[i];
        if (!pattern->length) {
            continue;
        }

        if (match_pattern(pattern, window, trace_count)) {
            Symbol *symbol = symbol_find(pattern->key);
            if (symbol && symbol_record_activation(symbol, pattern->impulse)) {
                write_semantic_echo(symbol);
            }
        }
    }

    broadcast_resonance_wave();

    return current_active_count;
}

size_t symbol_layer_active(const Symbol **out_symbols, size_t max_count)
{
    if (!out_symbols || max_count == 0) {
        return 0;
    }

    size_t to_copy = current_active_count < max_count ? current_active_count : max_count;
    for (size_t i = 0; i < to_copy; ++i) {
        out_symbols[i] = current_active[i];
    }

    return to_copy;
}

void symbol_nudge_from_kiss(void)
{
    if (current_active_count == 0) {
        return;
    }

    const float energy_cap = 12.0f;
    const float energy_nudge = 0.18f;
    const float resonance_nudge = 0.12f;

    for (size_t i = 0; i < current_active_count; ++i) {
        Symbol *symbol = current_active[i];
        if (!symbol) {
            continue;
        }
        symbol->energy += energy_nudge;
        if (symbol->energy > energy_cap) {
            symbol->energy = energy_cap;
        }
        symbol->resonance += resonance_nudge;
        if (symbol->resonance > energy_cap) {
            symbol->resonance = energy_cap;
        }
    }
}
