#ifndef LIMINAL_INCLUDE_SYMBOL_H
#define LIMINAL_INCLUDE_SYMBOL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char key[32];
    float resonance;
    float energy;
} Symbol;

void symbol_layer_init(void);
size_t symbol_layer_pulse(void);
size_t symbol_layer_active(const Symbol **out_symbols, size_t max_count);
void symbol_set_affinity_scale(float scale);

void symbol_register(const char *key, float resonance);
Symbol *symbol_find(const char *key);
void symbol_decay(void);
void symbol_create_link(const char *from_key, const char *to_key, float weight);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_INCLUDE_SYMBOL_H */
