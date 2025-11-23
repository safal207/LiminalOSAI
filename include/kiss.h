#ifndef LIMINAL_KISS_H
#define LIMINAL_KISS_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RES_KISS_BROADCAST "kiss"
#define RES_KISS_SOURCE_ID 29

void kiss_init(void);
void kiss_set_thresholds(float trust, float presence, float harmony);
void kiss_set_warmup(uint8_t cycles);
void kiss_set_refractory(uint8_t cycles);
void kiss_set_alpha(float alpha);
bool kiss_update(float trust, float presence, float harmony, float awareness_scale);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_KISS_H */
