#ifndef LIMINAL_QEL_H
#define LIMINAL_QEL_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
  double t;           // timestamp (сек)
  float amp, tempo, consent, influence, harmony;
  uint32_t ctx;       // контекст/маска
} qel_obs_t;

typedef struct {
  double t_new;       // время уточнения
  float retro_gain;   // 0..1 — сколько «стираем/переписываем»
  uint32_t ctx_mask;  // какие контексты трогаем
} qel_retro_t;

typedef struct qel_state qel_state;

qel_state* qel_init(const char* log_path, uint32_t cap);
void       qel_free(qel_state* s);

// наблюдение (пишем «как было замечено»)
void qel_mark_observation(qel_state* s, const qel_obs_t* o);

// «ластик»: пришло уточнение, пересчитай прошлые веса
void qel_apply_retro(qel_state* s, const qel_retro_t* r);

// сохранить «после уточнения» в отдельный JSONL
void qel_commit_revision(qel_state* s);

// быстрый гейт влияния (возвращает скорректированное значение 0..1)
float qel_influence(qel_state* s, float raw_infl, uint32_t ctx);

#endif
