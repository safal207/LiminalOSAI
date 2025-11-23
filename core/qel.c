#include "qel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

typedef struct {
  qel_obs_t o;
  float adj_infl;  // скоррект. влияние после ретро-правки
  bool revised;
} qel_slot_t;

struct qel_state {
  FILE* log_raw;     // logs/qel_raw.jsonl
  FILE* log_rev;     // logs/qel_rev.jsonl
  qel_slot_t* ring;
  uint32_t cap, head, size;
};

static void write_obs_json(FILE* f, const qel_obs_t* o, float adj, bool revised) {
  if (!f || !o) {
    return;
  }
  fprintf(f,
    "{\"t\":%.3f,\"amp\":%.4f,\"tempo\":%.4f,\"consent\":%.4f,"
    "\"influence\":%.4f,\"harmony\":%.4f,\"ctx\":%u,"
    "\"adj_infl\":%.4f,\"revised\":%s}\n",
    o->t, o->amp, o->tempo, o->consent, o->influence, o->harmony,
    o->ctx, adj, revised ? "true":"false");
  fflush(f);
}

qel_state* qel_init(const char* dir, uint32_t cap) {
  if (!dir) {
    return NULL;
  }
  qel_state* s = calloc(1, sizeof(*s));
  if (!s) {
    return NULL;
  }
  s->cap = cap ? cap : 2048;
  s->ring = calloc(s->cap, sizeof(qel_slot_t));
  if (!s->ring) {
    free(s);
    return NULL;
  }

  char p1[256], p2[256];
  snprintf(p1, sizeof(p1), "%s/qel_raw.jsonl",  dir);
  snprintf(p2, sizeof(p2), "%s/qel_rev.jsonl",  dir);
  s->log_raw = fopen(p1, "a+");
  s->log_rev = fopen(p2, "a+");
  if (!s->log_raw || !s->log_rev) {
    if (s->log_raw) {
      fclose(s->log_raw);
    }
    if (s->log_rev) {
      fclose(s->log_rev);
    }
    free(s->ring);
    free(s);
    return NULL;
  }
  return s;
}

void qel_free(qel_state* s) {
  if (!s) return;
  if (s->log_raw) fclose(s->log_raw);
  if (s->log_rev) fclose(s->log_rev);
  free(s->ring);
  free(s);
}

void qel_mark_observation(qel_state* s, const qel_obs_t* o) {
  if (!s || !o) return;
  qel_slot_t* slot = &s->ring[s->head % s->cap];
  slot->o = *o;
  slot->adj_infl = o->influence; // пока «как наблюдали»
  slot->revised = false;
  s->head++; if (s->size < s->cap) s->size++;
  write_obs_json(s->log_raw, o, slot->adj_infl, false);
}

// простая «ретро-волна» — эксп. затухание по времени и маске
void qel_apply_retro(qel_state* s, const qel_retro_t* r) {
  if (!s || !r) return;
  for (uint32_t i = 0; i < s->size; ++i) {
    qel_slot_t* slot = &s->ring[(s->head - 1 - i + s->cap) % s->cap];
    if ((slot->o.ctx & r->ctx_mask) == 0) continue;

    double dt = fabs(r->t_new - slot->o.t);
    // чем ближе по времени и выше согласие — тем сильнее переписываем
    float w_time = expf((float)(-dt * 0.35f));
    float delta  = (slot->o.consent * r->retro_gain) * w_time;

    // двунаправленная правка: снижаем «избыточную важность»
    slot->adj_infl = fmaxf(0.f, fminf(1.f, slot->o.influence * (1.f - delta) + slot->o.harmony * delta));
    slot->revised = true;
  }
}

void qel_commit_revision(qel_state* s) {
  if (!s) return;
  for (uint32_t i = 0; i < s->size; ++i) {
    qel_slot_t* slot = &s->ring[(s->head - s->size + i + s->cap) % s->cap];
    if (slot->revised) write_obs_json(s->log_rev, &slot->o, slot->adj_infl, true);
  }
}

// быстрый гейт для онлайна
float qel_influence(qel_state* s, float raw_infl, uint32_t ctx) {
  if (!s || s->size == 0) return raw_infl;
  // берём последний пересчитанный слепок в том же контексте
  for (uint32_t i = 0; i < s->size; ++i) {
    qel_slot_t* slot = &s->ring[(s->head - 1 - i + s->cap) % s->cap];
    if (slot->revised && (slot->o.ctx & ctx)) {
      // мягко смешиваем (как «интерференция»)
      return 0.5f * raw_infl + 0.5f * slot->adj_infl;
    }
  }
  return raw_infl;
}
