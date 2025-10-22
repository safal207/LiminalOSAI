#ifndef LIMINAL_AFFINITY_H
#define LIMINAL_AFFINITY_H

#include <stdbool.h>

typedef struct {
    float care;      // готовность поддерживать (0..1)
    float respect;   // самоконтроль/ненасилие (0..1)
    float presence;  // устойчивое внимание (0..1)
} Affinity; // "крылья любви"

typedef struct {
    float consent;   // явное/неявное согласие канала (0..1)
    float safety;    // оценка безопасного влияния (0..1)
    float bond_coh;  // связность пары/поля (0..1)
    float influence; // итоговый коэффициент влияния (0..1)
} BondGate;

void affinity_default(Affinity *aff);
void affinity_configure(Affinity *aff, float care, float respect, float presence);
float affinity_strength(const Affinity *a);

void bond_gate_reset(BondGate *gate);
void bond_gate_update(BondGate *gate, const Affinity *aff, float consent, float field_coh);
float bond_gate_apply(float base_adjust, const BondGate *gate);

bool bond_gate_log_enabled(void);
void bond_gate_set_log_enabled(bool enabled);
void bond_gate_trace(const Affinity *aff, const BondGate *gate, float adj);

#endif /* LIMINAL_AFFINITY_H */
