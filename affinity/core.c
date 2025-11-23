#include "affinity.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#ifndef BOND_TRACE_PATH
#define BOND_TRACE_PATH "logs/bond_trace.log"
#endif

static bool bond_trace_enabled = false;

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

void affinity_default(Affinity *aff)
{
    if (!aff) {
        return;
    }
    aff->care = 0.75f;
    aff->respect = 0.85f;
    aff->presence = 0.70f;
}

void affinity_configure(Affinity *aff, float care, float respect, float presence)
{
    if (!aff) {
        return;
    }
    aff->care = clamp_unit(care);
    aff->respect = clamp_unit(respect);
    aff->presence = clamp_unit(presence);
}

float affinity_strength(const Affinity *a)
{
    if (!a) {
        return 0.0f;
    }
    float care = clamp_unit(a->care);
    float presence = clamp_unit(a->presence);
    float respect = clamp_unit(a->respect);
    float strength = 0.5f * care + 0.3f * presence + 0.2f * respect;
    if (strength < 0.0f) {
        strength = 0.0f;
    } else if (strength > 1.0f) {
        strength = 1.0f;
    }
    return strength;
}

void bond_gate_reset(BondGate *gate)
{
    if (!gate) {
        return;
    }
    gate->consent = 0.0f;
    gate->safety = 0.0f;
    gate->bond_coh = 0.0f;
    gate->influence = 0.0f;
}

void bond_gate_update(BondGate *gate, const Affinity *aff, float consent, float field_coh)
{
    if (!gate) {
        return;
    }

    float consent_clamped = clamp_unit(consent);
    float coh_clamped = clamp_unit(field_coh);

    gate->consent = consent_clamped;
    gate->bond_coh = coh_clamped;

    float respect = aff ? clamp_unit(aff->respect) : 0.0f;
    gate->safety = fminf(respect, coh_clamped);

    float influence = 0.0f;
    if (aff) {
        influence = affinity_strength(aff) * gate->safety * gate->consent;
    }

    if (respect < 0.5f || consent_clamped < 0.3f) {
        influence = 0.0f;
    }

    if (!isfinite(influence) || influence < 0.0f) {
        influence = 0.0f;
    } else if (influence > 1.0f) {
        influence = 1.0f;
    }

    gate->influence = influence;
}

float bond_gate_apply(float base_adjust, const BondGate *gate)
{
    if (!gate) {
        return 0.0f;
    }
    float influence = clamp_unit(gate->influence);
    float adj = base_adjust * influence;
    const float limit = 0.06f;
    if (adj > limit) {
        adj = limit;
    } else if (adj < -limit) {
        adj = -limit;
    }
    return adj;
}

bool bond_gate_log_enabled(void)
{
    return bond_trace_enabled;
}

void bond_gate_set_log_enabled(bool enabled)
{
    bond_trace_enabled = enabled;
}

void bond_gate_trace(const Affinity *aff, const BondGate *gate, float adj)
{
    if (!bond_trace_enabled || !gate) {
        return;
    }

    float care = aff ? clamp_unit(aff->care) : 0.0f;
    float respect = aff ? clamp_unit(aff->respect) : 0.0f;
    float presence = aff ? clamp_unit(aff->presence) : 0.0f;
    float consent = clamp_unit(gate->consent);
    float bond_coh = clamp_unit(gate->bond_coh);
    float influence = clamp_unit(gate->influence);

    FILE *fp = fopen(BOND_TRACE_PATH, "a");
    if (!fp) {
        return;
    }

    fprintf(fp,
            "{\"care\":%.2f,\"respect\":%.2f,\"presence\":%.2f,\"consent\":%.2f,\"bond_coh\":%.2f,\"influence\":%.2f,\"adj\":%.3f}\n",
            care,
            respect,
            presence,
            consent,
            bond_coh,
            influence,
            adj);

    fclose(fp);
}
