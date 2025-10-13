#ifndef LIMINAL_INCLUDE_DREAM_BALANCE_H
#define LIMINAL_INCLUDE_DREAM_BALANCE_H

#include "council.h"
#include "dream.h"

#ifdef __cplusplus
extern "C" {
#endif

// unified merge by Codex
typedef struct {
    float balance_strength;
    float coherence_bias;
    float anticipation_sync;
} DreamAlignmentBalance;

DreamAlignmentBalance dream_alignment_balance(const InnerCouncil *council,
                                              const DreamState *dream,
                                              float anticipation_field,
                                              float anticipation_level,
                                              float anticipation_trend);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_INCLUDE_DREAM_BALANCE_H */
