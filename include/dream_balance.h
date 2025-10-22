#ifndef LIMINAL_DREAM_BALANCE_H
#define LIMINAL_DREAM_BALANCE_H

struct InnerCouncil;
struct DreamState;

#ifdef __cplusplus
extern "C" {
#endif

// unified merge by Codex
typedef struct {
    float balance_strength;
    float coherence_bias;
    float anticipation_sync;
} DreamAlignmentBalance;

DreamAlignmentBalance dream_alignment_balance(const struct InnerCouncil *council,
                                              const struct DreamState *dream,
                                              float anticipation_field,
                                              float anticipation_level,
                                              float anticipation_trend);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_DREAM_BALANCE_H */
