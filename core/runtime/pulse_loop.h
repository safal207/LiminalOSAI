#ifndef LIMINAL_PULSE_LOOP_H
#define LIMINAL_PULSE_LOOP_H

#include <stdint.h>

typedef void (*PulseStage)(const void *context);
typedef void (*PulseCompleted)(const void *context, uint64_t pulse_number);

/* The orchestrator supplies live stage implementations once; the loop owns
 * only its counter. A zero limit retains the existing unlimited-run contract.
 * Required callbacks and the descriptor must be non-NULL. */
typedef struct {
    const void *context;
    uint64_t limit;
    PulseStage inhale;
    PulseStage reflect;
    PulseStage exhale;
    PulseStage delay;
    PulseCompleted completed;
} PulseLoop;

uint64_t pulse_loop_run(const PulseLoop *loop);

#endif /* LIMINAL_PULSE_LOOP_H */
