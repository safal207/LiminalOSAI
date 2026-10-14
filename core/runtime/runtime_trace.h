#ifndef LIMINAL_RUNTIME_TRACE_H
#define LIMINAL_RUNTIME_TRACE_H

#include <stdbool.h>
#include <stdio.h>

#include "empathic.h"
#include "substrate_state.h"

/* Formatting consumes read-only snapshots and writes to the supplied stream.
 * Callers retain ownership of state and output streams. */
void runtime_print_soil_traces(FILE *stream);
void substrate_trace_analysis(FILE *stream, const liminal_state *state,
                              bool enabled, bool empathic_enabled,
                              const EmpathicResponse *response);
void substrate_trace_shutdown(FILE *stream, const liminal_state *state,
                              bool human_bridge, bool trace);

#endif /* LIMINAL_RUNTIME_TRACE_H */
