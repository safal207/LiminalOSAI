#ifndef LIMINAL_KERNEL_SEQUENCE_CLI_H
#define LIMINAL_KERNEL_SEQUENCE_CLI_H

#include <stdbool.h>

#include "kernel_sequence.h"

/*
 * Extract only stage-enablement intent from process arguments. Numeric values
 * and all other semantics remain owned by the production kernel parser.
 */
bool kernel_sequence_options_from_argv(int argc,
                                       char *const argv[],
                                       kernel_sequence_options *options_out);

#endif /* LIMINAL_KERNEL_SEQUENCE_CLI_H */
