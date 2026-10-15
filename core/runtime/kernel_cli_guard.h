#ifndef LIMINAL_KERNEL_CLI_GUARD_H
#define LIMINAL_KERNEL_CLI_GUARD_H

#include <stdbool.h>

typedef enum {
    KERNEL_CLI_PULSE = 0,
    KERNEL_CLI_SUBSTRATE
} kernel_cli_profile;

/* Validate scalar and recognized composite numeric syntax before initialization.
 * Retain valid ranges, partial/duplicate keyed lists, aliases and runtime clamps.
 * Reject nonfinite/suffixed/overflowing components, malformed or truncated lists,
 * missing explicit range endpoints, uint32 context/index overflow and int seed
 * narrowing. Both profiles retain the case-insensitive --allow=now form. */
bool kernel_cli_validate_argument(const char *argument, kernel_cli_profile profile);
bool kernel_cli_validate_arguments(int argc, char *const argv[], kernel_cli_profile profile);

#endif /* LIMINAL_KERNEL_CLI_GUARD_H */
