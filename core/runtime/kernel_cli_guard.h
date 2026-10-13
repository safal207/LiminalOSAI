#ifndef LIMINAL_KERNEL_CLI_GUARD_H
#define LIMINAL_KERNEL_CLI_GUARD_H

#include <stdbool.h>

typedef enum {
    KERNEL_CLI_PULSE = 0,
    KERNEL_CLI_SUBSTRATE
} kernel_cli_profile;

/* Validate numeric syntax before the runtime applies its clamping/defaults. */
bool kernel_cli_validate_argument(const char *argument, kernel_cli_profile profile);
bool kernel_cli_validate_arguments(int argc, char *const argv[], kernel_cli_profile profile);

#endif /* LIMINAL_KERNEL_CLI_GUARD_H */
