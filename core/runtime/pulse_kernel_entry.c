#include "kernel_context.h"
#include "kernel_cli_guard.h"
#include "kernel_sequence_cli.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int pulse_kernel_core_main(int argc, char **argv);

int main(int argc, char **argv)
{
    kernel_context context;
    if (!kernel_context_init(&context, argc, argv)) {
        fputs("pulse_kernel: invalid process arguments\n", stderr);
        return kernel_context_exit_code(&context);
    }

    const char *argument = NULL;
    while (kernel_context_next_argument(&context, &argument)) {
        if (!kernel_cli_validate_argument(argument, KERNEL_CLI_PULSE)) {
            kernel_context_reject(&context, 2);
            return kernel_context_exit_code(&context);
        }

        if (!kernel_context_accept_argument(&context)) {
            kernel_context_reject(&context, 2);
            return kernel_context_exit_code(&context);
        }
    }

    if (!kernel_context_is_ready(&context)) {
        return kernel_context_exit_code(&context);
    }

    kernel_sequence_options sequence_options;
    if (!kernel_sequence_options_from_argv(argc, argv, &sequence_options) ||
        !kernel_context_plan_sequence(&context, &sequence_options)) {
        kernel_context_reject(&context, 2);
        return kernel_context_exit_code(&context);
    }

    return kernel_context_run(&context, pulse_kernel_core_main);
}
