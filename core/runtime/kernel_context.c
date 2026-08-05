#include "kernel_context.h"

static int normalized_failure_code(int exit_code)
{
    return exit_code == 0 ? 2 : exit_code;
}

bool kernel_context_init(kernel_context *context, int argc, char **argv)
{
    if (!context) {
        return false;
    }

    context->argc = argc;
    context->argv = argv;
    context->next_argument = 1U;
    context->validated_arguments = 0U;
    context->current_argument = NULL;
    context->sequence_count = 0U;
    context->sequence_planned = false;
    context->exit_code = 2;
    context->state = KERNEL_CONTEXT_NEW;

    if (argc < 0 || (argc > 0 && !argv)) {
        context->state = KERNEL_CONTEXT_REJECTED;
        return false;
    }

    context->state = KERNEL_CONTEXT_VALIDATING;
    return true;
}

bool kernel_context_next_argument(kernel_context *context,
                                  const char **argument_out)
{
    if (!context || !argument_out ||
        context->state != KERNEL_CONTEXT_VALIDATING ||
        context->current_argument) {
        return false;
    }

    if (context->next_argument >= (size_t)context->argc) {
        context->state = KERNEL_CONTEXT_READY;
        *argument_out = NULL;
        return false;
    }

    const char *argument = context->argv[context->next_argument];
    if (!argument) {
        context->state = KERNEL_CONTEXT_REJECTED;
        context->exit_code = 2;
        *argument_out = NULL;
        return false;
    }

    context->current_argument = argument;
    *argument_out = argument;
    return true;
}

bool kernel_context_accept_argument(kernel_context *context)
{
    if (!context || context->state != KERNEL_CONTEXT_VALIDATING ||
        !context->current_argument) {
        return false;
    }

    ++context->validated_arguments;
    ++context->next_argument;
    context->current_argument = NULL;

    if (context->next_argument >= (size_t)context->argc) {
        context->state = KERNEL_CONTEXT_READY;
    }

    return true;
}

void kernel_context_reject(kernel_context *context, int exit_code)
{
    if (!context || context->state == KERNEL_CONTEXT_RUNNING ||
        context->state == KERNEL_CONTEXT_FINISHED) {
        return;
    }

    context->current_argument = NULL;
    context->sequence_count = 0U;
    context->sequence_planned = false;
    context->exit_code = normalized_failure_code(exit_code);
    context->state = KERNEL_CONTEXT_REJECTED;
}

bool kernel_context_is_ready(const kernel_context *context)
{
    return context && context->state == KERNEL_CONTEXT_READY;
}

size_t kernel_context_validated_count(const kernel_context *context)
{
    return context ? context->validated_arguments : 0U;
}

int kernel_context_exit_code(const kernel_context *context)
{
    return context ? context->exit_code : 2;
}

bool kernel_context_plan_sequence(kernel_context *context,
                                  const kernel_sequence_options *options)
{
    if (!context || context->state != KERNEL_CONTEXT_READY ||
        context->sequence_planned) {
        return false;
    }

    size_t count = kernel_plan_sequence(options,
                                        context->sequence,
                                        KERNEL_STAGE_COUNT);
    bool valid = count >= 2U &&
                 kernel_sequence_is_canonical(context->sequence, count) &&
                 kernel_sequence_contains(context->sequence,
                                          count,
                                          KERNEL_STAGE_AWARENESS) &&
                 kernel_sequence_contains(context->sequence,
                                          count,
                                          KERNEL_STAGE_GATE);
    if (!valid) {
        kernel_context_reject(context, 2);
        return false;
    }

    context->sequence_count = count;
    context->sequence_planned = true;
    return true;
}

const kernel_stage *kernel_context_sequence(const kernel_context *context,
                                            size_t *count_out)
{
    if (count_out) {
        *count_out = context && context->sequence_planned
                         ? context->sequence_count
                         : 0U;
    }
    return context && context->sequence_planned ? context->sequence : NULL;
}

int kernel_context_run(kernel_context *context, kernel_context_runner runner)
{
    if (!context || !runner) {
        return 2;
    }

    if (context->state != KERNEL_CONTEXT_READY ||
        !context->sequence_planned) {
        return context->state == KERNEL_CONTEXT_REJECTED
                   ? context->exit_code
                   : 2;
    }

    context->state = KERNEL_CONTEXT_RUNNING;
    context->exit_code = runner(context->argc, context->argv);
    context->state = KERNEL_CONTEXT_FINISHED;
    return context->exit_code;
}
