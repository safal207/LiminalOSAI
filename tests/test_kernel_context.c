#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "kernel_context.h"

static bool runner_called = false;
static int observed_argc = -1;
static char **observed_argv = NULL;

static int recording_runner(int argc, char **argv)
{
    runner_called = true;
    observed_argc = argc;
    observed_argv = argv;
    return 17;
}

static void reset_runner(void)
{
    runner_called = false;
    observed_argc = -1;
    observed_argv = NULL;
}

static void test_invalid_process_arguments(void)
{
    kernel_context context;

    assert(!kernel_context_init(&context, -1, NULL));
    assert(context.state == KERNEL_CONTEXT_REJECTED);
    assert(kernel_context_exit_code(&context) == 2);

    assert(!kernel_context_init(&context, 1, NULL));
    assert(context.state == KERNEL_CONTEXT_REJECTED);
}

static void test_argument_iteration_and_readiness(void)
{
    char *argv[] = {"pulse_kernel", "--trace", "--limit=2"};
    kernel_context context;
    const char *argument = NULL;

    assert(kernel_context_init(&context, 3, argv));
    assert(kernel_context_next_argument(&context, &argument));
    assert(strcmp(argument, "--trace") == 0);
    assert(kernel_context_accept_argument(&context));

    assert(kernel_context_next_argument(&context, &argument));
    assert(strcmp(argument, "--limit=2") == 0);
    assert(kernel_context_accept_argument(&context));

    assert(kernel_context_is_ready(&context));
    assert(kernel_context_validated_count(&context) == 2U);
    assert(!kernel_context_next_argument(&context, &argument));
}

static void test_rejection_blocks_runner(void)
{
    char *argv[] = {"pulse_kernel", "--bad"};
    kernel_context context;
    const char *argument = NULL;

    reset_runner();
    assert(kernel_context_init(&context, 2, argv));
    assert(kernel_context_next_argument(&context, &argument));
    kernel_context_reject(&context, 64);

    assert(context.state == KERNEL_CONTEXT_REJECTED);
    assert(kernel_context_run(&context, recording_runner) == 64);
    assert(!runner_called);
}

static void test_runner_receives_original_process_arguments(void)
{
    char *argv[] = {"pulse_kernel"};
    kernel_context context;
    const char *argument = NULL;

    reset_runner();
    assert(kernel_context_init(&context, 1, argv));
    assert(!kernel_context_next_argument(&context, &argument));
    assert(kernel_context_is_ready(&context));

    assert(kernel_context_run(&context, recording_runner) == 17);
    assert(runner_called);
    assert(observed_argc == 1);
    assert(observed_argv == argv);
    assert(context.state == KERNEL_CONTEXT_FINISHED);
    assert(kernel_context_exit_code(&context) == 17);

    assert(kernel_context_run(&context, recording_runner) == 2);
}

static void test_null_argument_is_rejected(void)
{
    char *argv[] = {"pulse_kernel", NULL};
    kernel_context context;
    const char *argument = NULL;

    assert(kernel_context_init(&context, 2, argv));
    assert(!kernel_context_next_argument(&context, &argument));
    assert(context.state == KERNEL_CONTEXT_REJECTED);
    assert(kernel_context_exit_code(&context) == 2);
}

int main(void)
{
    test_invalid_process_arguments();
    test_argument_iteration_and_readiness();
    test_rejection_blocks_runner();
    test_runner_receives_original_process_arguments();
    test_null_argument_is_rejected();
    puts("kernel context tests: PASS");
    return 0;
}
