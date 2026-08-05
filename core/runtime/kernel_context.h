#ifndef LIMINAL_KERNEL_CONTEXT_H
#define LIMINAL_KERNEL_CONTEXT_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    KERNEL_CONTEXT_NEW = 0,
    KERNEL_CONTEXT_VALIDATING,
    KERNEL_CONTEXT_READY,
    KERNEL_CONTEXT_REJECTED,
    KERNEL_CONTEXT_RUNNING,
    KERNEL_CONTEXT_FINISHED
} kernel_context_state;

typedef int (*kernel_context_runner)(int argc, char **argv);

typedef struct {
    int argc;
    char **argv;
    size_t next_argument;
    size_t validated_arguments;
    const char *current_argument;
    int exit_code;
    kernel_context_state state;
} kernel_context;

/* Initialize the launch boundary without invoking the production kernel. */
bool kernel_context_init(kernel_context *context, int argc, char **argv);

/* Iterate over process arguments beginning at argv[1]. */
bool kernel_context_next_argument(kernel_context *context,
                                  const char **argument_out);
bool kernel_context_accept_argument(kernel_context *context);
void kernel_context_reject(kernel_context *context, int exit_code);

bool kernel_context_is_ready(const kernel_context *context);
size_t kernel_context_validated_count(const kernel_context *context);
int kernel_context_exit_code(const kernel_context *context);

/* Invoke the production runner exactly once after successful validation. */
int kernel_context_run(kernel_context *context, kernel_context_runner runner);

#endif /* LIMINAL_KERNEL_CONTEXT_H */
