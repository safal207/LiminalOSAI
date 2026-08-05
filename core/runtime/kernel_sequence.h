#ifndef LIMINAL_KERNEL_SEQUENCE_H
#define LIMINAL_KERNEL_SEQUENCE_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    KERNEL_STAGE_ANTICIPATION = 0,
    KERNEL_STAGE_AWARENESS,
    KERNEL_STAGE_COLLECTIVE,
    KERNEL_STAGE_AFFINITY,
    KERNEL_STAGE_MIRROR,
    KERNEL_STAGE_INTROSPECT,
    KERNEL_STAGE_HARMONY,
    KERNEL_STAGE_ASTRO,
    KERNEL_STAGE_KISS,
    KERNEL_STAGE_GATE,
    KERNEL_STAGE_VSE,
    KERNEL_STAGE_DREAM,
    KERNEL_STAGE_COUNT
} kernel_stage;

typedef struct {
    bool anticipation;
    bool collective;
    bool affinity;
    bool mirror;
    bool introspect;
    bool harmony;
    bool astro;
    bool kiss;
    bool vse;
    bool dream;
} kernel_sequence_options;

/* Awareness and gate are mandatory. Harmony is added for introspect or dream. */
size_t kernel_plan_sequence(const kernel_sequence_options *options,
                            kernel_stage *stages,
                            size_t capacity);

const char *kernel_stage_name(kernel_stage stage);
bool kernel_sequence_is_canonical(const kernel_stage *stages, size_t count);
void kernel_format_sequence(const kernel_stage *stages,
                            size_t count,
                            char *buffer,
                            size_t buffer_size);

#endif /* LIMINAL_KERNEL_SEQUENCE_H */
