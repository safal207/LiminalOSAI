#include "kernel_sequence.h"

#include <stdio.h>
#include <string.h>

static bool append_stage(kernel_stage stage,
                         kernel_stage *stages,
                         size_t capacity,
                         size_t *count)
{
    if (!stages || !count || *count >= capacity) {
        return false;
    }
    stages[(*count)++] = stage;
    return true;
}

size_t kernel_plan_sequence(const kernel_sequence_options *options,
                            kernel_stage *stages,
                            size_t capacity)
{
    if (!stages || capacity == 0) {
        return 0;
    }

    kernel_sequence_options disabled = {0};
    const kernel_sequence_options *opts = options ? options : &disabled;
    const bool strict = opts->strict_order;
    size_t count = 0;

    if (strict || opts->anticipation) {
        append_stage(KERNEL_STAGE_ANTICIPATION, stages, capacity, &count);
    }
    append_stage(KERNEL_STAGE_AWARENESS, stages, capacity, &count);
    if (strict || opts->collective) {
        append_stage(KERNEL_STAGE_COLLECTIVE, stages, capacity, &count);
    }
    if (strict || opts->affinity) {
        append_stage(KERNEL_STAGE_AFFINITY, stages, capacity, &count);
    }
    if (strict || opts->mirror) {
        append_stage(KERNEL_STAGE_MIRROR, stages, capacity, &count);
    }
    if (strict || opts->introspect) {
        append_stage(KERNEL_STAGE_INTROSPECT, stages, capacity, &count);
    }
    if (strict || opts->harmony || opts->introspect || opts->dream) {
        append_stage(KERNEL_STAGE_HARMONY, stages, capacity, &count);
    }
    if (strict || opts->astro) {
        append_stage(KERNEL_STAGE_ASTRO, stages, capacity, &count);
    }
    if (strict || opts->kiss) {
        append_stage(KERNEL_STAGE_KISS, stages, capacity, &count);
    }
    append_stage(KERNEL_STAGE_GATE, stages, capacity, &count);
    if (strict || opts->vse) {
        append_stage(KERNEL_STAGE_VSE, stages, capacity, &count);
    }
    if (opts->dream) {
        append_stage(KERNEL_STAGE_DREAM, stages, capacity, &count);
    }

    return count;
}

const char *kernel_stage_name(kernel_stage stage)
{
    static const char *const names[KERNEL_STAGE_COUNT] = {
        "anticipation",
        "awareness",
        "collective",
        "affinity",
        "mirror",
        "introspect",
        "harmony",
        "astro",
        "kiss",
        "gate",
        "vse",
        "dream"
    };

    if (stage < 0 || stage >= KERNEL_STAGE_COUNT) {
        return "unknown";
    }
    return names[stage];
}

bool kernel_sequence_is_canonical(const kernel_stage *stages, size_t count)
{
    if (!stages && count != 0) {
        return false;
    }

    int previous = -1;
    for (size_t index = 0; index < count; ++index) {
        int current = (int)stages[index];
        if (current < 0 || current >= KERNEL_STAGE_COUNT || current <= previous) {
            return false;
        }
        previous = current;
    }
    return true;
}

bool kernel_sequence_contains(const kernel_stage *stages,
                              size_t count,
                              kernel_stage stage)
{
    if (!stages || stage < 0 || stage >= KERNEL_STAGE_COUNT) {
        return false;
    }

    for (size_t index = 0; index < count; ++index) {
        if (stages[index] == stage) {
            return true;
        }
    }
    return false;
}

void kernel_format_sequence(const kernel_stage *stages,
                            size_t count,
                            char *buffer,
                            size_t buffer_size)
{
    if (!buffer || buffer_size == 0) {
        return;
    }
    buffer[0] = '\0';
    if (!stages) {
        return;
    }

    size_t written = 0;
    for (size_t index = 0; index < count; ++index) {
        const char *separator = index == 0 ? "" : " -> ";
        int result = snprintf(buffer + written,
                              buffer_size - written,
                              "%s%s",
                              separator,
                              kernel_stage_name(stages[index]));
        if (result < 0) {
            buffer[written] = '\0';
            return;
        }
        if ((size_t)result >= buffer_size - written) {
            buffer[buffer_size - 1] = '\0';
            return;
        }
        written += (size_t)result;
    }
}
