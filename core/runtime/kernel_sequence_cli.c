#include "kernel_sequence_cli.h"

#include <stddef.h>
#include <string.h>

static bool has_prefix(const char *argument, const char *prefix)
{
    if (!argument || !prefix) {
        return false;
    }
    size_t length = strlen(prefix);
    return strncmp(argument, prefix, length) == 0;
}

bool kernel_sequence_options_from_argv(int argc,
                                       char *const argv[],
                                       kernel_sequence_options *options_out)
{
    if (!options_out || argc < 0 || (argc > 0 && !argv)) {
        return false;
    }

    kernel_sequence_options options = {0};
    for (int index = 1; index < argc; ++index) {
        const char *argument = argv[index];
        if (!argument) {
            return false;
        }

        if (strcmp(argument, "--strict-order") == 0) {
            options.strict_order = true;
        } else if (strcmp(argument, "--anticipation2") == 0 ||
                   strcmp(argument, "--ant2-trace") == 0 ||
                   has_prefix(argument, "--ant2-gain=")) {
            options.anticipation = true;
        } else if (strcmp(argument, "--collective") == 0 ||
                   strcmp(argument, "--collective-trace") == 0) {
            options.collective = true;
        } else if (strcmp(argument, "--affinity") == 0) {
            options.affinity = true;
        } else if (strcmp(argument, "--mirror") == 0) {
            options.mirror = true;
        } else if (strcmp(argument, "--introspect") == 0) {
            options.introspect = true;
        } else if (strcmp(argument, "--harmony") == 0) {
            options.harmony = true;
        } else if (strcmp(argument, "--astro") == 0 ||
                   strcmp(argument, "--astro-trace") == 0) {
            options.astro = true;
        } else if (strcmp(argument, "--kiss") == 0) {
            options.kiss = true;
        } else if (strcmp(argument, "--vse") == 0 ||
                   strcmp(argument, "--vse-trace") == 0 ||
                   has_prefix(argument, "--vse-temp=") ||
                   has_prefix(argument, "--vse-intent=") ||
                   has_prefix(argument, "--vse-importance=") ||
                   has_prefix(argument, "--vse-allow=") ||
                   has_prefix(argument, "--vse-lambda-p=") ||
                   has_prefix(argument, "--vse-lambda-x=") ||
                   has_prefix(argument, "--allow-hold=") ||
                   has_prefix(argument, "--allow=")) {
            options.vse = true;
        } else if (strcmp(argument, "--dream") == 0 ||
                   strcmp(argument, "--dreamsync") == 0) {
            options.dream = true;
        }
    }

    *options_out = options;
    return true;
}
