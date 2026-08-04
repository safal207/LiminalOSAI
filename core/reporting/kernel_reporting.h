#ifndef KERNEL_REPORTING_H
#define KERNEL_REPORTING_H

#include "pulse_kernel.h"

/* Функции финализации и вывода отчётов */
void kernel_print_traces(void);
void kernel_dump_reflections(int count);
void kernel_finalize_subsystems(const kernel_options *opts);

#endif /* KERNEL_REPORTING_H */
