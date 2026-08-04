#ifndef KERNEL_LOOP_H
#define KERNEL_LOOP_H

#include "pulse_kernel.h"

/* Фазы основного цикла */
void kernel_inhale(void);
void kernel_reflect(const kernel_options *opts);
void kernel_exhale(const kernel_options *opts);

/* Задержка между пульсами */
void kernel_pulse_delay(void);

#endif /* KERNEL_LOOP_H */
