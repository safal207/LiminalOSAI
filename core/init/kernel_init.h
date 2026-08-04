#ifndef KERNEL_INIT_H
#define KERNEL_INIT_H

#include <stdbool.h>
#include <stdint.h>
#include "pulse_kernel.h"

/* Парсинг аргументов командной строки */
kernel_options kernel_parse_options(int argc, char **argv);

/* Инициализация всех подсистем ядра */
void kernel_init_subsystems(const kernel_options *opts);

/* Сброс состояния ядра к значениям по умолчанию */
void kernel_reset_state(void);

#endif /* KERNEL_INIT_H */
