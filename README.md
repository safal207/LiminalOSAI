# LiminalOSAI

LiminalOSAI — это экспериментальная система пульсирующего ядра, исследующая устойчивость через мягкие перерождения и адаптивные контуры осознанности.

## Phoenix Layer — Regenerative Core
Итерация #11 вводит Phoenix Layer, который превращает фатальные сбои в цикл обучения. Слой хранит «семена» состояния, фиксирует параметры распада и при перезапуске мягко мутирует коэффициенты управления для повышения устойчивости.

- Подробное описание архитектуры: [docs/phoenix_layer.md](docs/phoenix_layer.md)
- Манифест цикла возрождения: [docs/phoenix.yaml](docs/phoenix.yaml)

## Metabolic Flow Layer — Energetic Rhythm
Итерация #12 добавляет слой метаболического потока, связывающий дыхание, сон и восстановление в единый ритм. Ядро отслеживает баланс энергии, регулирует задержку пульса и мягко переходит в режимы восстановления и творчества.

- Активация: `--metabolic`
- Подробный след: `--metabolic-trace` (пишет `meta_echo` и обновляет `metabolic_trace.log`)
- Настройка порогов витальности: `--vitality-threshold=<rest>` или `--vitality-threshold=<rest>:<creative>`
- Отчёт по ритму: `python3 metabolic_report.py` или `make report-metabolic`

## Adaptive CLI Controls — Mirror & Order
Итерация #13 добавляет гибкие опции командной строки для управления мягкими зажимами зеркального слоя и порядка выдоха.

- Диапазон амплитуды зеркала: `--amp-min=<min>` и `--amp-max=<max>` (по умолчанию `0.5` и `1.2`).
- Диапазон темпа: `--tempo-min=<min>` и `--tempo-max=<max>` (по умолчанию `0.8` и `1.2`). Значения автоматически нормализуются и всегда остаются в допустимом диапазоне.
- Форсированный порядок выдоха: `--strict-order` поддерживает последовательность `ant2→awareness→collective→affinity→mirror` даже при частично отключённых слоях.
- Сухой прогон: `--dry-run` выводит текущую последовательность и активные зажимы без изменения состояния ядра — удобно для проверки конфигурации перед запуском.
- Dream Sync: флаг `--dreamsync` открывает сон-гармонию в диагностическом ядре, автоматически активируя связку introspect/harmony и синхронизатор (для `pulse_kernel` он также включает weave-синк), поэтому мечтательные метрики снова оказываются в отчётах без явного `--dream`.

## Long-run Substrate Diagnostics
Новая цель `make long-run-diagnostics` запускает `build/liminal_core --substrate --limit=60 --trace --symbols --reflect --awareness --anticipation --dreamsync --sync`, сохраняет полный вывод в `diagnostics/traces/liminal_core_long_run.log` и автоматически строит аналитический отчёт.

- Человеко-читаемый сводный файл: `diagnostics/traces/liminal_core_long_run.txt`
- Машинно-читаемая статистика: `diagnostics/traces/liminal_core_long_run.json`
- Отчёт формируется скриптом `diagnostics/liminal_trace_report.py` (требуется Python 3, стандартная библиотека)

Команда выводит ключевые метрики — дельты когерентности, карту прогноза (anticipation heatmap) и коэффициент предсказуемости — прямо в консоль и в соответствующие файлы, что упрощает анализ длительных прогонах.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
