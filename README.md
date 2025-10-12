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

## Long-run Substrate Diagnostics
Новая цель `make long-run-diagnostics` запускает `build/liminal_core --substrate --limit=60 --trace --symbols --reflect --awareness --anticipation --dreamsync --sync`, сохраняет полный вывод в `diagnostics/traces/liminal_core_long_run.log` и автоматически строит аналитический отчёт.

- Человеко-читаемый сводный файл: `diagnostics/traces/liminal_core_long_run.txt`
- Машинно-читаемая статистика: `diagnostics/traces/liminal_core_long_run.json`
- Отчёт формируется скриптом `diagnostics/liminal_trace_report.py` (требуется Python 3, стандартная библиотека)

Команда выводит ключевые метрики — дельты когерентности, карту прогноза (anticipation heatmap) и коэффициент предсказуемости — прямо в консоль и в соответствующие файлы, что упрощает анализ длительных прогонах.
