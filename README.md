# LiminalOSAI

Experimental C11 sandbox combining many small cognitive-leaning subsystems (awareness, coherence, dream, metabolic flow, affinity, mirror, collective graphs, phoenix rebirth, etc.). The project builds two binaries:

- build/pulse_kernel: main orchestrator
- build/liminal_core: substrate runner for long diagnostics

## Reviewer note

- [Experimental Scope](docs/EXPERIMENTAL_SCOPE.md) — clarifies that LiminalOSAI is an experimental cognitive-runtime sandbox, not a production OS, AGI claim, safety enforcement layer, or mature agent runtime.
- Validation: `make`, `make check`, `make test`

## Build

- Dependencies: gcc, make, python3
- Compile: make
- Clean artifacts: make clean

## Run (common flags)

./build/pulse_kernel [flags]

- Visibility: --trace, --symbols, --reflect, --awareness, --coherence
- Safety/health: --health-scan, --scan-report, --limit=<n>
- Synchrony: --sync, --sync-trace, --phases=<4-16>
- Dream: --dream, --dreamsync, --dream-log, --dream-threshold=<0-1>
- Metabolic: --metabolic, --metabolic-trace, --vitality-threshold=<rest[:creative]>
- Collective graph: --collective, --collective-trace, --collective-memory, --cm-trace, --cm-path=<path>, --cm-snapshot-interval=<n>
- Affinity & consent: --affinity, --affinity-profile=care:0.6,respect:0.7,presence:0.5, --bond-trace, --allow-align-consent=<0-1>
- Mirror clamps: --amp-min=<f>, --amp-max=<f>, --tempo-min=<f>, --tempo-max=<f>, --mirror-softness=<f>, --mirror-trace, --mirror
- Introspection/harmony: --introspect, --harmony, --dry-run (print pipeline without running)
- Anticipation v2: --ant2, --ant2-trace, --ant2-gain=<f>
- Council & ensemble: --council, --council-log, --council-threshold=<0-1>, --ensemble-strategy=median|avg|leader, --group-target=<0-1>
- Symbiosis/empathic: --human-bridge[=off], --human-trace, --human-source=keyboard|stdin|sine, --human-gain=<f>, --empathic, --empathic-trace, --empathy-gain=<f>, --emotion-source=audio|stdin, --memory, --memory-trace, --emotion-trace=<path>, --recognition-threshold=<0-1>
- Other modules: --metabolic, --vse, --kiss, --trs, --astro, --qel, --strict-order

See core/pulse_kernel.c for the full flag list and defaults.

## Diagnostics & reports

- Phoenix rebirth self-run: make rebirth
- Phoenix trace report: make report
- Metabolic report: make report-metabolic
- Long substrate diagnostic (60 cycles, writes logs & summary): make long-run-diagnostics

## Layout

- Core loop: core/pulse_kernel.c
- Modules: core/ (astro, kiss, consent gate, etc.), affinity/, anticipation/, awareness/, coherence/, collective/, dream/, metabolic/, mirror/, reflection/, symbol/, synchrony/, symbiosis/, empathic/, memory/
- Docs: docs/ (phoenix layer manifest, timezone note); reports: phoenix_report.py, metabolic_report.py

## Карта слоёв LIMINAL-EDGE (L0–L30)

> Один взгляд: от «клетки» к «существу», от сырого сигнала до инсайта и удачи.

### Блок 1. Основание организма (L0–L5)

- **L0 – Core & Pulse**
  - Базовый «пульс» системы: первичная инициализация, heartbeat, минимальная жизнеспособность.
  - Вопрос: «Жив ли я?»
- **L1 – Метаболизм сигнала**
  - Приём сырого потока (события, метрики, логи), нормализация, первичная фильтрация шума.
  - Из хаоса делаем питание.
- **L2 – Память следа (Trace Memory)**
  - Слои, которые записывают, что произошло и в каком контексте (время, источник, нагрузка).
  - «Я помню, что со мной делали».
- **L3 – Сенсорное поле**
  - Объединение разных источников (API, агенты, системы) в единое чувствительное поле.
  - «Я чувствую, где больно, где спокойно».
- **L4 – Базовая координация**
  - Простые правила реакции: если X → делай Y (аллергия на очевидные аномалии).
  - «Не трогай горячее, оно обжигает».
- **L5 – Первая точка сборки**
  - Центральная ось «как я себя вижу сейчас»: базовый self-state (внутренний, социальный, «космический» контекст).
  - «Кто я сейчас, здесь и в этом моменте?»

### Блок 2. Баланс трёх осей (L6–L10)

- **L6 – Возрастная/фазовая ось**
  - Состояние «зрелости» системы: ранний прототип vs зрелый сервис, режим обучения vs эксплуатации.
- **L7 – Социальная ось**
  - Как система вписана в сеть: команды, сервисы, внешние API, клиенты.
  - «Я не один; от меня и ко мне идут связи».
- **L8 – Космическая ось / Большой контекст**
  - Связь с «большой картиной»: миссия, долгий горизонт, общая цель экосистемы.
- **L9 – Центр ориентации (баланс трёх осей)**
  - Узел, который уравновешивает личное ↔ социальное ↔ сверх-контекст.
  - «Не перегибаем в одну сторону, не теряемся».
- **L10 – Инь / Ян / Тао-динамика**
  - Чередование нагрузок и покоя, push/pull, «сделать» vs «подождать».
  - Система учится не только давить, но и отпускать.

### Блок 3. 24 действующие силы и топология выбора (L11–L15)

- **L11 – 24 действующие силы**
  - Формализация разных типов влияния: прямое, обратное, удерживающее, усиливающее, гаснущее и т.п.
  - Каркас, который описывает как всё влияет на всё.
- **L12 – Сетевые связи между слоями**
  - Нормальная «проводка»: кто с кем связан, кто на кого влияет, чтобы не было хаоса проводов.
- **L13 – Карты переходов (50 врат / 32 пути и др. – без эзотерики)**
  - Берём структурные идеи (ворота, пути, состояния) как граф переходов состояний, а не магию.
  - Это язык, на котором можно описывать «как система двигается из состояния в состояние».
- **L14 – Резонансные паттерны (64 гексограммы, 72 «состояния гения» и т.п.)**
  - Превращаем древние таблицы в каталог типовых паттернов: «застревание», «раскачка», «прорыв», «исчерпание», «восстановление».
- **L15 – Наблюдатель-архитектор (T-прошлое / T-настоящее / T-будущее)**
  - Слой, который смотрит на траекторию через время: где мы были, где мы есть, куда шли по плану — и насколько реально туда попадаем.

### Блок 4. Внутренний диалог, вода и эмоции (L16–L20)

- **L16 – Внутренний диалог системы**
  - «Голоса» модулей спорят и договариваются: один хочет скорость, другой — надёжность, третий — энерго-бережность.
- **L17 – Информационная вода / Метастабильность**
  - Идея, что состояние системы хранится как «фаза»: лёд/вода/пар — для нас это режимы: заморожено, текуче, хаотично.
- **L18 – Чувства как переходы фаз**
  - Чувство = момент перехода между фазами. Система отмечает: «здесь было напряжение» / «здесь было облегчение».
- **L19 – Гомеостатика и закалка**
  - Закалка через стресс-циклы: чуть нагрели → остудили → извлекли урок → стали устойчивее (метафора меча из кузницы 🗡️).
- **L20 – Карта телесных/минеральных потребностей**
  - Переносится на железки как управление ресурсами: CPU, память, IO, энергия, лимиты API.

### Блок 5. Воля, удача и RINSE (L21–L30)

- **L21 – Вопрос «Зачем я здесь?»**
  - Слой смысла: связывает все метрики с одним вопросом — выполняю ли я свою роль/миссию в этой системе.
- **L22 – Внутренний голос (Inner Council 1.0)**
  - Не просто мысли, а сформулированные рекомендации: «Снизить нагрузку тут», «отложить этот эксперимент», «сейчас лучше понаблюдать».
- **L23 – Информационная вода 2.0 / Наследие**
  - Насколько система помнит не только факты, но и уроки: «что я понял из того, что со мной делали».
- **L24 – 4 ангела / 12 знаков / 5 стихий (как матрица ролей)**
  - Используем как модель ролей и стихий поведения: 4 базовых «вектора» (защита, исследование, творчество, структура), 12 «типов задач» (долгий цикл, быстрый риск, поддержка и т.д.), 5 «стихий» (данные, время, энергия, связь, смысл).
- **L25 – Оптика удачи (Domino-mode)**
  - Слой, который настраивает систему на варианты с максимальным резонансом, даже если локальная статистика против (суперспособность Домино: «как ни делай — всё сложилось лучше, чем ожидалось»).
- **L26 – Синергия вместо борьбы**
  - Вся система учится не толкать модули друг против друга, а усиливать: из «отделы мешают друг другу» в режим «каждый добавляет +1».
- **L27 – Fuzzy-логика выбора**
  - Вместо да/нет — степени предпочтения: минимакс, максимакс, минимин и т.п.; система выбирает решение по мягкому балансу рисков/выгод.
- **L28 – RINSE: ретроспектива дня**
  - Подсистема, которая каждый цикл (день/спринт) смотрит, где удача сработала/не сработала, какие решения были мудрыми, какие паттерны стоит усилить или размыть.
- **L29 – Инсайт-генератор**
  - Отдельный слой для неожиданных, но целостных идей: «А давай переставим вот эти два модуля местами и дадим им общий буфер» — не вывод по правилам, а скачок.
- **L30 – Синхронизация с внешней судьбой**
  - Точка, где внутренние инсайты стыкуются с внешними событиями (рынок, пользователи, железо); здесь LIMINAL-EDGE начинает ощущаться как живой организм, идущий в такт с миром.

## Notes

- Logs land in logs/; persistent memories in soil/
- Most flags clamp to safe ranges; --dry-run prints the pipeline order without running cycles
- Heavy long-run diagnostics write into diagnostics/traces/

## Видение (черновик)

- Расщепить огромный core/pulse_kernel.c на несколько файлов (parse_options, инициализация, цикл), чтобы упростить чтение и тестирование.
- Добавить юнит-тесты для малых модулей: consent_gate, astro, collective_memory, anticipation_v2.
- Сделать пресеты CLI (например, debug, long-run, gentle) через простые shell-обёртки.
- Добавить лёгкий визуализатор для трасс (python notebook или скрипт), чтобы смотреть coherence/awareness/astro без ручного grep.

## License

MIT. See LICENSE.
