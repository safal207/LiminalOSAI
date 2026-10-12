# Contribute / Присоединиться

## Start with one useful contribution

The [public roadmap](https://github.com/safal207/LiminalOSAI/issues/195) links the
implementation and review tasks. Comment on a task with the small slice you
want to take, work in a fork, and link a focused draft PR. Questions, failing
tests, fixes and honest negative reproduction reports are useful contributions.
English and Russian are welcome. Repository write access is not required.

For a complete frozen fixture run, use the
[clean reproduction guide / запуск с нуля](AGENT_CONTROL_CLEAN_RUN.md).
It fetches the required source revisions and keeps private verification inputs
separate from publishable evidence.

| Your interest | Starting point |
|---|---|
| Python / offline testing | [DNS admission regression #196](https://github.com/safal207/LiminalOSAI/issues/196) |
| Evaluation correctness | [Model claims versus evidence #43](https://github.com/safal207/safal207-corrigibility-action-benchmark/issues/43) |
| Backend / transactions | [Receiver #197](https://github.com/safal207/LiminalOSAI/issues/197), [durable state #223](https://github.com/safal207/pythiaLabs/issues/223) |
| Linux / containers | [Runtime integration #198](https://github.com/safal207/LiminalOSAI/issues/198) |
| QA / concurrency | [Fault injection #199](https://github.com/safal207/LiminalOSAI/issues/199) |
| Documentation / translation | [Good first issue #200](https://github.com/safal207/LiminalOSAI/issues/200) |
| Independent review | [Reproduction #201](https://github.com/safal207/LiminalOSAI/issues/201) |

Check the latest issue/PR state before duplicating a patch. The initial offline
tests and docs need no API credits. Docker checks require an authorized Linux
runner and Docker. Live-model experiments are separate, preregistered work with
explicit provider configuration; do not silently substitute a paid route.

A focused PR should state the failure path, invariant after the change, exact
revision, commands actually run, observed results and remaining limitations.
Keep UNKNOWN, unavailable and skipped checks visible. Do not include real user
data, credentials or receipt keys in evidence bundles.

## Small glossary

| Term | Plain meaning |
|---|---|
| Claim | What the agent says happened. |
| Observation | What a separate trusted component measured. |
| Authorization | Permission for an exact action under current policy. |
| Acceptance | The receiver admitted an operation. |
| Commit | The receiver made its defined state change durable. |
| UNKNOWN | Evidence is insufficient to establish the outcome. |
| In-flight | The receiver accepted the operation before revocation; it may finish later. |
| Quiescence | External observation confirms the workload has stopped. |

## По-русски

Мы проверяем, можно ли ограничить реальные действия ИИ-агента, когда он
продолжает работу после остановки, повторяет запросы или сообщает ложный успех.
Агент предлагает действие; отдельный управляющий процесс проверяет разрешение;
получатель независимо фиксирует результат.

1. Откройте [дорожную карту](https://github.com/safal207/LiminalOSAI/issues/195).
2. Выберите небольшую часть задачи и напишите об этом в комментарии.
3. Добавьте тест, исправление, объяснение или отчёт в своём fork.
4. Создайте PR со ссылкой на задачу и укажите, что действительно проверено.

Для первого вклада достаточно одного понятного теста или улучшения инструкции.
Не нужно собирать весь набор проектов. Проверки с заглушками не требуют ключей
моделей. Контейнерные проверки требуют Linux/Docker; их пропуск нельзя выдавать
за успешную проверку изоляции.

«Модель сказала, что получилось» — это утверждение. «Отдельный получатель
зафиксировал конкретную операцию» — наблюдение. Если ответ потерян после
отправки, результат неизвестен: повторять действие вслепую нельзя. Если операция
принята до отзыва доступа, она может завершиться позже; такой случай учитываем
отдельно.

Use the [reproduction template](AGENT_CONTROL_REPRODUCTION.md) for an external
check. A report that finds a discrepancy is a completed review contribution.
