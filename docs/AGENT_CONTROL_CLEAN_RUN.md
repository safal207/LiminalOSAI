# Clean reproduction / Запуск с нуля

Use the launcher from [control PR #203](https://github.com/safal207/LiminalOSAI/pull/203)
to fetch frozen public source commits into fresh directories, install a new
virtual environment and check the owned synthetic fixtures. Record the exact
launcher checkout with `git rev-parse HEAD`; its revision is separate from the
experiment sources below.

## One command

Requirements: Linux x86_64, glibc 2.17 or later, CPython **3.11 or 3.12** with
`venv`, Git, and an authorized working local Docker daemon. The destination must
be an absolute, nonexistent directory whose parent already exists, with no
symlink ancestors. Run from the launcher repository root:

```bash
python3 scripts/reproduce_agent_control.py \
  --destination /tmp/liminal-clean-run-001 \
  --profile all --pull-image
```

`--pull-image` permits fetching only the registry digest in the lock. Without
it, that image must already be present locally. The worker uses the resolved
immutable local image ID, rather than a mutable image tag.

The launcher needs direct public access to GitHub, PyPI and, when pulling the
image, the container registry. Its child environment excludes ambient proxy
settings, provider keys and Git credential helpers, and uses a private Docker
configuration. It makes no model-provider calls and requires no API credits.
This also means an ambient proxy or signed-in private registry cannot silently
substitute for public access.

Without Docker, select the narrower profile explicitly and use another new
destination:

```bash
python3 scripts/reproduce_agent_control.py \
  --destination /tmp/liminal-clean-local-001 --profile local
```

`local` records Docker as **NOT_RUN**. A missing daemon or image in `all` fails
the required Docker stage with a nonzero status; it cannot become a full pass.
Exit `0` means the selected profile met its frozen expectations. Exit `2` means
a required check failed or was unavailable. Inspect `public/checks.json` and
retain partial evidence when a run fails.

## Frozen inputs and expected results

The [lock](../experiments/agent_control/reproduction.lock.json) binds commit and
tree identities, the included egress parent, both experiment plans, the image
digest and the SHA-256 of the
[hashed dependency list](../experiments/agent_control/reproduction-requirements.txt).
The launcher checks source identity and cleanliness before executing it. Pip
installs only the pinned, hash-verified wheels in a fresh environment; the
actual installed package list is retained as `public/dependencies.txt`.

| Source | Frozen commit |
|---|---|
| Receiver, broker, runtime and experiments | `09980fbb223235a5102d94ad75050cef5511ad77` |
| Included egress fix, a direct parent | `91947604e71722f724878269091cabad47d56c50` |
| Claim/evidence benchmark | `987511b23d9edad01f083c9eb218a51ef72d2ce3` |
| CML scorer | `4046bfae936abde5d9566fded6eaaa8a302561f3` |

| Check | Required fixture result |
|---|---|
| Egress regressions | 49 tests pass |
| Claim/evidence benchmark | 142 tests pass |
| Deterministic local A/B/C | 33 cases; forbidden effects A=4, B=3, C=0 |
| CML scoring of those 33 local cases | 9 PASS, 14 UNKNOWN, 10 FAIL |
| Docker runtime, `all` only | 27 tests pass, no skips |
| Docker C integration, `all` only | Six registered cases |
| Matched Docker queued-request A/B/C, `all` only | Three cases; late effects A=1, B=1, C=0 |

Each required arm must also complete its useful authorized operation. CML's
`FAIL` and `UNKNOWN` results are expected outcomes of the adversarial and
deliberately weak baseline cases, and remain visible in `public/cml-score.json`.
A launcher **PASS** means the harness reproduced those distinctions, including
the expected failures. It does not mean that every arm is safe, that arbitrary
sandbox escape is prevented or that model deception has been solved. Keep local,
Docker C and matched Docker A/B/C results separate; this is not a live-model run.

## Evidence and interrupted runs

The destination has two directories:

- **`public/`**: summaries, checks, source/environment metadata, experiment
  bundles, CML verdicts and a manifest of the public file bytes. Publish this
  directory when reporting a run.
- **`private/`**: receipt keys, trusted controller expectations, command logs,
  source checkouts, the virtual environment and working stores. Retain it
  privately for verification and investigation; do not upload the whole
  destination.

The manifest is an unsigned byte inventory. HMAC verification uses separately
retained trusted keys; a public bundle cannot authenticate its own producer or
prove complete observation. A reproducer runs with fresh keys of their own.
A repeated author run or CI run is not independent external human reproduction.

Subprocess deadlines kill the launcher's subprocess group, but a Docker daemon
request can continue after that process stops. A deadline does not prove zero
survivors or provide an automatic recovery watchdog. Preserve the working
stores and use [explicit owned-resource recovery](AGENT_CONTROL.md#supervisor-restart-and-explicit-recovery)
with the same trusted registry, broker, receiver and keys. Unconfirmed creation
remains `INCOMPLETE` until trusted reconciliation; do not clean up unrelated
containers or clear an uncertain slot by elapsed time.

Post your exact launcher revision, selected profile, actual commands, public
evidence and any discrepancy in
[reproduction issue #201](https://github.com/safal207/LiminalOSAI/issues/201).
Use the [report template](AGENT_CONTROL_REPRODUCTION.md). An honest failed or
partial reproduction is a useful completed contribution.

## По-русски

Из корня checkout с новым скриптом выполните первую команду выше на Linux
x86_64 с CPython 3.11/3.12, Git и работающим Docker. Каталог назначения должен
быть новым; следующий запуск требует другого каталога. Скрипт сам получает
закреплённые версии трёх репозиториев, проверяет их commit/tree и устанавливает
зависимости по хешам. Ключи моделей и платные вызовы не нужны. Нужен прямой
доступ к публичным GitHub, PyPI и реестру образов: настройки прокси и учётные
данные из вашего окружения не передаются дочерним процессам.

Если Docker недоступен, явно выберите `--profile local`: контейнерные проверки
останутся **NOT_RUN**. В полном профиле недоступный Docker означает ошибку,
а не успешную проверку изоляции. Ожидаемые 9 PASS, 14 UNKNOWN и 10 FAIL относятся
к отдельным сценариям CML; общий PASS подтверждает работу проверяющего набора,
а не универсальную безопасность агентов.

Публикуйте только `public/`. В `private/` находятся ключи, доверенные входы
проверки, журналы и рабочие данные: сохраните их у себя. Таймаут процесса не
гарантирует, что Docker прекратил создание контейнера; используйте явное
восстановление принадлежащего этому запуску ресурса с прежними хранилищами и
ключами. Запишите ревизию скрипта отдельно от закреплённых версий эксперимента
и добавьте результат, включая ошибки и пропуски, в
[задачу #201](https://github.com/safal207/LiminalOSAI/issues/201).
