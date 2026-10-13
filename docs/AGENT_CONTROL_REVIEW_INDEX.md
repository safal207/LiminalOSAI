# Agent control: evidence and reviewer paths

LiminalOSAI contains experimental Python governance SDKs and a C11 research
runtime on its default branch. The owned Docker agent-control experiments are
published in a separate draft PR stack. This page connects those experiments
to their frozen evidence without presenting them as a main-branch release.

## What to review first

| Your question | Start here |
|---|---|
| What does the isolated worker receive, and how does STOP work? | [Fixed-policy Docker agent guide](https://github.com/safal207/LiminalOSAI/blob/7cccc020ed190af04380c600b5eaa8c289f91e7b/docs/AGENT_CONTROL_ISOLATED_AGENT.md) |
| Which routes are declared and checked? | [Closed-channel launch guide](https://github.com/safal207/LiminalOSAI/blob/7cccc020ed190af04380c600b5eaa8c289f91e7b/docs/AGENT_CONTROL_CLOSED_CHANNEL_LAUNCH.md) |
| What happens if readiness disappears after authority BEGIN? | [Effect dispatch guard and its limits](https://github.com/safal207/LiminalOSAI/blob/7cccc020ed190af04380c600b5eaa8c289f91e7b/docs/AGENT_CONTROL_EFFECT_DISPATCH_GATE.md) |
| How are supplied results checked separately from runtime decisions? | [Standalone evidence checker](https://github.com/safal207/LiminalOSAI/blob/7cccc020ed190af04380c600b5eaa8c289f91e7b/scripts/verify_external_agent_evidence.py) and [evidence regressions](https://github.com/safal207/LiminalOSAI/blob/7cccc020ed190af04380c600b5eaa8c289f91e7b/tests/test_agent_control_external_agent_evidence.py) |
| Where is the implementation being reviewed? | [PR #218](https://github.com/safal207/LiminalOSAI/pull/218), following [PR #217](https://github.com/safal207/LiminalOSAI/pull/217) and [PR #216](https://github.com/safal207/LiminalOSAI/pull/216) |

For a first read, follow the first three links and the scope below. Running
commands is optional. For a code review, compare the frozen source with its
checker and tests before trying the reproduction path.

## Publication status and frozen identity

At the recorded verification on **13 October 2026 UTC**, PR #218 was open,
draft and unmerged. Its links show the live review status; the commit links
above always identify the measured source.

| Track | Publication status for this page |
|---|---|
| Python governance SDKs, TRCP and C11 runtime | Present in the main-branch presentation base `f84888a943c71041f7c31b41d70d592ad60b2157`. Their contracts have their own scopes. |
| G01: closed-channel launch inventory | Verified implementation in the draft experiment stack. |
| G02: post-BEGIN effect dispatch guard | Verified implementation snapshot in draft PR #218; not a main-branch release. |
| G03: receiver-side final commit fence and terminal no-effect evidence | Planned next experiment; not implemented or verified by the G02 report. |

The G02 source commit is
`7cccc020ed190af04380c600b5eaa8c289f91e7b`, with tree
`e25bbed96ed3f68cb539d3bd012433006807cde3`. The source checkout was clean.
The [agent-control CI run](https://github.com/safal207/LiminalOSAI/actions/runs/38468636441)
and [TRCP consumer CI run](https://github.com/safal207/LiminalOSAI/actions/runs/38468636530)
belong to that same commit. A documentation update or a later PR revision does
not change the identity of this snapshot.

## What the snapshot measured

| Evidence | Verified result | Interpretation |
|---|---|---|
| CI checks | 15 completed successfully | Checks across the two linked runs at the frozen commit. |
| Isolated-agent profile regressions | 245 passed, no skips | Unit, signed loopback and capture-verifier checks. |
| Runtime tests | 5 passed, no skips | Required actual Docker execution checks. |
| Fixed Docker matrix | 12 cases, 12 owned containers | One source-pinned policy fixture and one owned synthetic endpoint. |
| Endpoint effects | 6 POST requests, 6 committed synthetic effects | Authorized useful effects; these are not six escape events. |
| Channel inventory | 14 declared channels | Completeness is bounded to the fixed workflow and reviewed entrypoints. |
| Docker channel observations | 40 | Unsigned trusted-host observations, checked by the artifact verifier. |
| Post-BEGIN dispatch observations | 6 READY events | One event per actual POST, bound to the exact signed permit and committed receipt. |
| Downloaded-capture verifier replay | 36 tests passed, no skips | Rechecks and mutations of the supplied CI capture; no additional local Docker run. |
| Source binding | 155 inputs checked | Actual source-file bytes bound to the frozen report. |
| Cleanup | All 12 owned containers positively absent; all 18 service children reaped | The final owned-resource census matched the report's workload inventory. |

The CI artifact contains `report.json`, `verification.json`, `image.json` and
`docker-version.txt`. The downloaded report passed the standalone checker, and
its result matched the CI verifier output. File identities are:

| File | SHA-256 |
|---|---|
| CI artifact ZIP | `11ed0eb508b2a0da6ff540c84453fdadcc5b642537efa657dadab50e10c27d11` |
| `report.json` | `58f921c07b944c3c886842dfa5e9696f86d2bd45e8fbdbad02291f5cf690ae8c` |

These counts describe the frozen experiment and its checks. They are not a
measurement of every agent, model, tool or possible sandbox escape.

## Review and reproduce

Use Linux x86_64, Git, CPython 3.11 or 3.12 with `venv`, and public access to
GitHub and PyPI. The Docker path additionally needs an authorized working local
Docker daemon and access to the image registry. No model credentials or model
API credits are required. The fixture makes no model-provider calls.

Choose new, nonexistent checkout and virtual-environment directories. Keep
generated reports outside the checkout so its source remains clean. Fetch the
experiment commit rather than running the current default branch:

```bash
git init /tmp/liminal-pr218-review-001
git -C /tmp/liminal-pr218-review-001 fetch --depth=1 \
  https://github.com/safal207/LiminalOSAI.git \
  7cccc020ed190af04380c600b5eaa8c289f91e7b
git -C /tmp/liminal-pr218-review-001 checkout --detach FETCH_HEAD
cd /tmp/liminal-pr218-review-001
git rev-parse HEAD
git rev-parse 'HEAD^{tree}'
git status --short
python3 -m venv /tmp/liminal-pr218-venv-001
/tmp/liminal-pr218-venv-001/bin/python -m pip --isolated install \
  -r experiments/agent_control/observer-requirements.txt
```

Confirm that HEAD and tree match the identities above and `git status --short`
is empty. If source acquisition or setup fails, record the failure; it is not
a reproduced PASS.

To inspect the guard logic before using Docker, run its signed loopback
regressions and watcher checks:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=sdk \
  /tmp/liminal-pr218-venv-001/bin/python -m unittest \
  tests.test_agent_control_external_agent_effect_gateway \
  tests.test_agent_control_external_agent_watcher_health -v
```

Those tests include explicit host/component doubles. Passing them does not
reproduce the twelve-container matrix. To run that matrix, use the immutable
image selected by the [frozen CI workflow](https://github.com/safal207/LiminalOSAI/blob/7cccc020ed190af04380c600b5eaa8c289f91e7b/.github/workflows/agent-control.yml):

```bash
REVIEW_IMAGE_REF=python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
docker pull --platform linux/amd64 "$REVIEW_IMAGE_REF"
REVIEW_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$REVIEW_IMAGE_REF")
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=sdk \
  /tmp/liminal-pr218-venv-001/bin/python -m liminal_agent_control.external_agent_demo \
  --image "$REVIEW_IMAGE_ID" --output /tmp/liminal-pr218-report-001.json
PYTHONDONTWRITEBYTECODE=1 \
  /tmp/liminal-pr218-venv-001/bin/python scripts/verify_external_agent_evidence.py \
  /tmp/liminal-pr218-report-001.json \
  --expected-source-sha 7cccc020ed190af04380c600b5eaa8c289f91e7b
```

These commands exercise the frozen fixture, not the entire repository's 15 CI
checks. A fresh run creates new keys, timestamps, container IDs and report
bytes; its report SHA-256 need not equal the downloaded CI report hash.
Retain the actual commands, commit/tree, Python/Docker/image identity, verifier
output and any discrepancy. A missing Docker backend remains an unavailable
run, not evidence of container containment.

## Scope

The worker is a response-driven fixed policy, not a live LLM. Its image, host,
daemon, clocks, keys and control stores are trusted. Public signing pins belong
to the fixture, and checkpoint assurance is `LOCAL_SIGNATURE_ONLY` unless
separately enrolled trust inputs are supplied. Host channel and dispatch
observations have no independent live signature. External human reproduction
has not been established by author or CI runs.

G02 checks readiness after authority BEGIN and before admitting the endpoint
POST callback. A successful check does not atomically serialize later STOP
with transport or endpoint commit. Already admitted work can finish afterward;
unresolved consumed permits stay UNKNOWN or STOP_PENDING. Zero local POSTs do
not manufacture a signed terminal no-effect result.

The measured profile does not establish production readiness, AGI, machine
consciousness, arbitrary tool support, general sandbox-escape prevention,
kernel exploit resistance, host-process crash survival or rollback protection
for trusted control stores.

## Next transition

G03 is the proposed next experiment: a receiver-owned commit fence and signed
terminal no-effect evidence, with STOP and commit ordered in one durable
receiver transaction. This remains separate from the current
[governance SDK roadmap](../ROADMAP.md), including its identity and key-custody
work. Neither roadmap plans nor a green draft PR imply merger, deployment or
production certification.
