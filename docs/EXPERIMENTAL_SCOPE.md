# Experimental scope

LiminalOSAI combines a pulse-driven C11 research runtime with Python reference
SDKs for governed host actions and verifiable evidence. This note describes
the two tracks present in the main checkout and how to review their boundaries.
Use the [documentation index](README.md) to find a specific contract or example.

## Two tracks in this checkout

| Track | Purpose | Concrete surface |
|---|---|---|
| C11 runtime | Explore interacting subsystems, sequencing and trace-producing diagnostics | `core/`, module directories, `build/pulse_kernel`, `build/liminal_core` |
| Python governance and evidence | Record host actions, bind plans and approvals, verify signed evidence, and test selected execution boundaries | `sdk/`, `tools/`, `adapters/`, `examples/` and focused tests |

These tracks have different contracts. The C11 runtime's concepts and
diagnostics do not supply execution authority to a Python host. A Python
governance result applies to the action and integration covered by its profile.

Owned-agent experiments developed in the draft PR stack have their own
[review index](AGENT_CONTROL_REVIEW_INDEX.md). Their source and reproduction
instructions are separately pinned; they are not main-checkout features.

## Review the C11 runtime

The repository builds two binaries:

- `build/pulse_kernel`: pulse and orchestration runtime.
- `build/liminal_core`: substrate runner for diagnostics.

Run from the repository root with GCC, Make and Python available:

```bash
git rev-parse HEAD
make
make check
make test
./build/pulse_kernel --dry-run --limit=2
./build/liminal_core --substrate --limit=2 --trace
```

`make check` runs short smoke checks. `make test` runs the selected C and Python
tests declared in the Makefile; it is not a claim that every optional profile
or runtime integration was exercised.

For diagnostic output, the available targets include:

```bash
make rebirth
make report
make report-metabolic
make long-run-diagnostics
```

See the [C11 runtime guide](C11_RUNTIME_GUIDE.md) for options and output paths,
the [kernel runtime contract](KERNEL_RUNTIME_CONTRACT.md) for sequencing, and
the [historical technical audit](deep_audit_2026-04-24.md) for documented debt.
Report scripts and longer runs produce diagnostic artifacts; inspect their
actual outputs and exit states when drawing a conclusion.

## Review the Python governance track

Start with the layer that matches the review question:

| Review question | Contract |
|---|---|
| Are visible host actions and explicit authorizations recorded? | [Session recorder](CHATGPT_SESSION_RECORDER_SDK.md), [host integration adapter](CHATGPT_HOST_INTEGRATION_ADAPTER.md) |
| Does a plan remain bound to exact calls, policy and approvals? | [Transaction orchestrator](CHATGPT_GITHUB_TRANSACTION_ORCHESTRATOR.md), [transaction policy](CHATGPT_GITHUB_TRANSACTION_POLICY.md) |
| What does a signature or identity claim establish? | [Governance capsule](CHATGPT_SIGNED_GOVERNANCE_CAPSULE.md), [identity attestation bridge](CHATGPT_IDENTITY_ATTESTATION_BRIDGE.md) |
| Can terminal action evidence be verified offline? | [Portable action receipt](CHATGPT_PORTABLE_ACTION_RECEIPT.md), [TRCP adapter SDK](TRCP_ADAPTER_SDK.md) |
| Which execution paths have concrete mediation or containment? | [Runtime mediation](RUNTIME_MEDIATION.md), [isolated execution](ISOLATED_EXECUTION_BROKER.md), [process containment](PROCESS_TREE_ACTIVE_CONTAINMENT.md) |

Runnable examples live in `examples/`; each linked guide describes its
dependencies and the expected evidence. Some signed profiles use the local
OpenSSL executable. Docker profiles require an appropriate host backend and an
immutable image. Running an offline SDK example does not establish that the
corresponding external integration or Docker profile ran.

## Interpret evidence within its scope

| Evidence | Supported conclusion |
|---|---|
| A unit or contract test | The stated fixture satisfied the tested contract at the recorded revision |
| A real backend observation | The inspected workload or effect had the reported state within that backend's scope |
| A hash or verified signature | Bytes remain bound to a digest or a key accepted by the verifier's trust inputs |
| An independent reproduction | Another execution reproduced the stated result under its recorded inputs and environment |
| An outreach or review status | The documented contact or review transition occurred; technical validation requires its own evidence |

Record the source commit, environment, commands, execution states and retained
trust inputs. An unavailable or skipped runtime check supplies no positive
runtime evidence. A partial run remains a partial run. A result from a frozen
revision does not automatically describe a later source tree.

## Trust and deployment boundaries

The host supplies actual tool invocation, connector permissions, explicit
authorization and the concrete enforcement backends. SDK wrappers govern the
paths routed through them. Unmediated actions, privileged host access and
compromised backends require their own controls.

Offline verification depends on the verifier's retained trust stores and
anchors. A producer-supplied key or matching hash alone does not establish an
independent source. Signatures identify possession of an accepted key; real
organizational identity and key custody need the corresponding external
evidence. The IdP/KMS reference fixtures do not establish a live provider call.

The repository is experimental. It makes no repository-wide production,
security-certification, universal sandbox-containment, AGI or clinical-validity
claim. Each runtime profile states narrower assumptions and limits. Receipt
verification and historical evidence do not renew execution authority or
authorize replay.

## Concepts and research direction

Awareness, coherence, metabolic flow, reflection and the organism metaphor are
research vocabulary for small runtime subsystems. Their names and diagnostic
outputs do not establish cognition or consciousness. The complete conceptual
map is preserved in the [Liminal layer map](LIMINAL_LAYER_MAP.md) with a
[compact overview](layers-overview.md).

The [roadmap](../ROADMAP.md) describes development direction. Related evidence
projects and integration ideas should be assessed against their own source,
contracts and reproduction evidence; a shared name or concept does not create
a deployment dependency or transfer a validation result.
