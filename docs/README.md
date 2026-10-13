# Documentation

LiminalOSAI contains two experimental tracks: a pulse-driven C11 runtime and
Python SDKs for governed host actions and verifiable evidence. Start with the
[repository overview](../README.md) and [experimental scope](EXPERIMENTAL_SCOPE.md),
then choose a route below.

## C11 runtime and diagnostics

| Goal | Start here |
|---|---|
| Build, run a short check, or inspect CLI options | [C11 runtime guide](C11_RUNTIME_GUIDE.md) |
| Understand runtime state and sequencing contracts | [Kernel runtime contract](KERNEL_RUNTIME_CONTRACT.md) |
| Review the decomposition approach | [Kernel refactor protocol](KERNEL_REFACTOR_PROTOCOL.md) |
| Explore the organism-inspired concepts | [Liminal layer map](LIMINAL_LAYER_MAP.md), [compact layer overview](layers-overview.md) |
| Read diagnostic context and technical debt | [Phoenix layer](phoenix_layer.md), [historical technical audit](deep_audit_2026-04-24.md) |

Conceptual layer names explain research ideas. The runtime guide and module
contracts describe the executable behavior.

## Python governance and evidence

Follow the smallest layer that fits the task. The host supplies actual tool
execution and authorization; a receipt or advisory decision does not replace
those responsibilities.

| Goal | Start here |
|---|---|
| Evaluate a structured draft against supplied evidence | [Liminal adapter](CHATGPT_LIMINAL_ADAPTER.md) |
| Record visible host actions and their outcomes | [Session recorder](CHATGPT_SESSION_RECORDER_SDK.md), [host integration adapter](CHATGPT_HOST_INTEGRATION_ADAPTER.md) |
| Normalize existing session records | [Conversation normalizer](CHATGPT_CONVERSATION_NORMALIZER.md), [session exporter](CHATGPT_LIVE_SESSION_EXPORTER.md) |
| Bind a host's GitHub calls to a narrow action catalog | [GitHub bridge](CHATGPT_GITHUB_AGENT_BRIDGE.md), [connected runtime](CHATGPT_CONNECTED_GITHUB_RUNTIME.md) |
| Review a multi-step plan, approvals and recovery | [Transaction orchestrator](CHATGPT_GITHUB_TRANSACTION_ORCHESTRATOR.md), [transaction policy](CHATGPT_GITHUB_TRANSACTION_POLICY.md) |
| Verify signed governance and identity evidence | [Governance capsule](CHATGPT_SIGNED_GOVERNANCE_CAPSULE.md), [identity attestation bridge](CHATGPT_IDENTITY_ATTESTATION_BRIDGE.md) |
| Export terminal action evidence for offline verification | [Portable action receipt](CHATGPT_PORTABLE_ACTION_RECEIPT.md) |
| Adapt another workload to TRCP evidence binding | [TRCP adapter SDK](TRCP_ADAPTER_SDK.md), [benchmark scope](benchmark-v0.1.md), [semantic mutation checks](TRCP_SEMANTIC_MUTATION.md) |

The identity bridge includes provider-neutral fixture contracts. Real IdP/KMS
integration and the verifier's retained trust stores are separate deployment
inputs. The `CHATGPT_*` filenames identify these reference documents; they do
not imply an installed integration with a hosted product.

## Runtime boundary research

| Question | Relevant profile |
|---|---|
| Which threats and interfaces are declared? | [Phase 0 threat model](POST_SANDBOX_PHASE0_THREAT_MODEL.md) |
| How are capabilities checked at dispatch? | [Capability broker](CAPABILITY_BROKER_PHASE1.md), [runtime mediation](RUNTIME_MEDIATION.md) |
| How are outbound destinations bound? | [Egress gateway](EGRESS_GATEWAY_PHASE2.md) |
| How is one immutable container plan executed? | [Isolated execution broker](ISOLATED_EXECUTION_BROKER.md) |
| How are workload descendants observed and contained? | [Process tree containment](PROCESS_TREE_ACTIVE_CONTAINMENT.md) |
| How are uncertainty and cross-process reservations preserved? | [Durable governance fence](DURABLE_CROSS_PROCESS_GOVERNANCE_FENCE.md) |
| How are effect, epoch and objective bindings checked? | [Epoch-bound effect commit](EPOCH_BOUND_EFFECT_COMMIT.md), [objective-bound effect commit](OBJECTIVE_BOUND_EFFECT_COMMIT.md), [causal-bound effect commit](CAUSAL_BOUND_EFFECT_COMMIT.md) |

Each profile defines its own supported paths, dependencies and trust assumptions.
A contract test, a backend observation and an external reproduction answer
different questions; retain their individual execution states.

## Owned-agent experiments in the draft stack

The separate [agent-control review index](AGENT_CONTROL_REVIEW_INDEX.md) points
to the source revisions and review material for the owned-agent experiment
stack. Those profiles are being developed in draft PRs and are separate from
the main-checkout SDKs listed above. Follow the index's pinned source and
reproduction instructions when reviewing them.

## Review and contribute

For a useful report, record the source commit, environment, commands actually
run, observed result, and the smallest failing or successful case. Preserve
unavailable, skipped and unresolved checks. Include the profile's scope and
the trust inputs used to interpret its evidence.

The [roadmap](../ROADMAP.md) describes direction. The
[external review ledger](EXTERNAL_REVIEW_LEDGER.md) and
[validation graph](EXTERNAL_VALIDATION_GRAPH.md) track evidence of review;
contact or routing status does not establish technical validation.

Changes to an execution boundary should explain the exact action being
controlled, the host-owned enforcement point, the failure behavior and the
evidence needed to check the result. Documentation fixes, focused negative
tests and reproducible counterexamples are all useful contributions.
