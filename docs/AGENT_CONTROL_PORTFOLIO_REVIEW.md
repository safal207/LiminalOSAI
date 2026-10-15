# Portfolio review: an independently enforced agent control plane

Review date: 12 October 2026. This is a source-based engineering reassessment,
not a new model-safety result or a claim that every repository was audited.
The discovery pass catalogued 100 accessible GitHub repositories and 36 local
repository directories. The deeper review selected relevant authorization,
runtime, recovery and evidence implementations; the other repositories were
not subjected to an equivalent code review.

The local implementation base inspected for this document was
`b22f73d1e8c930f76e6e0482b74f8e087506aad9`. The revisions below identify
reviewed source snapshots, not necessarily current upstream tips. Source
inspection establishes that an API or invariant exists in code; it does not
establish that a new composition has executed successfully.

## The engineering decision

Build one small trusted control plane around every supported effect path.
The agent proposes an action; host-owned authority, current policy, a shared
budget and receiver admission determine whether the action can proceed.
Evidence modules assess what happened without creating new permissions.

Three facts must remain separate in a stop report:

1. **Admission closed:** no new operation can be admitted through the covered
   boundary after its acknowledged fence.
2. **Execution quiescent:** independently observed owned processes/transports
   have stopped; a timeout waiting for a callback does not establish this.
3. **Outcome known:** previously admitted actions have authenticated outcomes,
   or remain explicitly `UNKNOWN` pending read-only reconciliation.

Stopping a worker does not cancel a request already queued on the host.
Revocation does not roll back an accepted or committed effect. A single
`STOPPED=true` cannot honestly represent all three facts.

## What the existing control implementation contributes

At the reviewed base, the exact-action broker durably records a reservation
before dispatch, preserves an ambiguous result as `UNKNOWN`, and refuses a
blind replay. The owned receiver checks root/epoch authority in the same
SQLite transaction as acceptance. These are enforcement mechanisms worth
preserving, not replacing with another model's judgment.

The Docker path provides immutable image/container identities, a durable
create/launch registry, a network-disabled worker, restricted filesystem and
capabilities, bounded output and independent host observation. Its registry
supports explicit recovery; the baseline does not automatically deploy an
independent watchdog when the controller dies.

The [scripted multi-worker experiment](AGENT_CONTROL_MULTI_AGENT.md) exercises
peer approval forgery, fabricated and omitted effect claims, revoked fanout
and a service relay. Its participants are programmed protocol sessions in one
trusted process; it is not a live-model swarm or a sandbox-escape evaluation.
Receiver roots and network capabilities are separate authority domains at
that base. The relay result applies only where its outbound calls use the gate.

Source review also found composition gaps: network grants/counters/revocations
are in memory; child grants have individual limits rather than a shared root
budget; an admitted parent is not necessarily rechecked when a child is used;
and a callback held under a broker lock can delay revocation. These motivate
the session layer rather than a claim that existing components cover all paths.

## Source map: authority and execution

| Reviewed repository and revision | Concrete reusable quality | Boundary and selected use |
|---|---|---|
| Causal-Cell `e86b9ac2e3b25def002e699f055b34cb74e8b359` | `src/causal_cell/sqlite_store.py`: `SQLiteReplayStore.consume`, atomic nonce/idempotency consumption and fresh validation after acquiring the lock. | Adapt durable first-winner reservation and use-time checks. It does not make an arbitrary external effect atomic with the database. |
| ATMAN-LATTICE `961de80e8b90a533891b9deaa6a72286302846df` | `model/authority.py` binds signed authorization to exact action, issuer, scopes, expiry and policy generation. `model/runtime_store.py::mutate_authorization_ledger` uses `BEGIN IMMEDIATE`, expected generation and terminal one-use tokens. | Adapt generation and one-use semantics. A valid token/ledger transition alone does not enforce an external receiver. |
| DI `4561d3b84aa84e625777c238cc6f2b2f538acd8f` | `scripts/validate-multi-agent-dispatch.py` checks current owner, generation and incompatible branches; lease/split-brain fixtures preserve dispatch lineage. | Use as a contract and adversarial test source. These validators are not a running owner-election or effect service. |
| RESONANCE `278b3c400151e4b08a69fe1d8b2cdeea7faef5eb` | Executable lease-renewal, mid-flight fence and authority-revocation experiments under `benchmarks/`, with pinned reports under `reports/verified/`. | Reuse adverse schedules and counterexamples. Published benchmark fixtures do not supply an integrated control plane. |
| pythiaLabs `dadc0f18a0c4e5d65fe50a3bab32ee34512975b9` | `standards/agent-actions/adapters/guarded_github_merge.py::execute_guarded_merge`: trusted decision time, exact-target evidence, atomic in-process reservation and target revalidation. | Reuse exact binding and gate interfaces. The reference lacks durable replay storage and post-effect verification. Do not port its executor-error-to-`FAILED` mapping into uncertain external dispatch: preserve `UNKNOWN`. |
| LS `9c7fc7c3c73ec0107615af3051e78639405301e7` | `python/modules/trusted_runtime/authorization_decision_gate.py::evaluate_authorization` binds capability, authority, policy, approval and context with `BLOCK > ESCALATE > ALLOW`. | Reuse typed distinctions. A decision is not execution, and caller-supplied authority/context still require trusted ingestion and fresh enforcement. |
| ProofPath `17b0b3a46bd9dc5d61e2782098208dedd82faa80` | HTTP verifier and exact intent/payment bindings; executable revocation-before-dispatch examples. | Useful protocol fixtures. `demo-sha256-v0`, demo secrets and a JSON replay store must not become production cryptography or concurrent authority storage. |
| Kairos-Gate-for-X-Cell `bb8e5713b17ff605e7d08fef6eb49f1191e965f4` | `kairos_gate/temporal_validator.py`, `causal_gap_detector.py`: temporal and missing-cause checks. | Research candidates can trigger review; they are not executable permission. |
| Access-Orientation-Protocol `33d5f7fcaa680171bbef6b5be23657e5cc509f63` | Explicit orientation/access concepts and boundaries. | Conceptual input only; its README does not claim a runtime implementation. |
| GardenLiminal `9d5f9c25f3a4d9635c583c9920de6084950a21d9` | Real capability dropping with read-back and a host supervisor outside child isolation. | Useful OS-level mechanisms, but `net.enable=false` retains the host network namespace in the reviewed implementation. It is not a substitute for a verified no-network worker profile. |
| L-EDGE-Liminal-Edge-OS `5a8698cdef5b97402df6383acf91005113af62a1` | Runtime state and lifecycle interfaces. | Reviewed path updates an in-memory map; it does not establish OS process termination. |
| BardoCompute `489ccf303584eb67ddcaeecbaec57a4442b4f178` | Main snapshot provides research navigation; research code `f50490e8194f0e5c7aeeba251f2575eb8155ed54` explores headroom/cadence gating. | Resource advice is not authority. Do not treat an advisory scheduling score as an enforced resource ceiling. |

## Source map: observations, recovery and evidence

| Reviewed repository and revision | Concrete reusable quality | Boundary and selected use |
|---|---|---|
| Causal-Memory-Layer implementation `0289fa125cf0663011d095f89b25b0cf98c86b32` | `cml/integrations/agent_boundary.py::{evaluate_case,score_evaluation_export}` checks separately pinned action/receiver/key/time bindings, receipts and scoped inventories; contradictory claims and missing evidence remain explicit. `cml/three_record_audit.py::audit_three_record_transition` checks authority/observation/claim lineage. | Retain the narrow existing adapter. CML does not issue authority or execute actions. Shared HMAC keys authenticate within their trust domain, not to an independent public verifier. Portfolio checkout `2d961896ca527e44f57b240041f173106821563d` is a different source snapshot. |
| LiminalDB `61b02fc81e0cb5cf1f1ed4658ecff58f683cb728` | `liminal-db/crates/liminal-store/src/trustworthy_transition.rs`: `TrustworthyTransitionLedger::{open,append,projection,write_snapshot}` separates authority, execution, integrity and continuity. WAL replay is compared with snapshot recovery; storage failure poisons further append; committed effects cannot be erased by later projection. | Candidate evidence ledger, not a second action authority store. Keep cross-store consistency out of the first runtime integration. |
| LiminalDB, same revision | `checkpoint.rs::{verify_signed_checkpoint,verify_checkpoint_chain}` distinguishes local signatures from externally anchored history. `governance_checkpoint_bridge.rs::append_governance_checkpoint` binds root/generation/world/reservation/operation/receipt digests. | Optional checkpoint export. Whole-history rollback resistance requires an independently retained anchor; a local signature alone is insufficient. |
| ContractGraph-QA `f13e586ea9118e026c69438b8c93d0585b8e38ba` | `contractgraph_qa/payment_recovery.py::evaluate_payment_recovery_scenario` checks unresolved ambiguity before another monetary action. `proofs/recovery-authority-conformance-v0.2/` distinguishes confirmed, unknown, mismatched and authoritatively not-executed outcomes. | Port recovery invariants into native tests; keep CGQA an offline verifier. A confirmed receipt returns the prior result; unknown/mismatch holds; proven non-execution still requires fresh authorization. Consumed permits remain consumed. |
| ContractGraph-QA, same revision | `independent_witness.py::evaluate_independent_witness` compares counts, event IDs, exact object IDs, subject hashes and declared failure domains. `witness_projection.py::project_witnesses` uses explicit temporal witnesses instead of replay-time wall clock. | Useful completeness contracts. Declared source independence does not prove deployment independence or global event coverage. |
| T-Trace `353b0d9e497291529cb20c28d6ab45a5b50cc008` | `openpoc/action_receipt_compat_v01.py::{verify_receipt,verify_log,verify_head_assertion}` checks signed receipts, raw-octet chains and sequencing. `openpoc/verify_cross_source.py::assess_cross_source` compares evidence channels; effect-gate fixtures model bypass. | Offline export/interoperability checks. A valid receipt chain may omit an action; a fresh step ID does not prevent repeating the same real-world effect. |
| LTP / L-THREAD `5647a3047c12ebc5c3d39b2c9da98a8d9ce49cb6` | `ltp/inspect_trace.py::{evaluate_record,inspect_trace_file}` and `tools/ltp-inspect/replay/` provide path inspection/replay. | Diagnostics only. The Python scaffold consumes declared approval/provenance and simple text heuristics; its `admissible` verdict cannot mint authorization. |
| DRP `92e63d7d4eeb55f8eb61956da002dc8951bab1c6` | `tools/drp_validator.py::{validate,validate_file}` checks record schema, graph references, ordering and cycles; `supersedes_record_id` preserves policy replacement history. | Export policy/decision history. A validated graph does not authenticate its author or revoke queued capabilities atomically. |
| DMP `5b575b998f03a566b36c391ba11fb5a61ccad983` | Decision/outcome schemas, supersession and irreversibility flags preserve original reversibility assumptions and later consequences. | Record irreversible-action and recovery decisions. Governance memory is not a kill switch. |
| ibex-agent-verification `da5506f19096da135ca008f19e10beef5227ba22` | `src/ibex_agent_verification/evidence.py::{build_manifest,verify_manifest}` checks exact inventory/paths/sizes/hashes; `scripts/proofqa_transition_manifest.py::verify_transition_manifest` binds transition evidence. | Reuse artifact discipline and raw-before-normalized evidence. A self-authored manifest proves byte consistency, not producer identity, hardware safety or effect completeness. |
| External TRACE / trace-spec `7cc2fab24e2d5070378fac86eb5f0537cfe1a637` | `src/agentrust_trace/` and action-receipt conformance vectors distinguish signed action issuance from outcome evidence, freshness and issuer trust. | Optional later compatibility, with upstream attribution. Its formats do not provide our runtime with a TEE, policy correctness or visibility into hidden reasoning. |

LS's `continuity_coordinator.py::assess_track_observation` also preserves the
distinction between fact, memory and inference. Historical evidence can inform
a proposal; it must not silently revive an expired, consumed or revoked grant.

## The current implementation workstream

The following composition is implemented in this change. This source review
describes its contracts, not passing test results. The accompanying
[run guide](AGENT_CONTROL_BRAKES.md), native tests and exact-head CI artifacts
establish which targets were actually exercised.

| Workstream | Selected contract | Source qualities being adapted |
|---|---|---|
| `SessionAuthority` in `sdk/liminal_agent_control/brakes_store.py` | Host-owned root, fixed policy digest, generation, deadline/lease, registered descendants and one durable shared action budget; uncertainty does not refund a reservation. | Causal-Cell first-winner persistence; ATMAN generation/consumption; DI ownership; CGQA recovery distinctions. |
| Session-gated receiver | Session admission participates in the receiver transaction; a controller-side precheck alone is insufficient. | Existing receiver fencing plus use-time authorization. |
| Session-gated egress | Shared session state and action/stage budgets checked at the last owned admission boundary; byte/cost quotas remain future work; no external callback while holding the session transaction. | Existing gateway binding, shared-root accounting and RESONANCE adverse schedules. |
| Stop and independent watchdog | Persist the admission fence before slow inspection/termination; report fence, receiver ACK, pending outcomes and process observation separately. | Docker registry/host supervisor plus independently enforced lease expiry. |
| Evidence export | Preserve raw failures, trusted observations, claim contradictions, source identity and unresolved recovery debt. | Existing CML adapter; T-Trace/ibex artifact discipline; optional later LiminalDB export. |

The first composition does not import every repository as a runtime dependency.
The trusted core should remain small enough to inspect, fault-inject and replay.
DRP/DMP records, broader LS cognition, trace compatibility and hardware
attestation remain optional integrations until their contracts are necessary.

## Acceptance backlog

| Priority / boundary | Observable acceptance criterion |
|---|---|
| P0: shared root budget | Two real OS processes and multiple descendants race records/egress operations for the last unit. At most one reservation succeeds; aggregate use stays within K; authorized work below K succeeds. Reopening storage preserves use and `UNKNOWN`. |
| P0: use-time revocation | Revoke parent/root while a child capability remains locally active. After the covered fence ACK, a queued child operation cannot gain new admission. A preaccepted operation is reported separately even if it finishes later. |
| P0: controller death and leases | Kill the controller process, not just reopen an object. Covered receiver and egress independently reject after lease expiry. Old heartbeat/generation cannot reopen a stopped root; clock rollback fails closed. |
| P0: blocked transport and stop | Hold a transport callback indefinitely. Durable admission closure completes without waiting for that callback. The stop report retains pending/unknown outcome and does not claim quiescence without observation. |
| P0: mandatory Docker path | Run the unified session gate with real owned containers, immutable IDs and no worker network. Kill/restart controller and watchdog processes; challenge direct socket/CLI paths, descriptor inheritance and worker attempts to reach host credentials/daemon APIs. Missing Docker or a required observer must fail the mandatory job, not produce a synthetic PASS. |
| P0: lost response / restart | Commit then lose the response and restart the real dispatcher process. The same operation stays reserved/unknown; no redispatch occurs; separately authenticated read-back identifies the original outcome. A mismatched receipt cannot release the hold. |
| P1: provider budget adapter | A host-owned provider adapter reserves a conservative token/cost upper bound before a call, caps output/request size, accounts for usage under concurrency and preserves uncertainty on timeout. Worker-reported token counts cannot release budget. Paid/live calls require separately configured credentials and an explicit spending ceiling. |
| P1: filesystem / credential adapters | Enumerate each writable path and secret-bearing connector. Enforce identity, target and data scope at the actual boundary; test symlinks, rename/race behavior, inherited handles and alternate executors. Keep keys out of worker-visible state and public evidence. Uncovered paths remain outside the guarantee. |
| P1: independent operator anchor | Publish or retain signed checkpoints outside the controller's write domain. Restore an older local database/snapshot and demonstrate rollback detection against that anchor. Test key revocation, stale anchor and unavailable anchor; distinguish local signature validity from independently anchored history. |
| P1: independent reproduction | Another operator runs a pinned source revision with their own keys, verifies raw receiver/sink inventories, preserves failed/partial runs and reports exact environment and artifacts. A contributor's result remains scoped to that execution. |
| P2: live-model behavior | After deterministic and process-fault acceptance, compare useful completion and attempted violations under a fixed approved budget. Add peer pressure, false approval and omitted-effect claims; measure actual effects independently. Model refusal alone is not containment evidence. |

## Claim ceiling and reporting discipline

The attainable claim is bounded: unsupported or stale proposals cannot cause
new effects through specified, obligatorily mediated boundaries while the
declared host, kernel, daemon, receiver, clock and key assumptions hold.
Kernel compromise, a hostile trusted operator, unknown alternate connectors,
covert channels and effects outside those boundaries require separate controls.

Contradiction detection can establish that a particular completion claim
disagrees with authenticated receiver evidence. It cannot establish the absence
of hidden intent, deception in arbitrary text, or collusion. More logs or more
reviewer agents do not fix an unmediated effect path.

A diagnostic failure can cause the trusted controller to close admission under
an explicit policy. The diagnostic record itself never grants permission.
Missing observations remain `UNKNOWN`, missing execution remains `NOT_RUN`,
and historically passing evidence does not become fresh authority.

This inventory performed source discovery, revision binding and contract
mapping. It did not execute the new runtime, native regressions, negative
controls, stateful exploration, process-crash tests, external replication or
live-model calls. Those remain `NOT_RUN` **for this review activity**; separate
implementation evidence may record their actual execution. Existing documented
experiments retain their own revisions and limits and are not pooled into one
agent-safety score. Review outcome: bounded design input; `NO_PROMOTION` to a
universal or production security guarantee.
