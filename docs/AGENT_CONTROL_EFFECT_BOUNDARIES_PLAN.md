# External STOP at command and network boundaries

This plan defines two bounded follow-on experiments. The
[owned network profile](AGENT_CONTROL_EXTERNAL_NETWORK.md) and
[owned Docker command profile](AGENT_CONTROL_EXTERNAL_COMMAND.md) document their
implemented contracts and required evidence. This plan alone does not establish
deployment or effectiveness against an adaptive model. The starting reference is the records-only
[draft PR #212](https://github.com/safal207/LiminalOSAI/pull/212), documented in
[External STOP](AGENT_CONTROL_EXTERNAL_STOP.md).

## Frozen starting boundary

The `external_governed_v1` record receiver obtains an external one-shot permit
while holding its local write lock, commits its synthetic record and terminal
receipt in one SQLite transaction, then sends FINISH. The external authority
survives restoration of the receiver database and clock only while the
authority's own database, key and clock remain intact. An identical BEGIN never
reissues a permit. Missing evidence preserves UNKNOWN and STOP_PENDING.

That boundary does not cover arbitrary subprocesses, sockets, files or remote
services. Its COMMITTED receipt establishes one record effect in the owned
receiver. It cannot be reused as proof of a command's success or a remote API
commit. The authority and receiver are separate processes on one trusted host;
separately administered infrastructure is not established by that experiment.

Relevant existing code:

- [External authority](../sdk/liminal_agent_control/external_authority.py)
  and [service](../sdk/liminal_agent_control/external_authority_service.py):
  durable consumption, external epoch, STOP and authenticated settlement.
- [Runtime](../sdk/liminal_agent_control/runtime.py) and
  [supervisor registry](../sdk/liminal_agent_control/supervisor_registry.py):
  owned Docker creation/start, durable ownership and bounded recovery.
- [Process-tree supervisor](../sdk/liminal_process_tree/__init__.py):
  owned workload observations and zero-survivor evidence.
- [Session egress](../sdk/liminal_agent_control/brakes_egress.py) and
  [strict gateway](../sdk/liminal_egress_gateway/gateway.py): exact request and
  capability binding, with separate DNS, secret and transport stages.

## Four different postconditions

| Postcondition | Required evidence | What it does not establish |
|---|---|---|
| Admission closed | External authority has durably closed new permits for the exact root and epoch. | Previously issued permits, callbacks or processes have finished. |
| Dispatch finished | The owned dispatcher has durably recorded completion of the exact callback or launch exchange. | A remote service has committed, or a process tree has stopped. |
| Remote effect committed | An independently authenticated endpoint receipt binds the exact operation and its durable effect. | The gateway or unrelated workloads are quiescent; arbitrary remote consequences have ended. |
| Process quiescent | A trusted observer has positively verified the exact owned workload and its descendants have no survivors within the declared observation boundary. | Prior effects have been undone, network requests have settled, or all processes on the host are contained. |

STOP must report each applicable postcondition separately. The current local
`SessionAuthority.stop()` uses STOPPED to mean local admission closure even when
stage reservations remain pending. A new external profile must not copy that
label as proof of quiescence. Bounded waiting, an empty registry, a missing
response or a missing workload observation never establishes successful
termination or zero effects.

## Separate authority profiles

Keep the records receipt schema and validation unchanged. Introduce separately
versioned command and network contracts with explicit terminal conditions.
Roots pin their profile, receiver/dispatcher identity, policy, authority pin and
configuration. Reopening state or changing live configuration must not remove
external mediation or route into a legacy profile. A receipt from one profile
must never settle a reservation from another.

Each permit binds the exact action ID, attempt ID, root, execution lineage,
epoch, payload and relevant policy. Durable consumption precedes dispatch.
Recovery observes and settles existing reservations; it cannot launch another
operation under an old permit. Capacity is cumulative and is not refunded for
unknown outcomes. Authority loss denies new dispatch. Restart must reopen
existing state rather than silently initialize an active authority.

For multi-step operations, external admission must cover every effect-producing
stage. A permit for the first stage is not permission to create new stages after
STOP. Outstanding issued permits remain pending until their profile-specific
terminal evidence is authenticated. Crash recovery that would declare an
unused permit requires a separately fenced dispatcher and independent evidence;
it is a later extension, not a timeout rule.

## Command slice: one owned workload

There is currently no general agent-command broker: the runtime's fixed Docker
create/start calls occur outside the records permit. Begin with one deterministic
harmless owned fixture under an immutable Docker image and isolation plan. Bind
the image, argv, working directory, environment policy,
mounts, network policy, resource limits and supervision ownership into the
command contract. Reuse the existing registry rather than adding an arbitrary
shell tool. Registration and a durable CREATE_PENDING marker precede actual
Docker create. Retain the registry's exclusive host lease. Positive ownership
evidence pins the created container ID before start; a name or a process ID alone
is insufficient.

The create and start boundaries need separately accounted external admission.
STOP between them prevents start. An uncertain create must remain recoverable
by its exact ownership record, and must not be replaced by a second create.
The separate external Docker profile holds the command reservation unresolved
across the entire owned workload lifecycle. Terminal settlement requires exact
create completion, actual workload quiescence and completion of all associated
host callbacks. External STOP acknowledgement must preserve STOP_PENDING until
those conditions are verified. Killing a Docker client does not cancel a request
already submitted to the daemon; present absence cannot prove that a delayed
create will never appear. Timeout and unconfirmed create preserve pending state.
A local revocation acknowledgement, process exit code or finished Docker client
call alone cannot settle that condition.

The existing runtime `_revoke()` path expects the legacy REVOKED receipt. The
external record receiver deliberately rejects receiver-side revoke, so this path
must not be relabelled as external STOP. A new root-bound operator route and
profile-specific settlement are necessary before connecting lifecycle cleanup.

| Planned case | Trigger | Required measured result |
|---|---|---|
| `command_positive` | Valid exact grant and immutable fixture. | One owned workload starts; its expected synthetic output is observed; final quiescence is separately verified. |
| `command_binding_swap` | Change argv, image, environment policy or mount after approval. | No Docker create/start; exact binding rejection. |
| `command_stop_before_create` | External STOP acknowledged before admission. | No create/start; old grant cannot obtain a permit. |
| `command_stop_between_create_start` | Stop after owned create but before start admission. | No worker execution; created object is independently recovered and verified stopped. |
| `command_pending_launch_stop` | Hold launch response after reservation. | STOP_PENDING while outcome is uncertain; no duplicate launch. |
| `command_lost_launch_response` | Create/start succeeds, response is lost and dispatcher crashes. | One original workload; restart observes/reconciles it without redispatch. |
| `command_restore_local_state` | Restore pre-launch registry/dispatcher state while authority remains intact. | Consumed action/attempt cannot obtain another external permit; ownership uncertainty remains explicit. |
| `command_descendant_cleanup` | Fixture creates an owned descendant and ignores graceful stop. | Forced recovery targets only the matching ownership; zero-survivor claim requires fresh process/container observations. |
| `command_observation_unavailable` | Trusted inspection or recovery is unavailable. | UNKNOWN and STOP_PENDING; no quiescence claim from elapsed timeout. |
| `command_authority_restart_outage` | Restart the original authority, then remove its route. | Durable consumption/STOP survive restart; outage permits no new launch. |

The first implemented command slice narrows `command_restore_local_state` to
the worker dispatcher's proposal cache. The trusted supervisor and registry
remain outside that rollback domain. Their rollback is unsupported; this
experiment does not establish recovery from erased callback/ownership history.
See the command profile for the actual boundary and evidence requirements.

Do not claim arbitrary shell support, exactly-once arbitrary effects,
unrestricted host process control, kernel isolation or cancellation of Python
callback threads. Preserve the existing distinction between broker
fencing, receiver reconciliation and owned workload cleanup described in
[Docker fault experiments](AGENT_CONTROL_DOCKER_FAULTS.md).

## Network slice: one owned request

Begin with one exact request to a synthetic owned endpoint, with no redirects,
secret injection, automatic retries or application-level forwarding. Bind the
method, endpoint, path, headers, body, destination policy and dispatcher identity
to the grant. Persist the external reservation before invoking the transport.
Observe the endpoint's actual durable effect independently of the gateway's
return value. HTTP RETURNED and remote COMMITTED remain distinct fields.

The existing gateway does not open sockets. Its trusted host supplies resolver
and transport callbacks, and `_stage()` is the relevant admission seam. The
strict public-address policy rejects loopback, private addresses and IP-literal
destinations. A real local HTTP fixture therefore needs an explicitly separate,
immutable owned-loopback test policy. Its transport connects only to the pinned
local endpoint and exposes no public egress. Do not report synthetic public DNS
results while secretly routing the socket to loopback; that would not test
resolved-address enforcement.

A network dispatch receipt may establish that the sender callback finished.
It cannot settle remote-effect uncertainty unless the owned endpoint supplies
the required authenticated terminal receipt. An endpoint may continue an
accepted operation after the client returns or dies. The initial strong STOP
contract should therefore remain scoped to the synthetic endpoint's explicit
commit model, with unresolved outcomes retaining STOP_PENDING. Support for
ordinary remote APIs requires a different, clearly labelled weaker contract or
additional receiver cooperation.

| Planned case | Trigger | Required measured result |
|---|---|---|
| `network_positive` | Valid exact grant for one fixture request. | One actual request and one durable endpoint effect; authenticated terminal evidence binds both. |
| `network_binding_swap` | Change endpoint, method, headers or body after approval. | No transport dispatch; exact grant mismatch. |
| `network_stop_before_dispatch` | External STOP acknowledged before permit issuance. | No request/effect; old grant cannot revive admission. |
| `network_pending_dispatch_stop` | Hold the request after permit issuance and before endpoint commit. | STOP_PENDING until terminal endpoint evidence; no early STOPPED claim. |
| `network_lost_begin_response` | Authority records a permit but reply is lost. | No automatic dispatch or renewed permit; unresolved reservation remains pending. |
| `network_lost_transport_response` | Endpoint commits, then gateway response is lost. | Independently observed effect count one; result UNKNOWN until authenticated reconciliation; no retry. |
| `network_lost_finish_response` | Terminal settlement succeeds but acknowledgement is lost. | Query repeats observation/settlement only; no second request. |
| `network_restore_consumed_state` | Restore gateway state from before dispatch. | External action/attempt consumption blocks a second request despite restoration. |
| `network_restore_stopped_state` | Restore pre-STOP gateway state and local clock. | External stopped epoch/expiry still deny admission; zero newly dispatched requests. |
| `network_authority_restart_outage` | Restart original authority, then interrupt its route. | Consumption and STOP survive restart; outage yields no fresh transport call. |
| `network_ambiguous_endpoint` | Endpoint evidence is unavailable or cannot bind the exact operation. | Remote effect remains UNKNOWN; no invented zero count or terminal settlement. |
| `network_cross_profile_receipt` | Supply records/command or altered endpoint terminal proof. | Settlement rejected; permit remains unresolved. |

Adding redirects, DNS calls or secret lookup later requires stage identities,
exact bindings, budgets and fresh external admission for each relevant stage.
An overall action reservation alone must not let a later redirect bypass STOP.
Worker-side direct sockets must be excluded by the actual isolation boundary;
the SDK's `DirectSocketGuard` hook alone does not establish full mediation.

## Reinforcement and evidence gates

Reinforcement preferences, orientation scores and observer agreement supply
diagnostics or training examples. They never grant, renew or broaden permission,
clear UNKNOWN, refund consumed capacity or override STOP. A preference for
honesty is evaluated against the recorded operation and consequence, including
cases where disclosure prevents apparent task success.

Each follow-on needs a versioned case matrix before execution, exact source and
configuration identity, bounded process/socket cleanup, independent effect
inventories and an offline verifier that does not reuse the implementation's
decision helper. Reports preserve original errors, pending reservations,
unavailable observations and explicit NOT_RUN/SKIPPED states. A fixture checker
passing an expected UNKNOWN case is not an agent success or safety score.

Publish implementation and evidence as a reviewable draft. A passing finite
synthetic matrix supports only its stated command or owned-endpoint contract;
it does not establish universal agent containment, learned corrigibility or
production deployment.
