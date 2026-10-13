# Closed launch channels for the owned record workflow

The concrete workflow is the source-pinned agent fixture, its bounded STDIO
bridge, and one exact synthetic record endpoint. A complete channel inventory
is required before launch. It is configuration evidence; every action still
requires its exact host grant and a fresh external one-shot BEGIN.

`ClosedChannelAgentSupervisor` stores the immutable contract under a distinct
store schema. A legacy ungated supervisor cannot reopen that store. The
concrete isolated-agent demonstration uses this supervisor and the bound
`ClosedChannelLaunchGate`; legacy lower-level APIs remain reference fixtures.

| Channel | Treatment | Enforcement |
|---|---|---|
| Direct worker networking | Denied | Actual Docker network `none`; no extra DNS, ports or shared namespace |
| Fixture workspace | Read only | Exact mount, regular source-pinned fixture, no extra files |
| Host filesystem | Denied | No extra host mounts or inherited volumes |
| Control sockets and devices | Denied | No device, socket mount or device-request routes |
| Namespace overrides | Restricted | Private PID/IPC/UTS/cgroup; user namespace isolation is not established |
| Worker-local processes and tmpfs | Confined | Existing PID/CPU/memory/tmpfs limits and owned process census |
| STDIO proposals | Mediated | Exact host allowlist, lineage, observation, authority and budgets |
| STDIO claims | Observation only | Cannot create permission or settle an effect |
| STDERR | Observation only | Bounded bytes, no automatic execution or publication |
| Host CREATE/START | Mediated | Exact plan, independent permit, launch gate and watchdog |
| Host endpoint effect | Mediated | Exact route/action, external BEGIN and endpoint receipt |
| Authority control | Trusted control | Pinned identity and fixed authenticated loopback routes |
| Watchdog, STOP and reconciliation | Trusted control | Durable fence; fresh completed watcher cycle; no redispatch |
| Model, MCP, host shell and external delegation | Denied | No route exists in the fixed inventory/bridge |

Missing channels, extra channels, unmediated external routes or changed
bindings reject the inventory. The gate binds the actual coordinator,
supervisor, bridge, gateway, controller and service clients once, and rejects
replaced routes or altered configuration. A worker never supplies these
objects, the inventory, signing keys or Docker access.

Before CREATE/START admission, the supervisor requires an open durable fence
and a ready, alive watcher with a completed cycle less than two seconds old.
An alive thread with a stale heartbeat is insufficient. The dispatch boundary
checks again; START also repeats actual Docker and fixed-image configuration
validation immediately before the attached CLI starts. Every effect proposal
requires another actual owned-process observation and channel check.
This gate controls fresh bridge callback admission. It does not cancel an
already admitted HTTP request or add a final endpoint commit gate.

The inspected channel projection is public diagnostic evidence. Its source is
the trusted host's Docker inspection, not an independent live signature. The
offline artifact verifier checks this projection and the immutable inventory
alongside the existing signed controller/endpoint evidence.

## Validation

The mandatory isolated-agent CI job runs the channel, launch and watcher
regressions and the existing twelve-case actual Docker matrix without skips.
Negative unit tests use explicit host/Docker doubles to check rejection and
dispatch counters; these are not new kernel-containment measurements.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=sdk python3 -m unittest \
  tests.test_agent_control_external_agent_launch \
  tests.test_agent_control_external_agent_channels \
  tests.test_agent_control_external_agent_watcher_health -v
```

Use the reproduction commands in [the isolated-agent guide](AGENT_CONTROL_ISOLATED_AGENT.md)
for the real Docker report and its verifier. Report claims must be bound to the
exact source revision and actual execution result.

## Limits

Completeness is bounded to this fixed fixture, Docker profile and examined
host entrypoints. It does not discover arbitrary hidden channels in a new
tool, model adapter or image. Each extension requires a new explicit inventory
and enforcement review; adding a manifest entry does not implement a gate.

The approved immutable image, host, daemon, clocks and control stores remain
trusted. Matching image environment bytes proves consistency, not absence of
embedded credentials. Worker-local sockets and descendants are allowed
internal resources, without external authority.

The watcher is an in-process thread. Its readiness requirement does not prove
survival of the entire host process, independent administration, kernel escape
resistance or trusted-store rollback protection. Already admitted effects may
finish after STOP and remain UNKNOWN/STOP_PENDING until independent evidence
settles them. No live LLM or training is part of this experiment.
