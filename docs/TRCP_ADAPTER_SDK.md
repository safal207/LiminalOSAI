# TRCP Adapter SDK v0.1

The public Adapter SDK turns a small external workload adapter into a
deterministic TRCP evidence bundle and typed binding receipt:

```text
external request -> normalize -> workload evidence -> binding verification
                                                      -> deterministic receipt
                         optional execution replay ---^ (reported separately)
```

Use only `sdk.liminal_trcp.sdk` from consumer code. Modules such as
`adapter.py`, `evidence.py`, `replay.py`, and the simulator are core
implementation details, not the integration contract.

## Five-minute integration

1. Add one adapter with a stable lowercase `consumer_type`.
2. Implement `normalize(external_input)` and return `normalize_workload(...)`.
3. Call `run_external_workload(adapter, request)`.
4. Require `result.binding_receipt.result == "PASS"` and retain the receipt
   and bundle hashes with your audit record.

```python
from collections.abc import Mapping
from typing import Any

from sdk.liminal_trcp.sdk import normalize_workload, run_external_workload


def execute_locally(request: Mapping[str, Any]) -> dict[str, Any]:
    return {"status": "RESERVED", "order_id": request["order_id"]}


class OrderAdapter:
    consumer_type = "example-order-system"

    def normalize(self, request: Mapping[str, Any]) -> dict[str, Any]:
        return normalize_workload(
            consumer_type=self.consumer_type,
            requested_operation=request["operation"],
            actor=request["actor"],
            input_data=request,
            result=execute_locally(request),
        )


result = run_external_workload(
    OrderAdapter(),
    {
        "operation": "reserve",
        "actor": "order-service",
        "order_id": "order-1001",
    },
)

assert result.binding_receipt.result == "PASS"
print(result.workload_sha256)
print(result.bundle_sha256)
print(result.receipt_sha256)
```

No inheritance, task construction, provider fixture, or replay-core import is
required. See the runnable
[`examples/trcp_external_consumer_reference/self_check.py`](../examples/trcp_external_consumer_reference/self_check.py)
for a complete order-reservation adapter:

```sh
python -m examples.trcp_external_consumer_reference.self_check
python -m examples.trcp_external_consumer_reference.self_check --execution-replay
```

The first command reports `NOT_RUN` for execution replay; the binding receipt
still reports `PASS`. The second invokes the consumer-owned replay hook and
reports its result separately.

## Normalized workload contract

`NORMALIZED_WORKLOAD_SCHEMA` is `generic-workload-evidence-v0.1`. The exact
hash closure contains six fields:

| Field | Meaning |
| --- | --- |
| `schema` | Versioned normalized contract identifier |
| `consumer_type` | Stable adapter type, matching `adapter.consumer_type` |
| `requested_operation` | One operation or a non-empty list of operations |
| `actor` | One actor or a non-empty list of actors |
| `input` | Canonical JSON copy of the external input |
| `result` | Canonical JSON copy of the consumer result |

The schema is closed: missing or extra fields are rejected. Values must be
canonical JSON data; sets, bytes, custom objects, `NaN`, and infinity are
rejected. Each normalized JSON value is capped at 900,000 encoded bytes and a
maximum nesting depth of 64 so the resulting evidence bundle remains bounded.
The helper deep-copies through JSON so later caller mutations do not change the
normalized artifact.

The SDK creates the deterministic synthetic task and fixture reference. If a
consumer needs the intermediate artifact, use:

```python
workload_evidence = build_workload_evidence(normalized_workload)
```

Its `workload_sha256` commits to the six normalized fields. The bundle and
receipt hashes commit to their respective canonical artifacts. Identical
input and deterministic normalization produce identical hashes; changing a
bound input or result changes the downstream hashes.

## Binding verification and tamper handling

`verify_binding(bundle)` returns an immutable `BindingReceipt`. A verifier
finding is data, not an exception: tampered evidence produces a typed receipt
with `result == "FAIL"`, `failed_check`, and a deterministic
`receipt_sha256`. Invalid SDK call shapes raise one of the stable public error
types:

- `AdapterContractError`: invalid adapter, input, or consumer identity;
- `WorkloadNormalizationError`: invalid normalized or non-JSON workload;
- `BindingVerificationError`: a bundle/receipt cannot be decoded or verified;
- `TRCPAdapterError`: common base error.

```python
receipt = verify_binding(result.evidence_bundle)
assert receipt == result.binding_receipt
```

Never edit a bundle after creation. Persist the exact evidence bundle and use
the receipt's `source_bundle_sha256` to associate them.

## Optional execution replay

Binding verification proves evidence integrity and workload-to-task/provider
binding. It does not re-run the external business system. An adapter may add:

```python
def replay_execution(self, normalized_workload):
    return execute_locally(normalized_workload["input"])
```

Then request it with
`run_external_workload(adapter, request, execution_replay=True)`. The public
status values are:

- `NOT_RUN`: execution replay was not requested;
- `UNSUPPORTED`: requested, but the adapter has no hook;
- `PASS`: hook output matches the bound result;
- `MISMATCH`: hook output differs from the bound result;
- `ERROR`: the hook raised an exception.

Execution status never changes the binding receipt or its hash. Consumers
should make their own policy decision about `MISMATCH` or `ERROR` rather than
interpreting a binding `PASS` as proof that execution replay passed.

## Trust and data boundary

This v0.1 integration is deterministic, local-only, and synthetic: it does
not contact providers or real targets and does not grant capabilities.
However, adapter and replay-hook code runs as ordinary Python in the caller's
process. The SDK does **not** sandbox, authenticate, or authorize that code.

The normalized `input` and `result` are embedded in workload evidence and the
evidence bundle. Do not pass secrets, credentials, personal data, proprietary
payloads, or anything that should not be retained in an audit artifact.
Redact/minimize data before calling the adapter, and store bundles according
to the sensitivity of their contents.

## Public surface

The stable v0.1 module exports version/schema constants, the two structural
protocols (`ExternalWorkloadAdapter`, `ExecutionReplayHook`), typed result and
receipt dataclasses, the four public errors, and these functions:

- `normalize_workload(...)`
- `build_workload_evidence(normalized_workload)`
- `verify_binding(evidence_bundle)`
- `run_external_workload(adapter, external_input, execution_replay=False)`

Run the focused compatibility suite with `make trcp-sdk-test`.
