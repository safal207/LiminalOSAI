# TRCP Semantic Mutation Checks

TRCP separates four different verification questions that must not be collapsed into one claim.

| Layer | Question | Typical observable |
| --- | --- | --- |
| Byte/evidence tamper | Did the bound artifact bytes change after creation? | binding `FAIL`, failed integrity check |
| Binding verification | Are workload, task/provider references, evidence and receipt internally consistent under the registered contract? | binding `PASS` / `FAIL` + deterministic receipt |
| Semantic mutation | Does a materially wrong business/policy rule change at least one discriminating outcome? | changed result/hash identity and/or replay `MISMATCH` |
| Execution replay | Does consumer-owned re-execution reproduce the result that was bound into evidence? | `NOT_RUN`, `UNSUPPORTED`, `PASS`, `MISMATCH`, `ERROR` |

## Why semantic mutation is separate

A producer can apply a wrong business rule and still construct a perfectly self-consistent evidence bundle. In that case binding verification may correctly return `PASS`: binding is proving consistency, not business correctness.

Semantic mutation testing asks a different question:

```text
material rule
    ↓ mutate
meaningfully wrong alternative
    ↓
discriminating vector
    ↓
observable result / receipt identity / replay status must move
```

If a material rule changes and no observable verification outcome moves, the test suite may be deterministic yet semantically deaf to that rule.

## Current local mutation catalog

`tests/test_trcp_semantic_mutation.py` defines three LOCAL_ONLY / SYNTHETIC_ONLY mutants against a small order-state consumer:

1. `exclusive_upper_bound` — incorrectly changes `quantity <= available` to `quantity < available`;
2. `accept_any_operation` — incorrectly lets a non-reserve operation enter the reserve path;
3. `mutate_on_reject` — incorrectly changes state for a rejected operation.

Each mutant has:

- one discriminating vector that must change the normalized result and public artifact hashes;
- one neutral vector showing the mutant is not merely always-on output noise;
- an independent execution-replay check where baseline evidence remains binding `PASS` but the mutated re-execution must report `MISMATCH`;
- a repeated-run determinism check.

Run the focused suite with:

```sh
python -m unittest tests/test_trcp_semantic_mutation.py -v
```

A surviving mutant fails the unit test under a `subTest` carrying both the mutant name and the expected discriminating vector, so CI exits non-zero and identifies the semantic gap.

## Boundary

These tests do not prove production correctness, independent remote execution, provider safety, wallet safety, or a percentage of system safety. They only verify that the defined local semantic mutants are observable under the defined vectors.
