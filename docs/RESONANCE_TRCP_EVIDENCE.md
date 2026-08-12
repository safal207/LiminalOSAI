# RESONANCE: Why a Green Test Is Not Enough

> We don't just test whether an agent action succeeded. We verify that the
> intended financial state transition happened, that its evidence is bound to
> the workload, and that tampering is independently detectable.

## The trap

A classic integration test asks: *"did the call return success?"* Green means
the SDK reported a happy path. For a financial AI agent that is the wrong
question, and it fails in a specific way:

- the **agent's own word** is the only evidence — the tool call and its result
  live in the same process that produced them;
- a *succeeded* call can still mean the **intended state transition did not
  happen** (wrong state reached, invariant broken);
- a *tampered* claim (altered final state, forged violations, swapped task
  identity) is indistinguishable from a true one unless something outside the
  producing process can re-check it.

Green tests optimize for "the code path ran". They do not optimize for "the
world actually moved the way the agent claims".

## What the receipt adds

TRCP produces a digest-first receipt that separates **three things a financial
agent must not conflate**:

1. **Did the intended transition happen?** — the workload result records the
   final contract state and every step; replay rebuilds it from evidence, not
   from memory.
2. **Is the evidence bound to the workload?** — `workload_sha256` covers the
   path, the actors, and the result; the bundle and the receipt chain to that
   digest. Change any one byte and the whole chain breaks.
3. **Is tampering independently detectable?** — the receiver re-executes the
   workload from the evidence and compares hashes, so detection does not
   depend on the honesty of the producer.

The benchmark makes this concrete: 21 scenarios prove stable receipts for
clean, illegal, and invariant workloads; 12 adversarial mutations are all
rejected with the expected failed check and none is ever confirmed as `PASS`.

## Resonance

The point is not "more tests". The point is a **state receipt the agent cannot
co-author with its own success**: evidence produced under one boundary,
verified under another, and stable across independent runs. That is the
difference between a green pipeline and a provable claim about what happened
to the money.

See [docs/benchmark-v0.1.md](benchmark-v0.1.md) for the technical detail and
[`scripts/benchmark_trcp_contract.py`](../scripts/benchmark_trcp_contract.py)
for the reproducible proof.
