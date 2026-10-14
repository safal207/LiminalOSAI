"""Exercise uncertainty through the real layered effect stack and durable store."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sdk.liminal_causal_effect_commit import (
    CausalBoundEffectRuntimeMediator,
    verify_commit_receipt as verify_causal,
)
from sdk.liminal_durable_governance_fence import (
    DurableGovernanceError,
    DurableGovernanceRuntimeMediator,
    verify_commit_receipt as verify_durable,
)
from sdk.liminal_effect_commit import (
    EpochBoundEffectRuntimeMediator,
    verify_commit_receipt as verify_effect,
)
from sdk.liminal_objective_effect_commit import (
    ObjectiveBoundEffectRuntimeMediator,
    verify_commit_receipt as verify_objective,
)
from sdk.liminal_runtime_mediation import ExecutionOutcomeUnknown
from tests.test_durable_governance_commit_fence import (
    ADAPTER_TOKEN,
    ROOT,
    authorize,
    operation,
    proposal,
    setup_stack,
)


class UncertainEffectOutcomeTests(unittest.TestCase):
    def test_diagnostic_store_failure_does_not_erase_effect_uncertainty(self):
        with tempfile.TemporaryDirectory() as directory:
            stack = setup_stack(str(Path(directory) / "governance.db"))
            _, _, _, _, epoch, _, _, _, ledger, _, store, _, durable, _ = stack
            mediator = DurableGovernanceRuntimeMediator(
                broker=epoch, durable_effect_broker=durable,
                adapter_token=ADAPTER_TOKEN,
                proposal_factory=lambda op, cap, journal: proposal(journal, op, cap),
            )
            original_read = store.read_state
            diagnostic_failure = False

            def read_state(**kwargs):
                if diagnostic_failure:
                    raise OSError("diagnostic store unavailable")
                return original_read(**kwargs)

            def uncertain_executor(_):
                nonlocal diagnostic_failure
                diagnostic_failure = True
                raise ExecutionOutcomeUnknown("terminal state unavailable")

            with patch.object(store, "read_state", side_effect=read_state):
                result = mediator.mediate(operation(), uncertain_executor)
            self.assertEqual(result["execution_outcome"], "UNKNOWN")
            self.assertTrue(original_read(root_id=ROOT)["reservation_active"])
            self.assertEqual(ledger.event_count, 0)

    def test_unknown_crosses_all_brokers_and_preserves_durable_reservation(self):
        with tempfile.TemporaryDirectory() as directory:
            stack = setup_stack(str(Path(directory) / "governance.db"))
            _, _, _, _, epoch, effect, guard, objective, ledger, causal, store, _, durable, _ = stack
            op = operation()
            capability = authorize(epoch, op)
            lease_id, _ = durable.issue_for_trusted_adapter(
                operation=op,
                capability_decision=capability,
                objective_decision=guard.evaluate_operation(op),
                proposed_event=proposal(ledger, op, capability),
            )
            callbacks = []

            def uncertain_executor(_):
                callbacks.append("entered")
                raise ExecutionOutcomeUnknown("secret path/token must remain private")

            with self.assertRaises(ExecutionOutcomeUnknown):
                durable.consume_for_trusted_adapter(
                    lease_id, adapter_token=ADAPTER_TOKEN, executor=uncertain_executor,
                )
            for broker, verifier, expected in (
                (effect, verify_effect, "UNKNOWN"),
                (objective, verify_objective, "UNKNOWN"),
                (causal, verify_causal, "UNKNOWN"),
                (durable, verify_durable, "EFFECT_UNKNOWN_RESERVATION_STUCK"),
            ):
                receipt = broker.commit_receipts()[-1]
                self.assertEqual(receipt["effect_outcome"], expected)
                self.assertEqual(verifier(receipt), receipt)
                self.assertNotIn("secret path/token", repr(receipt))
            state = store.read_state(root_id=ROOT)
            self.assertTrue(state["reservation_active"])
            self.assertEqual(state["generation"], 0)
            self.assertEqual(ledger.event_count, 0)
            with self.assertRaisesRegex(DurableGovernanceError, "durable_lease_replayed"):
                durable.consume_for_trusted_adapter(
                    lease_id, adapter_token=ADAPTER_TOKEN, executor=uncertain_executor,
                )
            self.assertEqual(callbacks, ["entered"])

    def test_mediators_report_unknown_instead_of_failed(self):
        for layer in ("epoch", "objective", "causal", "durable"):
            with self.subTest(layer=layer), tempfile.TemporaryDirectory() as directory:
                stack = setup_stack(str(Path(directory) / "governance.db"))
                _, _, _, _, epoch, effect, _, objective, ledger, causal, _, _, durable, _ = stack
                common = {"broker": epoch, "adapter_token": ADAPTER_TOKEN}
                factory = lambda op, cap, journal: proposal(journal, op, cap)
                if layer == "epoch":
                    mediator = EpochBoundEffectRuntimeMediator(
                        effect_commit_broker=effect, broker=epoch,
                    )
                elif layer == "objective":
                    mediator = ObjectiveBoundEffectRuntimeMediator(
                        objective_effect_broker=objective, **common,
                    )
                elif layer == "causal":
                    mediator = CausalBoundEffectRuntimeMediator(
                        causal_effect_broker=causal, proposal_factory=factory, **common,
                    )
                else:
                    mediator = DurableGovernanceRuntimeMediator(
                        durable_effect_broker=durable, proposal_factory=factory, **common,
                    )

                def uncertain_executor(_):
                    raise ExecutionOutcomeUnknown("unobserved terminal state")

                result = mediator.mediate(operation(), uncertain_executor)
                self.assertEqual(result["admission_decision"], "ALLOW")
                self.assertEqual(result["execution_outcome"], "UNKNOWN")
                self.assertIn("reconciliation_required", result["reason_codes"])
                self.assertEqual(ledger.event_count, 0)


if __name__ == "__main__":
    unittest.main()
