"""Check actual callback effects, independent inventory, and subject scope."""
from __future__ import annotations

import copy
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from sdk.liminal_agent_control.authority import ControlError, verify_receipt
from sdk.liminal_agent_control.multi_agent_relay import (
    ARMS, CLIENT_SUBJECT, RELAY_SUBJECT, _grant, _inputs, _request,
    relay_spec, run_relay_scenario,
)
from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_egress_gateway import EgressBlocked, EgressGateway, TransportResponse


class RelayScenarioTests(unittest.TestCase):
    def run_case(self):
        with tempfile.TemporaryDirectory() as temp:
            return run_relay_scenario(Path(temp), b"observer test key never emitted!!" * 2)

    def test_real_sink_effects_distinguish_arms_and_preserve_useful_control(self):
        result = self.run_case()
        self.assertEqual(result["measured"], {
            "outer_only": {"forbidden_effect_count": 1, "useful_effect_count": 1},
            "relay_guarded": {"forbidden_effect_count": 0, "useful_effect_count": 1},
        })
        for arm in ARMS:
            inventory = result["observation"][arm]
            self.assertEqual(inventory["effects"], relay_spec()["arms"][arm]["effects"])
            self.assertTrue(verify_receipt(inventory, b"observer test key never emitted!!" * 2))
            transports = [event for event in result["raw"]["arms"][arm]["callbacks"]
                          if event["stage"] == "sink_transport"]
            self.assertEqual(len(transports), len(inventory["effects"]))
            self.assertEqual([event["body_sha256"] for event in transports],
                             [effect["body_sha256"] for effect in inventory["effects"]])

    def test_forbidden_relay_denial_precedes_its_dns_and_transport(self):
        result = self.run_case()
        guarded = result["raw"]["arms"]["relay_guarded"]
        events = [event for event in guarded["callbacks"] if event["message_id"] == "forbidden"]
        self.assertEqual([event["stage"] for event in events], ["outer_dns", "outer_transport"])
        decisions = guarded["relay_capability_decisions"]
        self.assertEqual(decisions[1]["decision"], "BLOCK")
        self.assertIn("scope_mismatch", decisions[1]["reason_codes"])
        forbidden, useful = guarded["requests"]
        self.assertEqual(forbidden["outer_receipt"]["decision"], "ALLOW")
        self.assertEqual(forbidden["outer_receipt"]["status_code"], 403)
        self.assertEqual(forbidden["relay_outcome"]["status"], "BLOCKED")
        self.assertEqual(useful["relay_outcome"]["receipt"]["decision"], "ALLOW")
        self.assertEqual(useful["outer_receipt"]["status_code"], 202)
        baseline = result["raw"]["arms"]["outer_only"]
        self.assertEqual([event["stage"] for event in baseline["callbacks"]
                          if event["message_id"] == "forbidden"],
                         ["outer_dns", "outer_transport", "relay_dns", "sink_transport"])
        self.assertEqual(baseline["relay_capability_decisions"], [])

    def test_messages_are_identical_between_arms_and_contain_no_authority(self):
        result = self.run_case()
        arms = result["raw"]["arms"]
        for message in result["raw"]["inputs"]:
            self.assertEqual(set(message), {"message_id", "target", "payload"})
        for left, right in zip(arms["outer_only"]["requests"], arms["relay_guarded"]["requests"]):
            self.assertEqual(left["outer_request"], right["outer_request"])
            self.assertEqual(left["relay_outcome"]["request"], right["relay_outcome"]["request"])
            self.assertEqual(left["outer_request"]["subject_id"], CLIENT_SUBJECT)
            self.assertEqual(left["relay_outcome"]["request"]["subject_id"], RELAY_SUBJECT)

    def test_scoped_grant_cannot_be_used_by_the_other_participant(self):
        for outer in (True, False):
            with self.subTest(outer=outer):
                broker = CapabilityBroker()
                broker.admit(_grant("relay_guarded", "outer" if outer else "relay"), at_unix=100)
                callbacks = []
                gateway = EgressGateway(
                    broker=broker,
                    resolver=lambda host: callbacks.append("dns") or ["93.184.216.34"],
                    transport=lambda request: callbacks.append("transport") or TransportResponse(200, {}, "a" * 64),
                    clock=lambda: 120,
                )
                request = replace(_request(_inputs()[1], outer=outer),
                                  subject_id=RELAY_SUBJECT if outer else CLIENT_SUBJECT)
                with self.assertRaisesRegex(EgressBlocked, "no_matching_capability"):
                    gateway.execute(request)
                self.assertEqual(callbacks, [])

    def test_inventory_tampering_fails_authentication_and_key_is_not_exported(self):
        result = self.run_case()
        inventory = copy.deepcopy(result["observation"]["outer_only"])
        inventory["effects"].clear()
        self.assertFalse(verify_receipt(inventory, b"observer test key never emitted!!" * 2))
        self.assertNotIn("observer test key", json.dumps(result))
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ControlError):
                run_relay_scenario(Path(temp), b"short")

    def test_fixture_does_not_open_sockets(self):
        with patch("socket.socket", side_effect=AssertionError("real socket forbidden")), \
             patch("socket.getaddrinfo", side_effect=AssertionError("real DNS forbidden")):
            result = self.run_case()
        self.assertEqual(result["measured"]["outer_only"]["forbidden_effect_count"], 1)


if __name__ == "__main__":
    unittest.main()
