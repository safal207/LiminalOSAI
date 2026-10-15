"""Actual bounded observer subprocesses; fixture statements never authorize effects."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.authority import canonical_bytes, digest
from sdk.liminal_agent_control.observer_auth import ATTESTATION_DOMAIN, sign_attestation
from sdk.liminal_agent_control import observer_process as worker


def fixtures(role="reality"):
    center = {"windows": [{"center_id": "window-1", "previous_center_id": None,
                           "starts_at": 100, "ends_at": 200, "center_nodes": ["center"]}],
              "max_past_age_seconds": 100, "max_future_horizon_seconds": 40,
              "max_transition_seconds": 40, "max_away_seconds": 90, "max_idle_seconds": 90,
              "progress_edge_ids": ["out"], "max_ideas": 30}
    edge = {"edge_id": "out", "source": "center", "destination": "work", "channel": "egress"}
    graph = {"nodes": [{"node_id": node, "space_id": "owned", "phase": node} for node in ("center", "work")],
             "edges": [edge, {"edge_id": "back", "source": "work", "destination": "center", "channel": "egress"}],
             "center_nodes": ["center"], "max_steps": 20, "max_visits": 10, "max_away_steps": 10,
             "max_observation_age_seconds": 100, "observers": {"records": "receiver", "egress": "sink"}}
    after = {"node_id": "center", "revision": 0, "last_observed_at": 100,
             "last_progress_at": 100, "away_since": None, "pending_action_id": None,
             "checkpoint_center_id": "window-1"}
    event = {"root_id": "root", "execution_id": "agent", "epoch": 1,
             "profile_digest": digest(center), "orientation_profile_digest": digest(graph),
             "sequence": 1, "parent_hash": "0" * 64, "kind": "SEED", "center_id": "window-1",
             "recorded_at": 100, "details": {"evidence_digest": digest("owned-seed")}, "state_after": after}
    event["event_hash"] = digest(event)
    state = {**after, "root_id": "root", "execution_id": "agent", "head_hash": event["event_hash"],
             "sequence": 1, "hold_reason": None}
    projection = {"action_id": "action", "root_id": "root", "execution_id": "agent", "epoch": 1,
                  "action_digest": digest("action"), "edge_id": "out", "expected_revision": 0,
                  "predecessor_hash": event["event_hash"], "idea_id": "idea", "not_before": 100,
                  "deadline": 120, "center_id": "window-1", "profile_digest": digest(center),
                  "orientation_profile_digest": digest(graph), "created_at": 100}
    request = {"schema": "liminal-observer-challenge-v1", "nonce": digest("nonce-" + role),
               "issued_at": 100, "valid_until": 110, "observer_id": role + "-observer",
               "role": role, "key_id": role + "-key", "ring_profile_digest": digest("ring"),
               "auth_profile_digest": digest("auth"), "policy_digest": digest("policy"),
               "objective_digest": digest("objective"), "projection_digest": digest(projection)}
    for name in ("action_id", "root_id", "execution_id", "epoch", "action_digest", "center_id",
                 "predecessor_hash", "orientation_profile_digest"):
        request[name] = projection[name]
    evidence = {"reality": {"projection": projection, "state": state, "edge": edge},
                "continuity": {"projection": projection, "events": [event]},
                "projection": {"projection": projection, "center_profile": center,
                               "orientation_profile": graph, "state": state}}[role]
    return request, evidence


class ObserverProcessTests(unittest.TestCase):
    def run_role(self, role="reality", **options):
        request, evidence = fixtures(role)
        options.setdefault("private_key", bytes([1 + list(("reality", "continuity", "projection")).index(role)]) * 32)
        options.setdefault("evidence", evidence)
        return worker.run_observer(request, **options)

    def assert_hold(self, result, reason):
        self.assertIsNone(result["envelope"])
        self.assertEqual(result["process"]["status"], "HOLD")
        self.assertEqual(result["process"]["reason"], reason)
        self.assertFalse(result["execution_authorized"])

    def assert_reaped(self, result):
        self.assertIsInstance(result["process"]["pid"], int)
        self.assertIsInstance(result["process"]["exit_code"], int)
        with self.assertRaises(ProcessLookupError):
            os.kill(result["process"]["pid"], 0)

    def test_three_roles_are_actual_distinct_processes_and_sign_exact_evidence(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        pids = set()
        for index, role in enumerate(("reality", "continuity", "projection"), 1):
            request, evidence = fixtures(role)
            private_key = bytes([index]) * 32
            result = worker.run_observer(request, private_key=private_key, evidence=evidence)
            self.assertEqual(result["process"]["status"], "PASS")
            self.assertEqual(result["process"]["exit_code"], 0)
            self.assertEqual(result["process"]["role"], role)
            self.assertEqual(result["envelope"]["verdict"], "SUPPORT")
            self.assertEqual(result["envelope"]["request"], request)
            self.assertEqual(result["envelope"]["evidence_digest"], digest(evidence))
            self.assertFalse(result["execution_authorized"])
            self.assert_reaped(result)
            pids.add(result["process"]["pid"])
            envelope = result["envelope"]
            body = {key: value for key, value in envelope.items() if key != "signature"}
            Ed25519PrivateKey.from_private_bytes(private_key).public_key().verify(
                bytes.fromhex(envelope["signature"]), ATTESTATION_DOMAIN + canonical_bytes(body))
        self.assertEqual(len(pids), 3)

    def test_key_only_in_stdin_not_argv_environment_report_or_metadata(self):
        private_key, authority_path = bytes([211]) * 32, "/private/authority-do-not-pass.sqlite"
        original_popen, original_exchange = subprocess.Popen, worker._exchange
        calls, wires = [], []

        def spawn(*args, **kwargs):
            calls.append((args, kwargs))
            return original_popen(*args, **kwargs)

        def exchange(process, wire, timeout):
            wires.append(wire)
            return original_exchange(process, wire, timeout)

        with patch.dict(os.environ, {"AUTHORITY_DATABASE": authority_path,
                                      "OTHER_OBSERVER_KEY": "another-observer-secret",
                                      "PYTHONPATH": "/untrusted-import-path"}), \
                patch.object(worker.subprocess, "Popen", side_effect=spawn), \
                patch.object(worker, "_exchange", side_effect=exchange):
            result = self.run_role(private_key=private_key)
        self.assertEqual(result["process"]["status"], "PASS")
        wire = json.loads(wires[0])
        self.assertEqual(wire["private_key"], private_key.hex())
        self.assertEqual(set(wire), {"request", "evidence", "private_key"})
        for value in (repr(calls), json.dumps(result)):
            self.assertNotIn(private_key.hex(), value)
            self.assertNotIn(authority_path, value)
            self.assertNotIn("another-observer-secret", value)
            self.assertNotIn("/untrusted-import-path", value)
        self.assertNotIn(authority_path.encode(), wires[0])
        self.assertFalse(calls[0][1]["shell"])
        self.assertTrue(calls[0][1]["close_fds"])
        self.assertTrue(calls[0][1]["start_new_session"])
        self.assertEqual(set(calls[0][1]["env"]), {"LC_ALL"})

    def test_malformed_challenges_are_rejected_before_process_creation(self):
        request, evidence = fixtures()
        malformed = []
        for key, value in (("schema", "other"), ("nonce", "bad"), ("issued_at", float("nan")),
                           ("epoch", True), ("role", "agent"), ("valid_until", 100)):
            item = copy.deepcopy(request)
            item[key] = value
            malformed.append(item)
        extra = copy.deepcopy(request)
        extra["command"] = "untrusted"
        malformed.extend([extra, {}, None])
        with patch.object(worker.subprocess, "Popen") as spawn:
            for value in malformed:
                with self.subTest(value=value):
                    self.assert_hold(worker.run_observer(value, private_key=b"x" * 32, evidence=evidence),
                                     "OBSERVER_PROCESS_INPUT_INVALID")
            spawn.assert_not_called()

    def test_input_and_timeout_budgets_fail_closed(self):
        request, evidence = fixtures()
        with patch.object(worker.subprocess, "Popen") as spawn:
            oversized = {"padding": "x" * worker.MAX_PUBLIC_INPUT_BYTES}
            self.assert_hold(worker.run_observer(request, private_key=b"x" * 32, evidence=oversized),
                             "OBSERVER_PROCESS_INPUT_LIMIT")
            for timeout in (0, -1, 11, float("inf"), float("nan"), True):
                self.assert_hold(self.run_role(timeout_seconds=timeout), "OBSERVER_PROCESS_INPUT_INVALID")
            for key in (b"short", b"x" * 33, "x" * 32):
                self.assert_hold(self.run_role(private_key=key), "OBSERVER_PROCESS_INPUT_INVALID")
            spawn.assert_not_called()

    def test_missing_evidence_is_signed_unknown_and_not_support(self):
        for role in ("reality", "continuity", "projection"):
            result = self.run_role(role, evidence={})
            self.assertEqual(result["process"]["status"], "PASS")
            self.assertEqual(result["envelope"]["verdict"], "UNKNOWN")

    def test_changed_projection_is_signed_veto(self):
        request, evidence = fixtures()
        evidence["projection"]["action_id"] = "another-action"
        result = worker.run_observer(request, private_key=b"x" * 32, evidence=evidence)
        self.assertEqual(result["envelope"]["verdict"], "VETO")
        self.assertEqual(result["envelope"]["request"], request)

    def test_reality_rejects_unobserved_position_revision_pending_and_future_fact(self):
        request, evidence = fixtures()
        for key, value in (("node_id", "work"), ("revision", 1), ("pending_action_id", "unobserved"),
                           ("hold_reason", "STOPPED"), ("last_observed_at", 101), ("head_hash", digest("forged"))):
            modified = copy.deepcopy(evidence)
            modified["state"][key] = value
            with self.subTest(field=key):
                self.assertEqual(worker.evaluate_fixture(request, modified)[0], "VETO")

    def test_continuity_rejects_hash_gap_reverse_time_and_foreign_history(self):
        request, evidence = fixtures("continuity")
        for key, value in (("sequence", 2), ("parent_hash", digest("gap")), ("recorded_at", 101),
                           ("root_id", "foreign"), ("epoch", 2)):
            modified = copy.deepcopy(evidence)
            event = modified["events"][0]
            event[key] = value
            event["event_hash"] = digest({field: content for field, content in event.items() if field != "event_hash"})
            with self.subTest(field=key):
                self.assertEqual(worker.evaluate_fixture(request, modified)[0], "VETO")
        malformed = copy.deepcopy(evidence)
        malformed["events"] = [None]
        self.assertEqual(worker.evaluate_fixture(request, malformed)[0], "UNKNOWN")

    def test_projection_checks_profile_digest_expiry_and_two_sided_time_limits(self):
        request, evidence = fixtures("projection")
        for profile in ("center_profile", "orientation_profile"):
            modified = copy.deepcopy(evidence)
            modified[profile]["untrusted"] = True
            self.assertEqual(worker.evaluate_fixture(request, modified)[0], "VETO")
        for changes in ({"checkpoint_center_id": "old-window"}, {"last_progress_at": 0},
                        {"away_since": 0}):
            modified = copy.deepcopy(evidence)
            modified["state"].update(changes)
            self.assertEqual(worker.evaluate_fixture(request, modified)[0], "VETO")
        request["valid_until"] = 121
        self.assertEqual(worker.evaluate_fixture(request, evidence)[0], "VETO")

    def test_future_or_malformed_observation_never_backdates_a_support(self):
        request, evidence = fixtures()
        for value in (99, 110, "100", True):
            modified = copy.deepcopy(evidence)
            modified["observed_at"] = value
            verdict, _, observed = worker.evaluate_fixture(request, modified)
            self.assertEqual(verdict, "UNKNOWN")
            self.assertEqual(observed, request["issued_at"])

    def test_actual_timeout_kills_and_reaps_worker(self):
        result = self.run_role(timeout_seconds=0.000001)
        self.assert_hold(result, "OBSERVER_PROCESS_TIMEOUT")
        self.assert_reaped(result)

    def fail_worker(self, code, expected_reason):
        with patch.object(worker, "_worker_command", return_value=[sys.executable, "-I", "-c", code]):
            result = self.run_role()
        self.assert_hold(result, expected_reason)
        self.assert_reaped(result)
        return result

    def test_malformed_response_is_not_attested(self):
        self.fail_worker("print('not json')", "OBSERVER_PROCESS_REPORT_INVALID")
        self.fail_worker("print('{}')", "OBSERVER_PROCESS_REPORT_INVALID")
        self.fail_worker("print('null')", "OBSERVER_PROCESS_REPORT_INVALID")

    def test_crash_and_stderr_are_bounded_and_not_disclosed(self):
        self.fail_worker("raise SystemExit(7)", "OBSERVER_PROCESS_FAILED")
        result = self.fail_worker("import sys;sys.stderr.write('private failure detail');print('{}')",
                                  "OBSERVER_PROCESS_FAILED")
        self.assertNotIn("private failure detail", json.dumps(result))

    def test_output_overflow_kills_process_while_streaming(self):
        for stream, count in (("stdout", worker.MAX_REPORT_BYTES + 1),
                              ("stderr", worker.MAX_STDERR_BYTES + 1)):
            code = "import sys;sys." + stream + ".write('x'*" + str(count) + ");sys." + stream + ".flush()"
            self.fail_worker(code, "OBSERVER_PROCESS_OUTPUT_LIMIT")

    def test_worker_holding_pipes_open_after_child_exit_is_killed_as_group(self):
        if os.name != "posix":
            self.skipTest("POSIX process-group behavior")
        # A broken trusted worker can fork a child retaining output descriptors.
        # This is a local cleanup fixture, not an available worker/agent mode.
        code = "import os,time; child=os.fork(); time.sleep(20) if child==0 else os._exit(0)"
        with patch.object(worker, "_worker_command", return_value=[sys.executable, "-I", "-c", code]):
            result = self.run_role(timeout_seconds=0.05)
        self.assert_hold(result, "OBSERVER_PROCESS_TIMEOUT")
        self.assert_reaped(result)

    def test_success_also_kills_same_group_descendant_that_closed_its_pipes(self):
        if os.name != "posix" or not Path("/proc").is_dir():
            self.skipTest("Linux process-group cleanup observation")
        request, evidence = fixtures()
        envelope = sign_attestation(request, private_key=b"x" * 32, verdict="SUPPORT",
                                    evidence_digest=digest(evidence), observed_at=100, valid_until=110)
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "child.pid"
            code = ("import os,time;from pathlib import Path\n"
                    "child=os.fork()\n"
                    "if child==0:\n"
                    " for fd in (0,1,2): os.close(fd)\n"
                    " time.sleep(20)\n"
                    " os._exit(0)\n"
                    "Path(" + repr(str(marker)) + ").write_text(str(child))\n"
                    "os.write(1," + repr(canonical_bytes(envelope)) + ")\n"
                    "os._exit(0)\n")
            with patch.object(worker, "_worker_command", return_value=[sys.executable, "-I", "-c", code]):
                result = self.run_role()
            self.assertEqual(result["process"]["status"], "PASS")
            self.assert_reaped(result)
            child = int(marker.read_text())
            for _ in range(20):
                try:
                    status = Path("/proc") / str(child) / "status"
                    if "State:\tZ" in status.read_text():
                        break  # A killed orphan awaits the host's init reaper.
                except FileNotFoundError:
                    break
                time.sleep(0.01)
            else:
                self.fail("same-group child survived observer completion")

    def test_spawn_failure_is_hold_without_attestation(self):
        with patch.object(worker.subprocess, "Popen", side_effect=OSError("secret path details")):
            result = self.run_role()
        self.assert_hold(result, "OBSERVER_PROCESS_FAILED")
        self.assertIsNone(result["process"]["pid"])
        self.assertNotIn("secret path details", json.dumps(result))

    def test_signer_with_one_key_cannot_forge_another_principal_signature(self):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        request, _ = fixtures("continuity")
        malicious = sign_attestation(request, private_key=b"a" * 32, verdict="SUPPORT",
                                     evidence_digest=digest("false statement"), observed_at=100, valid_until=110)
        body = {key: value for key, value in malicious.items() if key != "signature"}
        with self.assertRaises(InvalidSignature):
            Ed25519PrivateKey.from_private_bytes(b"b" * 32).public_key().verify(
                bytes.fromhex(malicious["signature"]), ATTESTATION_DOMAIN + canonical_bytes(body))


if __name__ == "__main__":
    unittest.main()
