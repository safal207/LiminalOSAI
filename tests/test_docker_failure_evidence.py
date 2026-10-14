"""Synthetic verifier fixtures are not evidence that a real daemon was exercised."""
import copy
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).parent / "fixtures/isolated_executor/verify_docker_failure_probe.py"
SPEC = importlib.util.spec_from_file_location("docker_failure_verifier", PATH)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def fixture():
    identity = {"session_id": "liminal-" + "a" * 16 + "-" + "b" * 16,
                "container_id": "c" * 64, "image_id": "sha256:" + "d" * 64,
                "plan_sha256": "e" * 64, "daemon_id": "fixture-daemon"}
    cases = {"normal": {"exit_code": 0, "container_id": "c" * 64, "target_absent": True}}
    for name in VERIFIER.CASES - {"normal"}:
        cases[name] = {"outcome": "UNKNOWN", "phase": "START", "cleanup_state": "VERIFIED_ABSENT",
                       "session": copy.deepcopy(identity), "target_absent": True}
    for name in ("lost_create_response", "delayed_create"):
        cases[name].update(phase="CREATE", cleanup_state="UNKNOWN", start_dispatched=False)
        cases[name]["session"]["container_id"] = None
    cases["lost_create_response"]["name_absent"] = True
    cases["delayed_create"].update(absent_before_delivery=True, late_absent_after=True,
        late_status="created", late_running=False, late_container_id="f" * 64, recovery_cleanup="UNKNOWN")
    cases["client_death"].update(phase="OBSERVE", client_returncode=-9, running_at_client_death=True)
    cases["delayed_start_replacement"].update(sentinel_id="f" * 64, delayed_start_returncode=1,
        sentinel_status="created", sentinel_running=False, recovery_cleanup="VERIFIED_ABSENT")
    cases["daemon_restart"].update(cleanup_state="UNKNOWN", daemon_before="fixture-daemon",
        daemon_after="fixture-daemon", reobserved_container_id="c" * 64, recovery_cleanup="VERIFIED_ABSENT")
    return {"schema": "liminal-docker-failure-probe-v1", "revision": "a" * 40,
            "image_id": identity["image_id"], "daemon_id": identity["daemon_id"],
            "scope": "fault-injected-control-plane-with-real-disposable-daemon", "cases": cases}


class DockerFailureEvidenceTests(unittest.TestCase):
    def verify(self, document):
        return VERIFIER.verify(document, revision="a" * 40, image="sha256:" + "d" * 64)

    def test_valid_synthetic_facts(self):
        document = fixture()
        self.assertEqual(self.verify(document), document)

    def test_rejects_unknown_upgrades_and_wrong_identity(self):
        mutations = [
            ("delayed_create", "recovery_cleanup", "VERIFIED_ABSENT"),
            ("lost_create_response", "start_dispatched", True),
            ("client_death", "outcome", "SUCCEEDED"),
            ("client_death", "target_absent", False),
            ("client_death", "client_returncode", 0),
            ("daemon_restart", "daemon_after", "replacement-daemon"),
            ("daemon_restart", "cleanup_state", "VERIFIED_ABSENT"),
            ("delayed_start_replacement", "sentinel_running", True),
            ("delayed_start_replacement", "sentinel_id", "c" * 64),
        ]
        for name, key, value in mutations:
            with self.subTest(case=name, field=key):
                document = fixture()
                document["cases"][name][key] = value
                with self.assertRaises(ValueError):
                    self.verify(document)

    def test_rejects_missing_scope_revision_or_scenario(self):
        for key in ("revision", "scope", "image_id"):
            with self.subTest(key=key):
                document = fixture()
                document[key] = "incorrect"
                with self.assertRaises(ValueError):
                    self.verify(document)
        document = fixture()
        document["cases"].pop("client_death")
        with self.assertRaises(ValueError):
            self.verify(document)


if __name__ == "__main__":
    unittest.main()
