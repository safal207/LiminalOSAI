"""Owned real-Docker crash tests for the managed observer ring.

No Docker success is inferred from unit mocks. Supplying the pinned image enables
these tests; CI supplies it explicitly so an unavailable daemon is a failure.
The controller, watchdog, containers and authority store are all owned fixtures.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from sdk.liminal_agent_control.authority import ControlError, connect
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.observer_auth import ObserverAuthStore
from sdk.liminal_agent_control.observer_registry import ObserverRingRegistry, ownership_labels


PROJECT = Path(__file__).resolve().parents[1]
ROLES = ("reality", "continuity", "projection")
POLICY = "a" * 64
OBJECTIVE = "b" * 64
_EVIDENCE_CASES = []
CONTROLLER_PROGRAM = r"""
import json, os, sys, threading, time
from pathlib import Path
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.observer_auth import ObserverAuthStore
from sdk.liminal_agent_control.observer_container import DockerObserver
from sdk.liminal_agent_control.observer_lifecycle import ObserverRingSupervisor
from sdk.liminal_agent_control.observer_ring import ObserverRingStore
from sdk.liminal_agent_control.orientation import OrientationStore

work, image, root = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
mode = sys.argv[4]
roles = ('reality', 'continuity', 'projection')
authority = SessionAuthority(work / 'authority.sqlite')
authority.create_session(root, controller_id='owned:controller', policy_digest='a' * 64,
    objective_digest='b' * 64, max_actions=10, max_executions=2, max_depth=1,
    max_stages=10, lifetime_seconds=120, lease_seconds=2)
authority.bind_execution(root, 'execution:' + root)
OrientationStore(authority).install(root, {
    'nodes': [{'node_id': 'center', 'space_id': 'owned', 'phase': 'checkpoint'}],
    'edges': [], 'center_nodes': ['center'], 'max_steps': 10, 'max_visits': 10,
    'max_away_steps': 0, 'max_observation_age_seconds': 30,
    'observers': {'records': 'owned:receiver', 'egress': 'owned:sink'}})
ObserverRingStore(authority).install(root, {
    'observers': [{'observer_id': role + '-observer', 'role': role} for role in roles],
    'required_roles': list(roles), 'max_attestation_age_seconds': 30,
    'max_attestations': 100})
def heartbeat():
    state = authority.status(root)
    while True:
        state = authority.renew(root, controller_id='owned:controller',
            expected_epoch=state['epoch'], expected_revision=state['lease_revision'])
        time.sleep(0.1)
threading.Thread(target=heartbeat, daemon=True).start()
sources = {}
for role in roles:
    source = work / role
    source.mkdir()
    source.chmod(0o755)
    sources[role] = source
ring = ObserverRingSupervisor(authority=authority, root_id=root,
    registry_path=work / 'registry.sqlite', image_id=image,
    source_directories=sources, lifetime_seconds=60, timeout_seconds=5)
def publish_ready(ready):
    target = work / 'ready.json'
    pending = target.with_suffix('.pending')
    with pending.open('w') as stream:
        json.dump(ready, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    pending.replace(target)
def base_ready():
    return {'root_id': root, 'controller_pid': os.getpid(),
        'watchdog_pid': ring.watchdog.pid, 'watchdog_output': str(ring.watchdog_output),
        'watchdog_process_start': Path('/proc/' + str(ring.watchdog.pid) + '/stat').read_text().rsplit(')', 1)[1].split()[19],
        'registry_record': ring.record,
        'registry_path': str(work / 'registry.sqlite'), 'authority_db': str(authority.db_path),
        'containers': [{'role': role, 'container_id': ring.services[role].container_id,
            'container_name': ring.services[role].container_name} for role in roles]}
if mode == 'create_ack_lost':
    original_command = DockerObserver._command
    def hold_created_response(observer, command):
        result = original_command(observer, command)
        if command[1] == 'create' and result[0] == 0:
            identity = result[1].decode('ascii').strip()
            ready = base_ready()
            for item in ready['containers']:
                if item['container_name'] == observer.container_name:
                    item['container_id'] = identity
            ready['crash_boundary'] = 'real_create_completed_before_controller_received_ack'
            publish_ready(ready)
            time.sleep(120)
        return result
    DockerObserver._command = hold_created_response
ring.start()
enrollments = [ring.services[role].enrollment for role in roles]
auth = ObserverAuthStore(authority)
if auth.snapshot(root)['profile'] is None:
    auth.install(root, {'keys': [{key: value for key, value in enrollment.items() if key != 'role'}
        for enrollment in enrollments], 'max_challenge_age_seconds': 15,
        'max_challenges': 100})
ready = base_ready()
ready.update(enrollments=enrollments, auth_profile=auth.snapshot(root)['profile'],
    auth_profile_digest=auth.snapshot(root)['profile_digest'])
publish_ready(ready)
time.sleep(120)
"""


@unittest.skipUnless(os.environ.get("LIMINAL_OBSERVER_DOCKER_IMAGE"),
    "set pinned Docker image for real observer lifecycle cleanup")
class ObserverLifecycleDockerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="liminal-observer-lifecycle-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name).resolve()
        self.image = os.environ["LIMINAL_OBSERVER_DOCKER_IMAGE"]
        self.assertRegex(self.image, r"^sha256:[0-9a-f]{64}$")
        self.root = "root:lifecycle:" + uuid.uuid4().hex
        self.controller = None
        self.ready = None
        self.unrelated = None
        self.addCleanup(self.cleanup_owned)

    def docker(self, *arguments, timeout=10):
        return subprocess.run(["docker", *arguments], stdin=subprocess.DEVNULL,
            capture_output=True, text=True, check=False, timeout=timeout)

    def inspect(self, identity):
        result = self.docker("inspect", identity)
        if result.returncode:
            missing = self.docker("ps", "--all", "--quiet", "--no-trunc", "--filter", "id=" + identity)
            self.assertEqual(missing.returncode, 0, missing.stderr)
            self.assertEqual(missing.stdout.strip(), "", result.stderr)
            return None
        documents = json.loads(result.stdout)
        self.assertEqual(len(documents), 1)
        self.assertEqual(documents[0]["Id"], identity)
        return documents[0]

    def launch_unrelated(self):
        name = "liminal-owned-unrelated-" + uuid.uuid4().hex
        result = self.docker("run", "--detach", "--pull=never", "--network=none",
            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--user=65532:65532", "--name", name,
            "--label", "liminal.fixture.unrelated=" + self.root,
            "--entrypoint=/usr/local/bin/python", self.image, "-I", "-c",
            "import time; time.sleep(120)")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.unrelated = result.stdout.strip()
        self.assertRegex(self.unrelated, r"^[0-9a-f]{64}$")
        self.assertTrue(self.inspect(self.unrelated)["State"]["Running"])

    def launch_controller(self, mode="enrolled"):
        self.controller = subprocess.Popen([sys.executable, "-u", "-c", CONTROLLER_PROGRAM,
            str(self.work), self.image, self.root, mode], cwd=PROJECT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            if (self.work / "ready.json").exists():
                self.ready = json.loads((self.work / "ready.json").read_text())
                return self.ready
            if self.controller.poll() is not None:
                _, stderr = self.controller.communicate(timeout=3)
                self.fail("controller exited before ready: " + stderr)
            time.sleep(0.05)
        self.fail("managed observer controller did not publish readiness")

    def wait_report(self):
        target = Path(self.ready["watchdog_output"])
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            if target.exists():
                return json.loads(target.read_text())
            time.sleep(0.05)
        self.fail("independent watchdog did not publish completion evidence")

    def cleanup_owned(self):
        if self.controller is not None:
            if self.controller.poll() is None:
                self.controller.kill()
            self.controller.wait(timeout=5)
            for stream in (self.controller.stdout, self.controller.stderr):
                if stream is not None:
                    stream.close()
        if self.ready is None and (self.work / "ready.json").exists():
            self.ready = json.loads((self.work / "ready.json").read_text())
        if self.ready is not None:
            # Exact immutable IDs from this fixture, never broad names/labels.
            for container in self.ready["containers"]:
                if container["container_id"] is not None:
                    self.docker("rm", "--force", container["container_id"])
            pid = self.ready["watchdog_pid"]
            try:
                observed_start = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
                if observed_start == self.ready["watchdog_process_start"]:
                    os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, FileNotFoundError):
                pass
        elif (self.work / "registry.sqlite").is_file():
            # A readiness assertion can fail after a real create. Recover only a
            # positive exact-ID/image/all-ownership-label match for our root;
            # never remove arbitrary names or containers sharing a broad label.
            registry = ObserverRingRegistry(self.work / "registry.sqlite", create=False)
            for record in registry.unfinished():
                if record["root_id"] != self.root or record["image_id"] != self.image:
                    continue
                for child in registry.snapshot(record)["children"]:
                    found = self.docker("inspect", child["container_id"] or child["container_name"])
                    if found.returncode:
                        continue
                    documents = json.loads(found.stdout)
                    if len(documents) != 1:
                        continue
                    observed = documents[0]
                    expected = ownership_labels(record, child["observer_id"])
                    labels = observed.get("Config", {}).get("Labels") or {}
                    identity = observed.get("Id")
                    if (isinstance(identity, str) and len(identity) == 64
                            and observed.get("Image") == self.image
                            and observed.get("Name") == "/" + child["container_name"]
                            and all(labels.get(key) == value for key, value in expected.items())
                            and child["container_id"] in (None, identity)):
                        self.docker("rm", "--force", identity)
        if self.unrelated is not None:
            self.docker("rm", "--force", self.unrelated)

    def record_evidence(self, document):
        destination = os.environ.get("LIMINAL_OBSERVER_LIFECYCLE_EVIDENCE")
        if not destination:
            return
        from sdk.liminal_agent_control.multi_agent import _source, _source_digests
        source_hashes = _source_digests()
        test_path = "tests/test_agent_control_observer_lifecycle_runtime.py"
        source_hashes[test_path] = hashlib.sha256((PROJECT / test_path).read_bytes()).hexdigest()
        document.update(source=_source(), source_files_sha256=source_hashes, image_id=self.image)
        _EVIDENCE_CASES.append(document)
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"schema": "liminal.observer-lifecycle-runtime-evidence.v1",
            "cases": _EVIDENCE_CASES}, indent=2, sort_keys=True) + "\n")

    def persisted_closure(self, ready):
        # Read before status(): the authority reader must not create the stop
        # transition which this independent-process test is meant to verify.
        with connect(ready["authority_db"]) as db:
            state = dict(db.execute("SELECT state,stop_reason FROM brakes_sessions WHERE root_id=?",
                                    (self.root,)).fetchone())
            self.assertIn(state["state"], ("STOPPED", "EXPIRED"))
            self.assertEqual(db.execute("SELECT revoked FROM roots WHERE root_id=?",
                                       (self.root,)).fetchone()[0], 1)
        return state

    def test_create_ack_not_recorded_removes_owned_candidate_but_preserves_unknown_after_sigkill(self):
        self.launch_unrelated()
        ready = self.launch_controller("create_ack_lost")
        self.assertNotEqual(os.getpgid(self.controller.pid), os.getpgid(ready["watchdog_pid"]))
        registry = ObserverRingRegistry(ready["registry_path"], create=False)
        before = registry.snapshot(ready["registry_record"])
        self.assertEqual(before["status"], "REGISTERED")
        self.assertEqual([child["phase"] for child in before["children"]],
                         ["CREATE_PENDING", "REGISTERED", "REGISTERED"])
        self.assertEqual([child["container_id"] for child in before["children"]], [None, None, None])
        created = [item for item in ready["containers"] if item["container_id"] is not None]
        self.assertEqual(len(created), 1)
        identity = created[0]["container_id"]
        self.assertRegex(identity, r"^[0-9a-f]{64}$")
        observed = self.inspect(identity)
        self.assertEqual(observed["Image"], self.image)
        self.assertFalse(observed["State"]["Running"])
        self.assertEqual(observed["Name"], "/" + created[0]["container_name"])
        self.controller.kill()
        self.controller.wait(timeout=5)
        self.assertEqual(self.controller.returncode, -signal.SIGKILL)
        report = self.wait_report()
        self.assertTrue(report["admission_closed"], report)
        self.assertFalse(report["observers_removed"], report)
        self.assertEqual(report["status"], "INCOMPLETE", report)
        self.assertLessEqual(report["closure_recorded_at"], report["cleanup_started_at"])
        self.assertEqual(len(report["cleanup"]), 3)
        self.assertEqual(report["cleanup"][0]["observed_removed_id"], identity)
        self.assertEqual(report["cleanup"][0]["reason"], "CREATE_OUTCOME_UNCONFIRMED")
        self.assertFalse(report["cleanup"][0]["removed"])
        self.assertEqual(report["cleanup"][0]["container_id"], None)
        self.assertTrue(all(item["removed"] is True for item in report["cleanup"][1:]), report)
        state = self.persisted_closure(ready)
        after = registry.snapshot(ready["registry_record"])
        self.assertEqual(after["status"], "CLOSING", after)
        self.assertEqual([child["phase"] for child in after["children"]],
                         ["CREATE_PENDING", "REMOVED", "REMOVED"])
        self.assertEqual([child["container_id"] for child in after["children"]], [None, None, None])
        self.assertEqual(registry.unfinished(), [ready["registry_record"]])
        self.assertIsNone(self.inspect(identity))
        self.assertTrue(self.inspect(self.unrelated)["State"]["Running"])
        self.record_evidence({"mode": "actual-docker-create-completed-ack-not-recorded-controller-sigkill",
            "ready": ready, "registry_before_crash": before, "created_container_id": identity,
            "watchdog": report, "persisted_session": state, "registry_after_cleanup": after,
            "created_container_absent": True, "create_outcome_kept_unknown": True,
            "unrelated_container_id": self.unrelated,
            "unrelated_survived": True})

    def test_controller_sigkill_stops_root_removes_three_observers_and_preserves_unrelated(self):
        self.launch_unrelated()
        ready = self.launch_controller()
        self.assertEqual(ready["controller_pid"], self.controller.pid)
        self.assertNotEqual(os.getpgid(self.controller.pid), os.getpgid(ready["watchdog_pid"]))
        self.assertEqual({item["role"] for item in ready["containers"]}, set(ROLES))
        ids = [item["container_id"] for item in ready["containers"]]
        self.assertEqual(len(set(ids)), 3)
        self.assertEqual(len({item["public_key"] for item in ready["enrollments"]}), 3)
        before = []
        for identity in ids:
            self.assertRegex(identity, r"^[0-9a-f]{64}$")
            observed = self.inspect(identity)
            self.assertTrue(observed["State"]["Running"], observed)
            self.assertEqual(observed["Image"], self.image)
            before.append({"container_id": identity, "running": True})
        self.controller.kill()
        self.controller.wait(timeout=5)
        self.assertEqual(self.controller.returncode, -signal.SIGKILL)
        report = self.wait_report()
        self.assertTrue(report["admission_closed"], report)
        self.assertTrue(report["observers_removed"], report)
        self.assertEqual(report["status"], "RECOVERED", report)
        self.assertLessEqual(report["closure_recorded_at"], report["cleanup_started_at"])
        self.assertEqual({item["container_id"] for item in report["cleanup"]}, set(ids))
        self.assertEqual(len(report["cleanup"]), 3)
        self.assertTrue(all(item["removed"] is True for item in report["cleanup"]), report)
        state = self.persisted_closure(ready)
        self.assertEqual([self.inspect(identity) for identity in ids], [None, None, None])
        self.assertTrue(self.inspect(self.unrelated)["State"]["Running"])
        registry = ObserverRingRegistry(ready["registry_path"], create=False)
        registry_state = registry.snapshot(ready["registry_record"])
        self.assertEqual(registry_state["status"], "CLOSED", registry_state)
        self.assertEqual(registry.unfinished(), [])
        self.assertEqual(len(registry_state["children"]), 3)
        self.assertTrue(all(child["phase"] == "REMOVED" for child in registry_state["children"]))
        self.assertEqual({child["container_id"] for child in registry_state["children"]}, set(ids))
        restarted = SessionAuthority(ready["authority_db"])
        action = {"action_id": "action:" + self.root, "attempt_id": "attempt:" + self.root,
            "root_id": self.root, "execution_id": "execution:" + self.root,
            "epoch": 1, "target": "records", "arguments": {"value": "must stay blocked"}}
        denied = restarted.reserve(action, channel="records")
        self.assertEqual(denied["status"], "BLOCKED", denied)
        self.assertEqual(denied["reason"], state["stop_reason"], denied)
        with self.assertRaises(ControlError):
            restarted.renew(self.root, controller_id="owned:controller", expected_epoch=1,
                            expected_revision=restarted.status(self.root)["lease_revision"])
        auth = ObserverAuthStore(restarted)
        replacement = deepcopy(ready["auth_profile"])
        replacement["keys"][0]["public_key"] = "0" * 64
        with self.assertRaises(ControlError):
            auth.install(self.root, replacement)
        self.assertEqual(auth.snapshot(self.root)["profile_digest"], ready["auth_profile_digest"])
        self.assertEqual(auth.snapshot(self.root)["profile"], ready["auth_profile"])
        from sdk.liminal_agent_control.observer_lifecycle import ObserverRingSupervisor
        with self.assertRaises((ControlError, ValueError)):
            ObserverRingSupervisor(authority=restarted, root_id=self.root,
                registry_path=ready["registry_path"], image_id=self.image,
                source_directories={role: self.work / role for role in ROLES}).start()
        self.assertEqual(registry.snapshot(ready["registry_record"]), registry_state)
        self.record_evidence({"mode": "actual-docker-three-enrolled-observers-controller-sigkill",
            "ready": ready, "before_crash": before, "watchdog": report,
            "registry": registry_state,
            "persisted_session": state, "reopened_admission": denied,
            "owned_container_ids_absent": ids,
            "unrelated_container_id": self.unrelated, "unrelated_survived": True,
            "auth_profile_digest_unchanged": ready["auth_profile_digest"]})


if __name__ == "__main__":
    unittest.main()
