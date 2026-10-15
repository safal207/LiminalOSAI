"""Real signed loopback controllers; watcher health is an in-process signal."""
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.authority import ControlError
from tests import test_agent_control_external_agent_coordinator as fixtures


class ExternalAgentWatcherHealthTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ExternalAgentCoordinatorTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.coordinator = self.fixture.coordinator

    def test_active_roots_without_watcher_are_not_ready(self):
        self.assertEqual(self.coordinator.status()["status"], "ACTIVE")
        self.assertEqual({key: self.coordinator.watcher_health()[key] for key in ("ready", "alive", "fresh")},
                         {"ready": False, "alive": False, "fresh": False})
        self.assertFalse(self.coordinator.wait_watcher_ready(timeout=.01))
        self.assertEqual(self.fixture.command_store.status("command-root")["issued_count"], 0)

    def test_ready_requires_a_completed_controller_cycle(self):
        self.coordinator.start_watcher()
        self.assertTrue(self.coordinator.wait_watcher_ready(timeout=2))
        health = self.coordinator.watcher_health()
        self.assertTrue(all(health[key] for key in ("ready", "alive", "fresh")))
        self.assertIsInstance(health["last_completed"], float)
        self.assertFalse(health["execution_authorized"])

    def test_live_thread_stale_or_backward_heartbeat_is_not_fresh(self):
        self.coordinator.start_watcher()
        self.assertTrue(self.coordinator.wait_watcher_ready(timeout=2))
        with self.coordinator._watcher_health_lock:
            for last in (100.0, 198.0, 201.0):
                self.coordinator._watcher_last_completed = last
                with patch("sdk.liminal_agent_control.external_agent_coordinator.time.monotonic", return_value=200.0):
                    health = self.coordinator.watcher_health()
                self.assertTrue(health["alive"])
                self.assertFalse(health["fresh"])

    def test_stopped_watcher_cannot_reuse_recent_readiness(self):
        self.coordinator.start_watcher()
        self.assertTrue(self.coordinator.wait_watcher_ready(timeout=2))
        self.coordinator._watcher_stop.set()
        self.coordinator._watcher.join(2)
        health = self.coordinator.watcher_health()
        self.assertFalse(health["alive"])
        self.assertFalse(health["ready"])
        self.assertFalse(health["fresh"])

    def test_cycle_failure_closes_admission_without_readiness(self):
        with patch.object(self.coordinator, "reconcile", side_effect=ControlError("OWNED_WATCHER_FAILURE")):
            self.coordinator.start_watcher()
            self.coordinator._watcher.join(2)
        self.assertFalse(self.coordinator.watcher_health()["ready"])
        self.assertTrue(self.coordinator.fence_state()["closed"])

    def test_local_admission_closure_does_not_wait_for_remote_control(self):
        command, effect = self.coordinator.command_admin_client, self.coordinator.effect_admin_client
        with patch.object(command, "stop", side_effect=AssertionError("remote STOP attempted")), \
                patch.object(effect, "stop", side_effect=AssertionError("remote STOP attempted")), \
                patch.object(command, "status", side_effect=AssertionError("remote status attempted")), \
                patch.object(effect, "status", side_effect=AssertionError("remote status attempted")):
            result = self.coordinator.close_admission("UNIT_EFFECT_GUARD")
        self.assertTrue(result["closed"])
        self.assertEqual(result["state"], "CLOSING")
        self.assertEqual(result["reason"], "UNIT_EFFECT_GUARD")
        self.assertEqual(self.fixture.command_store.status("command-root")["state"], "ACTIVE")
        self.assertEqual(self.fixture.effect_store.status("effect-root")["state"], "ACTIVE")

    def test_invalid_health_and_wait_windows_rejected(self):
        for value in (True, 0, -1, float("nan"), float("inf"), 6):
            with self.subTest(value=value), self.assertRaises(ControlError):
                self.coordinator.watcher_health(max_age_seconds=value)
            with self.subTest(timeout=value), self.assertRaises(ControlError):
                self.coordinator.wait_watcher_ready(timeout=value)
