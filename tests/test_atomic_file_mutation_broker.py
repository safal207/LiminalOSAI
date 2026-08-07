from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import threading
import unittest

from adapters.filesystem.liminal_atomic_file_replacer import (
    AtomicFileReplaceError,
    AtomicFileReplacer,
    verify_execution_receipt,
)
from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_file_mutation_broker import (
    FileMutationBroker,
    FileMutationError,
    FileMutationRequest,
    FileRootBinding,
    normalize_relative_path,
    verify_authorization_receipt,
)
from sdk.liminal_post_sandbox_contracts import CapabilityContract

POLICY = "a" * 64
ADAPTER_TOKEN = "host-only-file-adapter-token"
ADAPTER_TOKEN_SHA = hashlib.sha256(ADAPTER_TOKEN.encode()).hexdigest()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Clock:
    def __init__(self, value: int = 100) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class FileMutationBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        os.mkdir(os.path.join(self.root, "docs"))
        self.target = os.path.join(self.root, "docs", "file.txt")
        with open(self.target, "wb") as fh:
            fh.write(b"before")
        self.clock = Clock()
        self.binding = FileRootBinding.build(root_id="repo-root", logical_prefix="rootrepo", max_content_bytes=1024)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _stack(self, *, grant_paths: list[str] | None = None, max_uses: int = 20):
        capability = CapabilityBroker("cap-broker:file-tests")
        contract = CapabilityContract.build(
            capability_id="cap:file",
            capability_type="filesystem.write_outside_workspace",
            subject_id="agent:a",
            issuer_id="host:tests",
            scope={"paths": grant_paths or ["rootrepo/docs/file.txt"]},
            issued_at_unix=100,
            not_before_unix=100,
            expires_at_unix=10000,
            max_uses=max_uses,
            delegable=False,
            parent_capability_id=None,
            policy_sha256=POLICY,
        )
        capability.admit(contract.as_document(), at_unix=100)
        broker = FileMutationBroker(
            capability_broker=capability,
            bindings=[self.binding.as_document()],
            adapter_token_sha256=ADAPTER_TOKEN_SHA,
            lease_ttl_seconds=10,
            clock=self.clock,
        )
        adapter = AtomicFileReplacer(
            broker=broker,
            adapter_token=ADAPTER_TOKEN,
            host_roots={"repo-root": self.root},
        )
        return capability, broker, adapter

    def _request(self, *, call_id: str = "call:1", path: str = "docs/file.txt", before: bytes = b"before", after: bytes = b"after") -> FileMutationRequest:
        return FileMutationRequest(
            call_id=call_id,
            subject_id="agent:a",
            policy_sha256=POLICY,
            root_id="repo-root",
            relative_path=path,
            expected_before_sha256=sha(before),
            desired_content_sha256=sha(after),
            content_length=len(after),
        )

    def test_valid_replace_is_atomic_and_digest_bound(self):
        before_stat = os.stat(self.target)
        _, broker, adapter = self._stack()
        auth = broker.authorize(self._request())
        self.assertEqual(auth["decision"], "ALLOW")
        verify_authorization_receipt(auth)
        receipt = adapter.replace(lease_id=auth["lease_id"], content=b"after")
        self.assertEqual(receipt["outcome"], "SUCCEEDED")
        verify_execution_receipt(receipt)
        with open(self.target, "rb") as fh:
            self.assertEqual(fh.read(), b"after")
        after_stat = os.stat(self.target)
        self.assertEqual(after_stat.st_uid, before_stat.st_uid)
        self.assertEqual(after_stat.st_gid, before_stat.st_gid)

    def test_privileged_mode_bits_are_not_preserved(self):
        os.chmod(self.target, 0o4755)
        _, broker, adapter = self._stack()
        auth = broker.authorize(self._request())
        receipt = adapter.replace(lease_id=auth["lease_id"], content=b"after")
        self.assertEqual(receipt["outcome"], "SUCCEEDED")
        observed_mode = stat.S_IMODE(os.stat(self.target).st_mode)
        self.assertEqual(observed_mode & 0o7000, 0)
        self.assertEqual(observed_mode & 0o0777, 0o755)

    def test_path_traversal_and_separator_ambiguity_rejected(self):
        for path in ("../escape", "docs/../file.txt", "/abs/file", "docs\\file.txt", "docs//file.txt", "./docs/file.txt"):
            with self.subTest(path=path):
                with self.assertRaises(FileMutationError):
                    normalize_relative_path(path)

    def test_scope_mismatch_blocks_without_lease(self):
        _, broker, _ = self._stack(grant_paths=["rootrepo/other.txt"])
        auth = broker.authorize(self._request())
        self.assertEqual(auth["decision"], "BLOCK")
        self.assertIsNone(auth["lease_id"])

    def test_content_mismatch_consumes_lease_but_does_not_touch_file(self):
        _, broker, adapter = self._stack()
        auth = broker.authorize(self._request())
        receipt = adapter.replace(lease_id=auth["lease_id"], content=b"WRONG")
        self.assertEqual(receipt["outcome"], "FAILED")
        with open(self.target, "rb") as fh:
            self.assertEqual(fh.read(), b"before")
        with self.assertRaises(FileMutationError):
            broker.consume_for_trusted_adapter(auth["lease_id"], adapter_token=ADAPTER_TOKEN)

    def test_stale_before_digest_blocks_replacement(self):
        _, broker, adapter = self._stack()
        auth = broker.authorize(self._request(before=b"older"))
        receipt = adapter.replace(lease_id=auth["lease_id"], content=b"after")
        self.assertEqual(receipt["outcome"], "FAILED")
        with open(self.target, "rb") as fh:
            self.assertEqual(fh.read(), b"before")

    def test_missing_target_is_not_created(self):
        _, broker, adapter = self._stack(grant_paths=["rootrepo/docs/missing.txt"])
        req = self._request(path="docs/missing.txt")
        auth = broker.authorize(req)
        receipt = adapter.replace(lease_id=auth["lease_id"], content=b"after")
        self.assertEqual(receipt["outcome"], "FAILED")
        self.assertFalse(os.path.exists(os.path.join(self.root, "docs", "missing.txt")))

    def test_symlink_target_is_refused(self):
        os.unlink(self.target)
        real = os.path.join(self.root, "docs", "real.txt")
        with open(real, "wb") as fh:
            fh.write(b"before")
        os.symlink("real.txt", self.target)
        _, broker, adapter = self._stack()
        auth = broker.authorize(self._request())
        receipt = adapter.replace(lease_id=auth["lease_id"], content=b"after")
        self.assertEqual(receipt["outcome"], "FAILED")
        with open(real, "rb") as fh:
            self.assertEqual(fh.read(), b"before")

    def test_symlink_parent_is_refused(self):
        outside = tempfile.TemporaryDirectory()
        try:
            with open(os.path.join(outside.name, "file.txt"), "wb") as fh:
                fh.write(b"before")
            os.unlink(self.target)
            os.rmdir(os.path.join(self.root, "docs"))
            os.symlink(outside.name, os.path.join(self.root, "docs"))
            _, broker, adapter = self._stack()
            auth = broker.authorize(self._request())
            receipt = adapter.replace(lease_id=auth["lease_id"], content=b"after")
            self.assertEqual(receipt["outcome"], "FAILED")
            with open(os.path.join(outside.name, "file.txt"), "rb") as fh:
                self.assertEqual(fh.read(), b"before")
        finally:
            outside.cleanup()

    def test_wrong_adapter_token_does_not_consume_lease(self):
        _, broker, adapter = self._stack()
        auth = broker.authorize(self._request())
        with self.assertRaises(FileMutationError):
            broker.consume_for_trusted_adapter(auth["lease_id"], adapter_token="wrong")
        receipt = adapter.replace(lease_id=auth["lease_id"], content=b"after")
        self.assertEqual(receipt["outcome"], "SUCCEEDED")

    def test_revoke_after_authorization_blocks_before_adapter_reference(self):
        capability, broker, _ = self._stack()
        auth = broker.authorize(self._request())
        capability.revoke("cap:file", at_unix=101)
        self.clock.value = 102
        with self.assertRaises(FileMutationError):
            broker.consume_for_trusted_adapter(auth["lease_id"], adapter_token=ADAPTER_TOKEN)
        with open(self.target, "rb") as fh:
            self.assertEqual(fh.read(), b"before")

    def test_lease_expiry_blocks_before_filesystem_access(self):
        _, broker, _ = self._stack()
        auth = broker.authorize(self._request())
        self.clock.value = 111
        with self.assertRaises(FileMutationError):
            broker.consume_for_trusted_adapter(auth["lease_id"], adapter_token=ADAPTER_TOKEN)
        with open(self.target, "rb") as fh:
            self.assertEqual(fh.read(), b"before")

    def test_containment_blocks_authorization_and_consumption(self):
        _, broker, _ = self._stack()
        broker.enter_containment("b" * 64)
        blocked = broker.authorize(self._request())
        self.assertEqual(blocked["decision"], "BLOCK")

        _, broker2, _ = self._stack()
        allowed = broker2.authorize(self._request())
        broker2.enter_containment("b" * 64)
        with self.assertRaises(FileMutationError):
            broker2.consume_for_trusted_adapter(allowed["lease_id"], adapter_token=ADAPTER_TOKEN)

    def test_lease_replay_fails_closed(self):
        _, broker, adapter = self._stack()
        auth = broker.authorize(self._request())
        self.assertEqual(adapter.replace(lease_id=auth["lease_id"], content=b"after")["outcome"], "SUCCEEDED")
        with self.assertRaises(FileMutationError):
            broker.consume_for_trusted_adapter(auth["lease_id"], adapter_token=ADAPTER_TOKEN)

    def test_duplicate_call_id_is_atomic_under_threads(self):
        _, broker, _ = self._stack()
        barrier = threading.Barrier(3)
        decisions: list[str] = []
        lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            result = broker.authorize(self._request(call_id="call:concurrent"))
            with lock:
                decisions.append(result["decision"])

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(decisions), ["ALLOW", "BLOCK"])

    def test_receipts_are_digest_only_and_exact_schema(self):
        _, broker, adapter = self._stack()
        auth = broker.authorize(self._request())
        execution = adapter.replace(lease_id=auth["lease_id"], content=b"after")
        serialized = json.dumps({"auth": auth, "execution": execution}, sort_keys=True)
        self.assertNotIn("docs/file.txt", serialized)
        self.assertNotIn('"after"', serialized)
        verify_authorization_receipt(auth)
        verify_execution_receipt(execution)
        bad_auth = dict(auth)
        bad_auth["raw_path"] = "docs/file.txt"
        with self.assertRaises(FileMutationError):
            verify_authorization_receipt(bad_auth)
        bad_execution = dict(execution)
        bad_execution["raw_content"] = "after"
        with self.assertRaises(AtomicFileReplaceError):
            verify_execution_receipt(bad_execution)

    def test_binding_is_immutable_after_construction(self):
        _, broker, _ = self._stack()
        with self.assertRaises(TypeError):
            broker._bindings["evil"] = self.binding  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
