"""External lifecycle accounting for separately admitted owned CREATE/START.

Only an independently pinned supervisor's QUIESCENT evidence settles an issued
stage. The inherited COMMITTED ledger status means authenticated settlement;
it does not assert a successful command or a business-effect count.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable

from .authority import ControlError, canonical_bytes
from .external_authority import ExternalAuthorityStore
from .external_command_protocol import (
    COMMAND_PROFILE, validate_command_action, validate_supervisor_pin, verify_command_receipt,
)
from .observer_auth import _crypto


class ExternalCommandAuthorityStore(ExternalAuthorityStore):
    def __init__(self, db_path: str | Path, *, supervisor_pin: dict[str, str],
                 authority_id: str, key_id: str, private_key: bytes, receipt_key: bytes,
                 clock: Callable[[], float] = time.time, create: bool = True) -> None:
        self._supervisor_pin = validate_supervisor_pin(supervisor_pin)
        if type(private_key) is bytes and len(private_key) == 32:
            private, _ = _crypto()
            public_key = private.from_private_bytes(private_key).public_key().public_bytes_raw().hex()
            if public_key == self._supervisor_pin["public_key"]:
                raise ControlError("EXTERNAL_AUTHORITY_SUPERVISOR_KEY_MUST_DIFFER")
        super().__init__(db_path, authority_id=authority_id, key_id=key_id, private_key=private_key,
                         receipt_key=receipt_key, clock=clock, create=create)

    def supervisor_pin(self) -> dict[str, str]:
        return dict(self._supervisor_pin)

    def _profile_configuration(self) -> dict[str, str]:
        return {"profile": COMMAND_PROFILE,
                "supervisor_pin": canonical_bytes(validate_supervisor_pin(self._supervisor_pin)).decode()}

    def _validate_action(self, action: Any) -> dict[str, Any]:
        return validate_command_action(action)

    def create_root(self, root_id: str, receiver_id: str, policy_digest: str, max_actions: int,
                    lifetime_seconds: float) -> dict[str, Any]:
        if receiver_id != self._supervisor_pin["supervisor_id"]:
            raise ControlError("EXTERNAL_AUTHORITY_SUPERVISOR_IDENTITY_MISMATCH")
        return super().create_root(root_id, receiver_id, policy_digest, max_actions, lifetime_seconds)

    def _additional_begin_reason(self, db: sqlite3.Connection, root: sqlite3.Row,
                                 action: dict[str, Any], authorization: dict[str, Any]) -> str | None:
        """Check parent and uniqueness under the same writer lock as admission."""
        args = action["arguments"]
        if args["stage"] == "CREATE":
            # A new action ID must not create another object for the same exact
            # approved command. DENIED rows did not admit a Docker request.
            rows = db.execute("SELECT action_json FROM external_actions WHERE root_id=? AND status != 'DENIED'",
                              (action["root_id"],)).fetchall()
            for row in rows:
                old = json.loads(row["action_json"])["arguments"]
                if old["stage"] == "CREATE" and old["spec"]["command_id"] == args["spec"]["command_id"]:
                    return "EXTERNAL_COMMAND_CREATE_ALREADY_ADMITTED"
            return None
        parent = db.execute("SELECT * FROM external_actions WHERE reservation_id=?",
                            (args["parent_reservation_id"],)).fetchone()
        if parent is None or parent["status"] != "PENDING":
            return "EXTERNAL_COMMAND_PARENT_NOT_PENDING"
        previous = json.loads(parent["action_json"])
        if (previous["target"] != "command" or previous["arguments"]["stage"] != "CREATE"
                or any(type(previous[field]) is not type(action[field]) or previous[field] != action[field]
                       for field in ("root_id", "execution_id", "epoch"))
                or canonical_bytes(previous["arguments"]["spec"]) != canonical_bytes(args["spec"])):
            return "EXTERNAL_COMMAND_PARENT_BINDING_MISMATCH"
        for row in db.execute("SELECT action_json FROM external_actions WHERE root_id=? AND status != 'DENIED'",
                              (action["root_id"],)):
            old = json.loads(row["action_json"])["arguments"]
            if old["stage"] == "START" and old["parent_reservation_id"] == parent["reservation_id"]:
                return "EXTERNAL_COMMAND_START_ALREADY_ADMITTED"
        return None

    def _verify_terminal_receipt(self, receipt: Any) -> dict[str, Any]:
        if not verify_command_receipt(receipt, self._supervisor_pin):
            raise ControlError("EXTERNAL_AUTHORITY_COMMAND_RECEIPT_INVALID")
        return json.loads(canonical_bytes(receipt))

    def _additional_finish_check(self, db: sqlite3.Connection, receipt: dict[str, Any],
                                 row: sqlite3.Row, root: sqlite3.Row, action: dict[str, Any]) -> None:
        args = action["arguments"]
        if args["stage"] == "CREATE":
            children = []
            for child in db.execute("SELECT * FROM external_actions WHERE root_id=? AND status != 'DENIED'",
                                    (action["root_id"],)):
                child_action = json.loads(child["action_json"])
                child_args = child_action["arguments"]
                if child_args["stage"] == "START" and child_args["parent_reservation_id"] == row["reservation_id"]:
                    children.append((child, child_action))
            if receipt["start_admitted"] != bool(children) or len(children) > 1:
                raise ControlError("EXTERNAL_AUTHORITY_COMMAND_START_ACCOUNTING_MISMATCH")
            if children:
                child, child_action = children[0]
                if (child_action["arguments"]["container_id"] != receipt["container_id"]
                        or canonical_bytes(child_action["arguments"]["spec"]) != canonical_bytes(args["spec"])):
                    raise ControlError("EXTERNAL_AUTHORITY_COMMAND_LIFECYCLE_BINDING_MISMATCH")
                if child["receipt_json"] is not None:
                    self._matching_lifecycle(receipt, json.loads(child["receipt_json"]))
        else:
            parent = db.execute("SELECT * FROM external_actions WHERE reservation_id=?",
                                (args["parent_reservation_id"],)).fetchone()
            if parent is None or parent["status"] not in ("PENDING", "COMMITTED"):
                raise ControlError("EXTERNAL_AUTHORITY_COMMAND_PARENT_NOT_ADMITTED")
            if parent["receipt_json"] is not None:
                self._matching_lifecycle(receipt, json.loads(parent["receipt_json"]))

    @staticmethod
    def _matching_lifecycle(left: dict[str, Any], right: dict[str, Any]) -> None:
        # Both stage receipts must describe one independently observed lifecycle,
        # including the same owned object, completed callbacks and final census.
        for field in ("container_id", "command_id", "image_id", "plan_sha256", "ownership_digest",
                      "observation_digest", "start_admitted", "start_outcome", "observed_at"):
            if type(left[field]) is not type(right[field]) or left[field] != right[field]:
                raise ControlError("EXTERNAL_AUTHORITY_COMMAND_LIFECYCLE_BINDING_MISMATCH")

    def _bind_terminal_receipt(self, receipt: dict[str, Any], row: sqlite3.Row,
                               root: sqlite3.Row, action: dict[str, Any]) -> str:
        args, spec = action["arguments"], action["arguments"]["spec"]
        if (receipt["supervisor_id"] != root["receiver_id"]
                or receipt["supervisor_id"] != self._supervisor_pin["supervisor_id"]
                or receipt["key_id"] != self._supervisor_pin["key_id"]
                or receipt["reservation_id"] != row["reservation_id"]
                or receipt["action_digest"] != row["action_digest"]
                or receipt["authorization_digest"] != row["authorization_digest"]
                or receipt["stage"] != args["stage"]
                or any(receipt[field] != spec[field] for field in ("command_id", "image_id", "plan_sha256"))
                or (args["stage"] == "START" and receipt["container_id"] != args["container_id"])
                or any(type(receipt[field]) is not type(action[field]) or receipt[field] != action[field]
                       for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))):
            raise ControlError("EXTERNAL_AUTHORITY_COMMAND_RECEIPT_BINDING_MISMATCH")
        return "COMMITTED"

    def _terminal_reason_prefix(self) -> str:
        return "AUTHENTICATED_SUPERVISOR_QUIESCENT_"
