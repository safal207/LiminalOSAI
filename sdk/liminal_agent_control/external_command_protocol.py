"""Exact contracts for one fixed, owned Docker workload and its lifecycle.

CREATE and START are different external admissions. QUIESCENT is a trusted
supervisor observation of an owned lifecycle, never a command-success or
zero-business-effect claim. This profile exposes no arbitrary shell tool.
"""
from __future__ import annotations

import json
import math
from typing import Any

from sdk.liminal_isolated_execution import IsolatedExecutionPlan, IsolationError, IsolationProfile

from .authority import ACTION_FIELDS, ControlError, canonical_bytes, digest, validate_id


COMMAND_PROFILE = "owned-docker-command-v1"
COMMAND_SPEC_SCHEMA = "liminal-owned-docker-command-spec-v1"
COMMAND_RECEIPT_SCHEMA = "liminal.external-command.receipt.v1"
COMMAND_RECEIPT_DOMAIN = b"liminal-external-command-receipt-v1\x00"
# Frozen source identity; supplied with the exact checked-in fixture bytes.
COMMAND_FIXTURE_SHA256 = "3127babde5158f2838b4e7859621651fc8deab2e2c74208c7aae10c79c79dd81"
COMMAND_RECEIPT_FIELDS = frozenset({"schema", "supervisor_id", "key_id", "reservation_id",
    "action_id", "attempt_id", "root_id", "execution_id", "epoch", "action_digest",
    "authorization_digest", "stage", "command_id", "image_id", "container_id", "plan_sha256",
    "ownership_digest", "create_confirmed", "callbacks_finished", "process_quiescent",
    "start_admitted", "start_outcome", "business_effects", "observation_digest", "observed_at",
    "status", "signature"})
_SPEC_FIELDS = frozenset({"schema", "command_id", "image_id", "host_workspace", "fixture", "argv",
    "timeout_seconds", "isolation", "working_directory", "environment_policy", "workspace_mount",
    "entrypoint", "log_driver", "plan_sha256", "fixture_sha256"})


def _hex(value: Any, length: int = 64) -> str:
    if type(value) is not str or len(value) != length or any(c not in "0123456789abcdef" for c in value):
        raise ControlError("COMMAND_DIGEST_INVALID")
    return value


def _copy(value: Any, maximum: int = 16384) -> Any:
    try:
        raw = canonical_bytes(value)
        if len(raw) > maximum:
            raise ControlError("COMMAND_PACKET_TOO_LARGE")
        return json.loads(raw)
    except (UnicodeError, RecursionError, OverflowError, TypeError) as exc:
        raise ControlError("COMMAND_JSON_INVALID") from exc


def command_spec(command_id: str, image_id: str, host_workspace: str,
                 fixture: str = "positive") -> dict[str, Any]:
    """Build the one approved fixture plan; every derived field is immutable."""
    validate_id(command_id, "command_id")
    if fixture not in ("positive", "descendant"):
        raise ControlError("COMMAND_FIXTURE_INVALID")
    try:
        plan = IsolatedExecutionPlan.build(operation_id=command_id, image_id=image_id,
            argv=("-I", "-u", "/workspace/external_command_fixture.py", fixture),
            host_workspace=host_workspace, timeout_seconds=30, profile=IsolationProfile())
    except (IsolationError, TypeError, ValueError) as exc:
        raise ControlError("COMMAND_SPEC_INVALID") from exc
    return {"schema": COMMAND_SPEC_SCHEMA, "command_id": command_id, "image_id": image_id,
        "host_workspace": host_workspace, "fixture": fixture, "argv": list(plan.argv),
        "timeout_seconds": plan.timeout_seconds, "isolation": plan.profile.body(),
        "working_directory": "/workspace", "environment_policy": "image-default-no-injected-env",
        "workspace_mount": {"source": host_workspace, "target": "/workspace", "read_only": True},
        "entrypoint": "python3", "log_driver": "none", "plan_sha256": plan.plan_sha256,
        "fixture_sha256": COMMAND_FIXTURE_SHA256}


def validate_command_spec(value: Any) -> dict[str, Any]:
    value = _copy(value)
    if type(value) is not dict or set(value) != _SPEC_FIELDS:
        raise ControlError("COMMAND_SPEC_INVALID")
    expected = command_spec(value["command_id"], value["image_id"], value["host_workspace"], value["fixture"])
    # Canonical bytes preserve integer/float and bool/integer distinctions.
    if canonical_bytes(value) != canonical_bytes(expected):
        raise ControlError("COMMAND_SPEC_BINDING_MISMATCH")
    return value


def command_plan(spec: Any) -> IsolatedExecutionPlan:
    spec = validate_command_spec(spec)
    return IsolatedExecutionPlan.build(operation_id=spec["command_id"], image_id=spec["image_id"],
        argv=tuple(spec["argv"]), host_workspace=spec["host_workspace"], timeout_seconds=30,
        profile=IsolationProfile())


def validate_command_action(value: Any) -> dict[str, Any]:
    value = _copy(value)
    if type(value) is not dict or set(value) != ACTION_FIELDS or value["target"] != "command":
        raise ControlError("COMMAND_ACTION_INVALID")
    for field in ("action_id", "attempt_id", "root_id", "execution_id"):
        validate_id(value[field], field)
    if type(value["epoch"]) is not int or not 1 <= value["epoch"] < 2**63:
        raise ControlError("COMMAND_EPOCH_INVALID")
    args = value["arguments"]
    if type(args) is not dict or set(args) != {"stage", "spec", "parent_reservation_id", "container_id"}:
        raise ControlError("COMMAND_STAGE_INVALID")
    validate_command_spec(args["spec"])
    if args["stage"] == "CREATE":
        if args["parent_reservation_id"] is not None or args["container_id"] is not None:
            raise ControlError("COMMAND_CREATE_BINDING_INVALID")
    elif args["stage"] == "START":
        validate_id(args["parent_reservation_id"], "parent_reservation_id")
        _hex(args["container_id"])
    else:
        raise ControlError("COMMAND_STAGE_INVALID")
    return value


def command_action(*, action_id: str, attempt_id: str, root_id: str, execution_id: str, epoch: int,
                   stage: str, spec: Any, parent_reservation_id: str | None = None,
                   container_id: str | None = None) -> dict[str, Any]:
    return validate_command_action({"action_id": action_id, "attempt_id": attempt_id,
        "root_id": root_id, "execution_id": execution_id, "epoch": epoch, "target": "command",
        "arguments": {"stage": stage, "spec": spec, "parent_reservation_id": parent_reservation_id,
                      "container_id": container_id}})


def validate_supervisor_pin(value: Any) -> dict[str, str]:
    value = _copy(value, 2048)
    if type(value) is not dict or set(value) != {"supervisor_id", "key_id", "public_key"}:
        raise ControlError("COMMAND_SUPERVISOR_PIN_INVALID")
    validate_id(value["supervisor_id"], "supervisor_id")
    validate_id(value["key_id"], "key_id")
    _hex(value["public_key"])
    return value


def validate_command_authorization(action: Any, value: Any, supervisor_id: str) -> dict[str, Any]:
    action, value = validate_command_action(action), _copy(value, 2048)
    validate_id(supervisor_id, "supervisor_id")
    if type(value) is not dict or set(value) != {"action_digest", "policy_version", "expires_at", "receiver_id"}:
        raise ControlError("COMMAND_AUTHORIZATION_INVALID")
    _hex(value["action_digest"])
    _hex(value["policy_version"])
    validate_id(value["receiver_id"], "receiver_id")
    expiry = value["expires_at"]
    if (type(expiry) not in (int, float) or not math.isfinite(expiry) or expiry < 0
            or value["action_digest"] != digest(action) or value["receiver_id"] != supervisor_id):
        raise ControlError("COMMAND_AUTHORIZATION_BINDING_MISMATCH")
    return value


def command_receipt_body(receipt: Any, pin: Any) -> dict[str, Any]:
    receipt, pin = _copy(receipt), validate_supervisor_pin(pin)
    if type(receipt) is not dict or set(receipt) != COMMAND_RECEIPT_FIELDS:
        raise ControlError("COMMAND_RECEIPT_INVALID")
    if (receipt["schema"] != COMMAND_RECEIPT_SCHEMA or receipt["status"] != "QUIESCENT"
            or receipt["supervisor_id"] != pin["supervisor_id"] or receipt["key_id"] != pin["key_id"]
            or any(receipt[field] is not True for field in
                   ("create_confirmed", "callbacks_finished", "process_quiescent"))
            or type(receipt["start_admitted"]) is not bool
            or receipt["business_effects"] != "NOT_ESTABLISHED"
            or receipt["stage"] not in ("CREATE", "START")
            or receipt["start_outcome"] != ("STARTED" if receipt["start_admitted"] else "NOT_STARTED")
            or (receipt["stage"] == "START" and receipt["start_admitted"] is not True)):
        raise ControlError("COMMAND_RECEIPT_INVALID")
    for field in ("supervisor_id", "key_id", "reservation_id", "action_id", "attempt_id", "root_id",
                  "execution_id", "command_id"):
        validate_id(receipt[field], field)
    if type(receipt["epoch"]) is not int or not 1 <= receipt["epoch"] < 2**63:
        raise ControlError("COMMAND_RECEIPT_INVALID")
    for field in ("action_digest", "authorization_digest", "container_id", "plan_sha256", "ownership_digest",
                  "observation_digest"):
        _hex(receipt[field])
    if (type(receipt["image_id"]) is not str or not receipt["image_id"].startswith("sha256:")
            or len(receipt["image_id"]) != 71):
        raise ControlError("COMMAND_RECEIPT_INVALID")
    _hex(receipt["image_id"][7:])
    _hex(receipt["signature"], 128)
    at = receipt["observed_at"]
    if type(at) not in (int, float) or not math.isfinite(at) or at < 0:
        raise ControlError("COMMAND_RECEIPT_INVALID")
    return {k: v for k, v in receipt.items() if k != "signature"}


def verify_command_receipt(receipt: Any, pin: Any) -> bool:
    try:
        body = command_receipt_body(receipt, pin)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin["public_key"])).verify(
            bytes.fromhex(receipt["signature"]), COMMAND_RECEIPT_DOMAIN + canonical_bytes(body))
        return True
    except Exception:
        return False
