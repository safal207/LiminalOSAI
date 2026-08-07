"""Issue and verify Portable Action Receipt v1.2."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable, Mapping

from sdk.liminal_governance_capsule import (
    GovernanceTrustStore,
    SignedGovernanceCapsule,
    base64url_decode,
    base64url_encode,
    derive_public_key,
    sign_ed25519,
    verify_capsule,
    verify_capsule_against_engine,
    verify_ed25519,
)
from sdk.liminal_identity_attestation import (
    IdentityAttestationBundle,
    IdentityTrustStore,
    verify_identity_bundle,
)

from ._contracts import (
    ALGORITHM,
    AUTHORITY,
    REDACTION_PROFILE,
    VERIFICATION_SCHEMA,
    ActionEvidence,
    BoundaryEvidence,
    CIGateEvidence,
    PortableActionReceipt,
    ReceiptClaims,
    ReceiptError,
    RecoveryEvidence,
    canonical_sha256,
    git_oid,
    identifier,
    repository,
    sha256,
    unix_time,
)


def _atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent,
        prefix=f".{path.name}.", delete=False,
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _read_json(path: Path, name: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReceiptError(f"{name} does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ReceiptError(f"{name} is not valid JSON: {exc}") from exc


def _read_private_key(path: str | Path) -> bytes:
    target = Path(path)
    try:
        value = target.read_bytes()
    except FileNotFoundError as exc:
        raise ReceiptError(f"private key does not exist: {target}") from exc
    if not value.startswith(b"-----BEGIN PRIVATE KEY-----\n"):
        raise ReceiptError("private key must be an unencrypted PKCS#8 PEM key")
    return value


def _capsule(value: SignedGovernanceCapsule | Mapping[str, Any]) -> SignedGovernanceCapsule:
    try:
        return value if isinstance(value, SignedGovernanceCapsule) else SignedGovernanceCapsule.from_document(dict(value))
    except Exception as exc:
        raise ReceiptError(f"invalid governance capsule: {exc}") from exc


def _bundle(value: IdentityAttestationBundle | Mapping[str, Any]) -> IdentityAttestationBundle:
    try:
        return value if isinstance(value, IdentityAttestationBundle) else IdentityAttestationBundle.from_document(dict(value))
    except Exception as exc:
        raise ReceiptError(f"invalid identity bundle: {exc}") from exc


def _governance_store(value: GovernanceTrustStore | Mapping[str, Any]) -> GovernanceTrustStore:
    try:
        return value if isinstance(value, GovernanceTrustStore) else GovernanceTrustStore.from_document(dict(value))
    except Exception as exc:
        raise ReceiptError(f"invalid governance trust store: {exc}") from exc


def _identity_store(value: IdentityTrustStore | Mapping[str, Any]) -> IdentityTrustStore:
    try:
        return value if isinstance(value, IdentityTrustStore) else IdentityTrustStore.from_document(dict(value))
    except Exception as exc:
        raise ReceiptError(f"invalid identity trust store: {exc}") from exc


def load_portable_receipt(path: str | Path) -> PortableActionReceipt:
    return PortableActionReceipt.from_document(_read_json(Path(path), "portable action receipt"))


def _safe_plan_map(value: Mapping[str, Any], allowed: frozenset[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in sorted(set(value) & allowed):
        item = value[key]
        if item is None or type(item) is bool or isinstance(item, int):
            result[key] = item
        elif isinstance(item, str) and item.strip() == item and item:
            result[key] = item
    return result


def _authorization_map(engine: Any) -> dict[str, list[tuple[str, str]]]:
    result: dict[str, list[tuple[str, str]]] = {}
    journal = engine.orchestrator.runtime.bridge.host.recorder.read()
    for entry in journal["entries"]:
        event = entry["event"]
        if event.get("type") != "user_authorization":
            continue
        event_id = event.get("id")
        entry_hash = entry.get("entry_sha256")
        if not isinstance(event_id, str) or not isinstance(entry_hash, str):
            continue
        for call_id in event.get("authorized_event_ids", []):
            result.setdefault(call_id, []).append((event_id, entry_hash))
    return result


def action_evidence_from_engine(engine: Any) -> tuple[ActionEvidence, ...]:
    """Project terminal v0.8 evidence into digest-only action records."""
    orchestrator = engine.orchestrator
    verification = orchestrator.verify(allow_pending=False)
    summary = verification["journal"]
    authorization = _authorization_map(engine)
    actions: list[ActionEvidence] = []
    for step in orchestrator.plan.steps:
        start = summary["starts"].get(step.step_id)
        finish = summary["finishes"].get(step.step_id)
        if start is None:
            continue
        if finish is None:
            raise ReceiptError(f"started step {step.step_id} has no terminal finish evidence")
        auth = sorted(authorization.get(step.call_id, []))
        if step.effect == "write" and not auth:
            raise ReceiptError(f"write step {step.step_id} lacks explicit authorization evidence")
        locator_hash = None
        if finish.get("locator") is not None:
            locator_hash = canonical_sha256({"locator": finish["locator"]})
        actions.append(
            ActionEvidence.build(
                step_id=step.step_id,
                call_id=step.call_id,
                action=step.action,
                effect=step.effect,
                request_sha256=start["request_sha256"],
                resolved_arguments_sha256=start["resolved_arguments_sha256"],
                runtime_status=finish["runtime_status"],
                locator_sha256=locator_hash,
                connected_receipt_sha256=finish.get("connected_receipt_sha256"),
                raw_response_sha256=finish.get("raw_response_sha256"),
                normalized_payload_sha256=finish.get("normalized_payload_sha256"),
                authorization_event_ids=[item[0] for item in auth],
                authorization_event_sha256s=[item[1] for item in auth],
                recorder_event_id=finish.get("recorder_event_id"),
                recorder_head_sha256=finish.get("recorder_head_sha256"),
                host_trace_head_sha256=finish.get("host_trace_head_sha256"),
                expectations_met=finish["expectations_met"],
                reconciled=finish["reconciled"],
                safe_bindings=_safe_plan_map(step.arguments, __import__("sdk.liminal_portable_receipt._contracts", fromlist=["SAFE_BINDING_KEYS"]).SAFE_BINDING_KEYS),
                safe_expectations=_safe_plan_map(step.expect, __import__("sdk.liminal_portable_receipt._contracts", fromlist=["SAFE_EXPECTATION_KEYS"]).SAFE_EXPECTATION_KEYS),
            )
        )
    return tuple(actions)


def derive_ci_gate(actions: Iterable[ActionEvidence]) -> CIGateEvidence:
    """Derive a bounded CI/exact-head observation from digest-only safe bindings."""
    checked: list[ActionEvidence] = []
    merged: list[ActionEvidence] = []
    for action in actions:
        if (
            action.action == "get_commit_combined_status"
            and action.runtime_status == "success"
            and action.expectations_met
            and action.safe_expectations.get("state") == "success"
            and isinstance(action.safe_bindings.get("commit_sha"), str)
        ):
            checked.append(action)
        if (
            action.action == "merge_pull_request"
            and action.runtime_status == "success"
            and action.expectations_met
            and isinstance(action.safe_bindings.get("expected_head_sha"), str)
        ):
            merged.append(action)
    if not checked:
        return CIGateEvidence.build(
            observed=False,
            checked_commit_oid=None,
            state="not_observed",
            merge_expected_head_oid=None,
            exact_head_verified=False,
        )
    check = checked[-1]
    checked_oid = git_oid(check.safe_bindings["commit_sha"], "ci checked commit")
    merge_oid = None
    exact = False
    if merged:
        candidate = git_oid(merged[-1].safe_bindings["expected_head_sha"], "merge expected head")
        merge_oid = candidate
        exact = candidate == checked_oid
    return CIGateEvidence.build(
        observed=True,
        checked_commit_oid=checked_oid,
        state="success",
        merge_expected_head_oid=merge_oid,
        exact_head_verified=exact,
    )


def _ensure_receipt_signer_matches_capsule(
    private_key: bytes,
    capsule: SignedGovernanceCapsule,
    store: GovernanceTrustStore,
    issued_at_unix: int,
) -> Any:
    claims = capsule.claims
    trusted = store.key_map.get((claims.issuer_id, claims.key_id))
    if trusted is None:
        raise ReceiptError("receipt signer is not present in governance trust store")
    derived = derive_public_key(private_key)
    if hashlib.sha256(derived).hexdigest() != trusted.public_key_sha256:
        raise ReceiptError("receipt private key does not match capsule governance key")
    if not (trusted.valid_from_unix <= issued_at_unix <= trusted.valid_until_unix):
        raise ReceiptError("receipt issuance is outside governance key validity")
    if trusted.revoked_at_unix is not None and issued_at_unix >= trusted.revoked_at_unix:
        raise ReceiptError("governance key was revoked before receipt issuance")
    return trusted


def _final_engine_hash(
    *,
    policy_sha256: str,
    snapshot_sha256: str,
    plan_sha256: str,
    approval_head_sha256: str,
    final_journal_sha256: str,
) -> str:
    return canonical_sha256(
        {
            "policy_sha256": policy_sha256,
            "snapshot_sha256": snapshot_sha256,
            "plan_sha256": plan_sha256,
            "approval_ledger_head_sha256": approval_head_sha256,
            "transaction_journal_head_sha256": final_journal_sha256,
        }
    )


def issue_portable_receipt_from_evidence(
    *,
    private_key_path: str | Path,
    governance_capsule: SignedGovernanceCapsule | Mapping[str, Any],
    identity_bundle: IdentityAttestationBundle | Mapping[str, Any],
    governance_trust_store: GovernanceTrustStore | Mapping[str, Any],
    identity_trust_store: IdentityTrustStore | Mapping[str, Any],
    receipt_id: str,
    intent_id: str,
    intent_sha256: str,
    source_head_oid: str,
    result_head_oid: str,
    policy_id: str,
    policy_sha256: str,
    snapshot_sha256: str,
    plan_sha256: str,
    approval_ledger_head_sha256: str,
    transaction_journal_final_sha256: str,
    actions: Iterable[ActionEvidence | Mapping[str, Any]],
    recovery: RecoveryEvidence | Mapping[str, Any],
    issued_at_unix: int | None = None,
    execution_verified_at_unix: int | None = None,
    expected_session_sha256: str | None = None,
    expected_tenant_id: str | None = None,
    expected_organization_id: str | None = None,
    expected_roles: Iterable[str] = (),
    ci_gate: CIGateEvidence | Mapping[str, Any] | None = None,
    capability: BoundaryEvidence | Mapping[str, Any] | None = None,
    containment: BoundaryEvidence | Mapping[str, Any] | None = None,
    output_path: str | Path | None = None,
) -> PortableActionReceipt:
    capsule = _capsule(governance_capsule)
    bundle = _bundle(identity_bundle)
    governance_store = _governance_store(governance_trust_store)
    identity_store = _identity_store(identity_trust_store)
    issued = unix_time(int(time.time()) if issued_at_unix is None else issued_at_unix, "issued_at_unix")
    evidence_time = unix_time(issued if execution_verified_at_unix is None else execution_verified_at_unix, "execution_verified_at_unix")
    if evidence_time > issued:
        raise ReceiptError("execution evidence time cannot be after receipt issuance")
    try:
        identity_verification = verify_identity_bundle(
            bundle,
            identity_store,
            capsule,
            governance_store,
            at_unix=evidence_time,
            expected_session_sha256=expected_session_sha256,
            expected_tenant_id=expected_tenant_id,
            expected_organization_id=expected_organization_id,
            expected_roles=list(expected_roles),
        )
    except Exception as exc:
        raise ReceiptError(f"identity-bound capsule evidence is invalid: {exc}") from exc
    private_key = _read_private_key(private_key_path)
    _ensure_receipt_signer_matches_capsule(private_key, capsule, governance_store, issued)

    action_items = tuple(
        item if isinstance(item, ActionEvidence) else ActionEvidence.from_value(dict(item))
        for item in actions
    )
    recovery_item = recovery if isinstance(recovery, RecoveryEvidence) else RecoveryEvidence.from_value(dict(recovery))
    ci_item = (
        derive_ci_gate(action_items)
        if ci_gate is None
        else ci_gate if isinstance(ci_gate, CIGateEvidence) else CIGateEvidence.from_value(dict(ci_gate))
    )
    capability_item = (
        BoundaryEvidence.pending("capability-broker-pending-v1.2")
        if capability is None
        else capability if isinstance(capability, BoundaryEvidence) else BoundaryEvidence.from_value(dict(capability), "capability")
    )
    containment_item = (
        BoundaryEvidence.pending("containment-pending-v1.2")
        if containment is None
        else containment if isinstance(containment, BoundaryEvidence) else BoundaryEvidence.from_value(dict(containment), "containment")
    )

    capsule_subject = capsule.claims.subject
    if policy_id != capsule_subject.policy_id:
        raise ReceiptError("receipt policy_id does not match governance capsule")
    for name, supplied, embedded in (
        ("policy_sha256", policy_sha256, capsule_subject.policy_sha256),
        ("snapshot_sha256", snapshot_sha256, capsule_subject.snapshot_sha256),
        ("plan_sha256", plan_sha256, capsule_subject.plan_sha256),
        ("approval_ledger_head_sha256", approval_ledger_head_sha256, capsule_subject.approval_ledger_head_sha256),
    ):
        if sha256(supplied, name) != embedded:
            raise ReceiptError(f"receipt {name} does not match governance capsule")
    final_journal = sha256(transaction_journal_final_sha256, "transaction_journal_final_sha256")
    final_engine = _final_engine_hash(
        policy_sha256=capsule_subject.policy_sha256,
        snapshot_sha256=capsule_subject.snapshot_sha256,
        plan_sha256=capsule_subject.plan_sha256,
        approval_head_sha256=capsule_subject.approval_ledger_head_sha256,
        final_journal_sha256=final_journal,
    )
    roles = tuple(sorted(identity_verification["roles"]))
    claims = ReceiptClaims(
        receipt_id=identifier(receipt_id, "receipt_id"),
        issuer_id=capsule.claims.issuer_id,
        subject_id=identity_verification["subject_id"],
        tenant_id=identity_verification["tenant_id"],
        organization_id=identity_verification["organization_id"],
        roles=roles,
        session_sha256=identity_verification["session_sha256"],
        key_id=capsule.claims.key_id,
        algorithm=ALGORITHM,
        audience=capsule.claims.audience,
        issued_at_unix=issued,
        execution_verified_at_unix=evidence_time,
        intent_id=identifier(intent_id, "intent_id"),
        intent_sha256=sha256(intent_sha256, "intent_sha256"),
        transaction_id=capsule_subject.transaction_id,
        repository_full_name=capsule_subject.repository_full_name,
        source_head_oid=git_oid(source_head_oid, "source_head_oid"),
        result_head_oid=git_oid(result_head_oid, "result_head_oid"),
        policy_id=capsule_subject.policy_id,
        policy_sha256=capsule_subject.policy_sha256,
        snapshot_sha256=capsule_subject.snapshot_sha256,
        plan_sha256=capsule_subject.plan_sha256,
        approval_ledger_head_sha256=capsule_subject.approval_ledger_head_sha256,
        transaction_journal_anchor_sha256=capsule_subject.transaction_journal_anchor_sha256,
        transaction_journal_final_sha256=final_journal,
        capsule_engine_evidence_sha256=capsule_subject.engine_evidence_sha256,
        final_engine_evidence_sha256=final_engine,
        governance_capsule_sha256=capsule.capsule_sha256,
        identity_assertion_sha256=identity_verification["identity_assertion_sha256"],
        kms_attestation_sha256=identity_verification["kms_attestation_sha256"],
        identity_bundle_sha256=identity_verification["bundle_sha256"],
        identity_verification_sha256=canonical_sha256(identity_verification),
        actions=action_items,
        actions_root_sha256=canonical_sha256([item.payload() for item in action_items]),
        ci_gate=ci_item,
        recovery=recovery_item,
        capability=capability_item,
        containment=containment_item,
        terminal_status=recovery_item.status,
    )
    claims = ReceiptClaims.from_value(claims.payload())
    unsigned = PortableActionReceipt(
        claims=claims,
        governance_capsule=capsule.as_document(),
        identity_bundle=bundle.as_document(),
        payload_sha256="0" * 64,
        signature_b64url="AA",
    )
    payload_hash = canonical_sha256(unsigned.unsigned_payload())
    signing_view = PortableActionReceipt(
        claims=claims,
        governance_capsule=capsule.as_document(),
        identity_bundle=bundle.as_document(),
        payload_sha256=payload_hash,
        signature_b64url="AA",
    )
    signature = sign_ed25519(private_key, signing_view.signed_message)
    receipt = PortableActionReceipt.from_document(
        PortableActionReceipt(
            claims=claims,
            governance_capsule=capsule.as_document(),
            identity_bundle=bundle.as_document(),
            payload_sha256=payload_hash,
            signature_b64url=base64url_encode(signature),
        ).as_document()
    )
    if output_path is not None:
        target = Path(output_path)
        if target.exists():
            raise ReceiptError(f"portable receipt already exists: {target}")
        _atomic_write_json(target, receipt.as_document())
    return receipt


def issue_portable_receipt_from_engine(
    engine: Any,
    *,
    private_key_path: str | Path,
    governance_capsule: SignedGovernanceCapsule | Mapping[str, Any],
    identity_bundle: IdentityAttestationBundle | Mapping[str, Any],
    governance_trust_store: GovernanceTrustStore | Mapping[str, Any],
    identity_trust_store: IdentityTrustStore | Mapping[str, Any],
    receipt_id: str,
    intent_id: str,
    intent_sha256: str,
    source_head_oid: str,
    result_head_oid: str,
    issued_at_unix: int | None = None,
    execution_verified_at_unix: int | None = None,
    expected_session_sha256: str | None = None,
    expected_tenant_id: str | None = None,
    expected_organization_id: str | None = None,
    expected_roles: Iterable[str] = (),
    output_path: str | Path | None = None,
) -> PortableActionReceipt:
    verification = engine.verify(allow_pending=False)
    transaction = verification["transaction"]["journal"]
    if transaction["status"] not in {"completed", "halted", "aborted"}:
        raise ReceiptError("portable receipt requires a terminal transaction")
    capsule = _capsule(governance_capsule)
    evidence_time = (
        int(time.time()) if execution_verified_at_unix is None else execution_verified_at_unix
    )
    try:
        verify_capsule_against_engine(
            capsule,
            _governance_store(governance_trust_store),
            engine,
            at_unix=evidence_time,
            expected_audience=capsule.claims.audience,
        )
    except Exception as exc:
        raise ReceiptError(f"governance capsule no longer matches engine: {exc}") from exc
    summary = engine.evidence_summary()
    recovery = RecoveryEvidence.build(engine.orchestrator.recovery_report())
    return issue_portable_receipt_from_evidence(
        private_key_path=private_key_path,
        governance_capsule=capsule,
        identity_bundle=identity_bundle,
        governance_trust_store=governance_trust_store,
        identity_trust_store=identity_trust_store,
        receipt_id=receipt_id,
        intent_id=intent_id,
        intent_sha256=intent_sha256,
        source_head_oid=source_head_oid,
        result_head_oid=result_head_oid,
        policy_id=verification["policy_id"],
        policy_sha256=verification["policy_sha256"],
        snapshot_sha256=verification["snapshot_sha256"],
        plan_sha256=verification["plan_sha256"],
        approval_ledger_head_sha256=verification["approval"]["head_sha256"],
        transaction_journal_final_sha256=transaction["head_sha256"],
        actions=action_evidence_from_engine(engine),
        recovery=recovery,
        issued_at_unix=issued_at_unix,
        execution_verified_at_unix=evidence_time,
        expected_session_sha256=expected_session_sha256,
        expected_tenant_id=expected_tenant_id,
        expected_organization_id=expected_organization_id,
        expected_roles=expected_roles,
        output_path=output_path,
    )


def verify_portable_receipt(
    receipt: PortableActionReceipt | Mapping[str, Any],
    governance_trust_store: GovernanceTrustStore | Mapping[str, Any],
    identity_trust_store: IdentityTrustStore | Mapping[str, Any],
    *,
    expected_repository: str | None = None,
    expected_source_head_oid: str | None = None,
    expected_result_head_oid: str | None = None,
) -> dict[str, Any]:
    value = receipt if isinstance(receipt, PortableActionReceipt) else PortableActionReceipt.from_document(dict(receipt))
    claims = value.claims
    governance_store = _governance_store(governance_trust_store)
    identity_store = _identity_store(identity_trust_store)
    capsule = _capsule(value.governance_capsule)
    bundle = _bundle(value.identity_bundle)
    if capsule.capsule_sha256 != claims.governance_capsule_sha256:
        raise ReceiptError("embedded governance capsule SHA mismatch")
    if bundle.bundle_sha256 != claims.identity_bundle_sha256:
        raise ReceiptError("embedded identity bundle SHA mismatch")
    if (
        claims.issuer_id != capsule.claims.issuer_id
        or claims.key_id != capsule.claims.key_id
        or claims.subject_id != capsule.claims.subject_id
        or claims.audience != capsule.claims.audience
        or claims.transaction_id != capsule.claims.subject.transaction_id
        or claims.repository_full_name != capsule.claims.subject.repository_full_name
        or claims.transaction_journal_anchor_sha256 != capsule.claims.subject.transaction_journal_anchor_sha256
        or claims.capsule_engine_evidence_sha256 != capsule.claims.subject.engine_evidence_sha256
    ):
        raise ReceiptError("receipt claims do not match embedded governance capsule")
    for name in ("policy_sha256", "snapshot_sha256", "plan_sha256", "approval_ledger_head_sha256"):
        if getattr(claims, name) != getattr(capsule.claims.subject, name):
            raise ReceiptError(f"receipt {name} does not match embedded capsule")
    expected_final_engine = _final_engine_hash(
        policy_sha256=claims.policy_sha256,
        snapshot_sha256=claims.snapshot_sha256,
        plan_sha256=claims.plan_sha256,
        approval_head_sha256=claims.approval_ledger_head_sha256,
        final_journal_sha256=claims.transaction_journal_final_sha256,
    )
    if expected_final_engine != claims.final_engine_evidence_sha256:
        raise ReceiptError("final_engine_evidence_sha256 mismatch")
    try:
        capsule_verification = verify_capsule(
            capsule,
            governance_store,
            at_unix=claims.execution_verified_at_unix,
            expected_audience=claims.audience,
            expected_repository=claims.repository_full_name,
            expected_plan_sha256=claims.plan_sha256,
            expected_policy_sha256=claims.policy_sha256,
        )
        identity_verification = verify_identity_bundle(
            bundle,
            identity_store,
            capsule,
            governance_store,
            at_unix=claims.execution_verified_at_unix,
            expected_session_sha256=claims.session_sha256,
            expected_tenant_id=claims.tenant_id,
            expected_organization_id=claims.organization_id,
            expected_roles=list(claims.roles),
        )
    except Exception as exc:
        raise ReceiptError(f"embedded trust evidence failed historical verification: {exc}") from exc
    for name in ("identity_assertion_sha256", "kms_attestation_sha256"):
        if identity_verification[name] != getattr(claims, name):
            raise ReceiptError(f"receipt {name} mismatch")
    if canonical_sha256(identity_verification) != claims.identity_verification_sha256:
        raise ReceiptError("identity_verification_sha256 mismatch")
    trusted = governance_store.key_map.get((claims.issuer_id, claims.key_id))
    if trusted is None:
        raise ReceiptError("receipt signing key is not trusted")
    if claims.audience not in trusted.allowed_audiences or claims.repository_full_name not in trusted.allowed_repositories:
        raise ReceiptError("receipt audience or repository is not permitted by signing key")
    if not (trusted.valid_from_unix <= claims.issued_at_unix <= trusted.valid_until_unix):
        raise ReceiptError("receipt was issued outside signing key validity")
    if trusted.revoked_at_unix is not None and claims.issued_at_unix >= trusted.revoked_at_unix:
        raise ReceiptError("receipt was issued after signing key revocation")
    signature = base64url_decode(value.signature_b64url)
    if len(signature) != 64:
        raise ReceiptError("portable receipt Ed25519 signature must contain 64 bytes")
    if not verify_ed25519(trusted.public_key_pem.encode("utf-8"), value.signed_message, signature):
        raise ReceiptError("portable receipt signature verification failed")
    if expected_repository is not None and claims.repository_full_name != repository(expected_repository, "expected_repository"):
        raise ReceiptError("portable receipt repository mismatch")
    if expected_source_head_oid is not None and claims.source_head_oid != git_oid(expected_source_head_oid, "expected_source_head_oid"):
        raise ReceiptError("portable receipt source head mismatch")
    if expected_result_head_oid is not None and claims.result_head_oid != git_oid(expected_result_head_oid, "expected_result_head_oid"):
        raise ReceiptError("portable receipt result head mismatch")
    return {
        "schema_version": VERIFICATION_SCHEMA,
        "status": "valid",
        "receipt_id": claims.receipt_id,
        "receipt_sha256": value.receipt_sha256,
        "payload_sha256": value.payload_sha256,
        "subject_id": claims.subject_id,
        "tenant_id": claims.tenant_id,
        "organization_id": claims.organization_id,
        "repository_full_name": claims.repository_full_name,
        "transaction_id": claims.transaction_id,
        "source_head_oid": claims.source_head_oid,
        "result_head_oid": claims.result_head_oid,
        "terminal_status": claims.terminal_status,
        "actions_root_sha256": claims.actions_root_sha256,
        "transaction_journal_final_sha256": claims.transaction_journal_final_sha256,
        "final_engine_evidence_sha256": claims.final_engine_evidence_sha256,
        "ci_gate": claims.ci_gate.payload(),
        "capability": claims.capability.payload(),
        "containment": claims.containment.payload(),
        "historical_evidence_time_unix": claims.execution_verified_at_unix,
        "receipt_issued_at_unix": claims.issued_at_unix,
        "capsule_verification": capsule_verification,
        "identity_verification_sha256": claims.identity_verification_sha256,
        "redaction_profile": REDACTION_PROFILE,
        "fresh_authorization": False,
        "authority": AUTHORITY,
    }


def verify_portable_receipt_against_engine(
    receipt: PortableActionReceipt | Mapping[str, Any],
    governance_trust_store: GovernanceTrustStore | Mapping[str, Any],
    identity_trust_store: IdentityTrustStore | Mapping[str, Any],
    engine: Any,
) -> dict[str, Any]:
    value = receipt if isinstance(receipt, PortableActionReceipt) else PortableActionReceipt.from_document(dict(receipt))
    result = verify_portable_receipt(value, governance_trust_store, identity_trust_store)
    current = engine.verify(allow_pending=False)
    evidence = engine.evidence_summary()
    claims = value.claims
    checks = {
        "transaction_id": current["transaction_id"],
        "repository_full_name": current["repository_full_name"],
        "policy_sha256": current["policy_sha256"],
        "snapshot_sha256": current["snapshot_sha256"],
        "plan_sha256": current["plan_sha256"],
        "approval_ledger_head_sha256": current["approval"]["head_sha256"],
        "transaction_journal_final_sha256": current["transaction"]["journal"]["head_sha256"],
        "final_engine_evidence_sha256": evidence["engine_evidence_sha256"],
    }
    for name, expected in checks.items():
        if getattr(claims, name) != expected:
            raise ReceiptError(f"portable receipt no longer matches engine field: {name}")
    if current["transaction"]["journal"]["status"] != claims.terminal_status:
        raise ReceiptError("portable receipt terminal status no longer matches engine")
    return {**result, "engine_status": "matched"}
