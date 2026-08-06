"""Issue and verify portable governance capsules above v0.9 policy evidence."""

from __future__ import annotations

import json
import os
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from ._contracts import (
    ALGORITHM,
    AUTHORITY,
    MAX_CAPSULE_TTL_SECONDS,
    VERIFICATION_SCHEMA,
    CapsuleClaims,
    CapsuleError,
    GovernanceSubject,
    GovernanceTrustStore,
    SignedGovernanceCapsule,
    canonical_sha256,
    identifier,
    positive_int,
    repository,
    unix_time,
)
from ._crypto import base64url_decode, base64url_encode, sign_ed25519, verify_ed25519


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
        raise CapsuleError(f"{name} does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CapsuleError(f"{name} is not valid JSON: {exc}") from exc


def _read_private_key(path: str | Path) -> bytes:
    target = Path(path)
    try:
        value = target.read_bytes()
    except FileNotFoundError as exc:
        raise CapsuleError(f"private key does not exist: {target}") from exc
    if not value.startswith(b"-----BEGIN PRIVATE KEY-----\n"):
        raise CapsuleError("private key must be an unencrypted PKCS#8 PEM key")
    return value


def _engine_subject(engine: Any) -> GovernanceSubject:
    verification = engine.verify(allow_pending=True)
    if verification["decision"] != "allow":
        raise CapsuleError("cannot issue capsule for a policy-denied transaction")
    if verification["approval"]["status"] != "ready":
        raise CapsuleError("cannot issue capsule before all approvals are ready")
    evidence = engine.evidence_summary()
    return GovernanceSubject.from_value({
        "policy_id": verification["policy_id"],
        "transaction_id": verification["transaction_id"],
        "repository_full_name": verification["repository_full_name"],
        "policy_sha256": verification["policy_sha256"],
        "snapshot_sha256": verification["snapshot_sha256"],
        "plan_sha256": verification["plan_sha256"],
        "approval_ledger_head_sha256": verification["approval"]["head_sha256"],
        "transaction_journal_anchor_sha256": verification["transaction"]["journal"]["head_sha256"],
        "engine_evidence_sha256": evidence["engine_evidence_sha256"],
        "decision": verification["decision"],
        "approval_status": verification["approval"]["status"],
    })


def issue_capsule(
    engine: Any,
    *,
    private_key_path: str | Path,
    capsule_id: str,
    issuer_id: str,
    subject_id: str,
    key_id: str,
    audience: str,
    ttl_seconds: int,
    issued_at_unix: int | None = None,
    not_before_delay_seconds: int = 0,
    nonce: str | None = None,
    output_path: str | Path | None = None,
) -> SignedGovernanceCapsule:
    ttl = positive_int(
        ttl_seconds, "ttl_seconds", maximum=MAX_CAPSULE_TTL_SECONDS
    )
    issued = unix_time(
        int(time.time()) if issued_at_unix is None else issued_at_unix,
        "issued_at_unix",
    )
    if isinstance(not_before_delay_seconds, bool) or not isinstance(
        not_before_delay_seconds, int
    ) or not_before_delay_seconds < 0:
        raise CapsuleError("not_before_delay_seconds must be a non-negative integer")
    if not_before_delay_seconds >= ttl:
        raise CapsuleError("not_before_delay_seconds must be less than ttl_seconds")
    claims = CapsuleClaims(
        capsule_id=identifier(capsule_id, "capsule_id"),
        issuer_id=identifier(issuer_id, "issuer_id"),
        subject_id=identifier(subject_id, "subject_id"),
        key_id=identifier(key_id, "key_id"),
        algorithm=ALGORITHM,
        audience=identifier(audience, "audience"),
        issued_at_unix=issued,
        not_before_unix=issued + not_before_delay_seconds,
        expires_at_unix=issued + ttl,
        nonce=identifier(nonce or secrets.token_hex(16), "nonce"),
        subject=_engine_subject(engine),
    )
    payload_hash = canonical_sha256(claims.payload())
    unsigned = SignedGovernanceCapsule(
        claims=claims, payload_sha256=payload_hash, signature_b64url="AA"
    )
    signature = sign_ed25519(_read_private_key(private_key_path), unsigned.signed_message)
    capsule = SignedGovernanceCapsule.from_document(
        SignedGovernanceCapsule(
            claims=claims,
            payload_sha256=payload_hash,
            signature_b64url=base64url_encode(signature),
        ).as_document()
    )
    if output_path is not None:
        target = Path(output_path)
        if target.exists():
            raise CapsuleError(f"capsule already exists: {target}")
        _atomic_write_json(target, capsule.as_document())
    return capsule


def load_capsule(path: str | Path) -> SignedGovernanceCapsule:
    return SignedGovernanceCapsule.from_document(
        _read_json(Path(path), "governance capsule")
    )


def load_trust_store(path: str | Path) -> GovernanceTrustStore:
    return GovernanceTrustStore.from_document(
        _read_json(Path(path), "governance trust store")
    )


def verify_capsule(
    capsule: SignedGovernanceCapsule | dict[str, Any],
    trust_store: GovernanceTrustStore | dict[str, Any],
    *,
    at_unix: int | None = None,
    expected_audience: str | None = None,
    expected_repository: str | None = None,
    expected_plan_sha256: str | None = None,
    expected_policy_sha256: str | None = None,
) -> dict[str, Any]:
    capsule_value = (
        capsule
        if isinstance(capsule, SignedGovernanceCapsule)
        else SignedGovernanceCapsule.from_document(capsule)
    )
    store = (
        trust_store
        if isinstance(trust_store, GovernanceTrustStore)
        else GovernanceTrustStore.from_document(trust_store)
    )
    claims = capsule_value.claims
    trusted_key = store.key_map.get((claims.issuer_id, claims.key_id))
    if trusted_key is None:
        raise CapsuleError("capsule issuer_id/key_id is not trusted")
    if trusted_key.algorithm != claims.algorithm:
        raise CapsuleError("capsule algorithm does not match trusted key")
    if claims.audience not in trusted_key.allowed_audiences:
        raise CapsuleError("capsule audience is not permitted by trusted key")
    if claims.subject.repository_full_name not in trusted_key.allowed_repositories:
        raise CapsuleError("capsule repository is not permitted by trusted key")
    ttl = claims.expires_at_unix - claims.issued_at_unix
    if ttl > store.max_ttl_seconds:
        raise CapsuleError("capsule TTL exceeds trust-store maximum")
    now = unix_time(int(time.time()) if at_unix is None else at_unix, "at_unix")
    skew = store.max_clock_skew_seconds
    if now + skew < claims.not_before_unix:
        raise CapsuleError("capsule is not yet valid")
    if now - skew > claims.expires_at_unix:
        raise CapsuleError("capsule has expired")
    if claims.issued_at_unix < trusted_key.valid_from_unix:
        raise CapsuleError("capsule was issued before trusted key validity")
    if claims.issued_at_unix > trusted_key.valid_until_unix:
        raise CapsuleError("capsule was issued after trusted key validity")
    if now - skew > trusted_key.valid_until_unix:
        raise CapsuleError("trusted key validity has ended")
    if trusted_key.revoked_at_unix is not None and now >= trusted_key.revoked_at_unix:
        raise CapsuleError("trusted key is revoked")
    if expected_audience is not None and claims.audience != identifier(
        expected_audience, "expected_audience"
    ):
        raise CapsuleError("capsule audience mismatch")
    if expected_repository is not None and claims.subject.repository_full_name != repository(
        expected_repository, "expected_repository"
    ):
        raise CapsuleError("capsule repository mismatch")
    if expected_plan_sha256 is not None and claims.subject.plan_sha256 != expected_plan_sha256:
        raise CapsuleError("capsule plan SHA mismatch")
    if expected_policy_sha256 is not None and claims.subject.policy_sha256 != expected_policy_sha256:
        raise CapsuleError("capsule policy SHA mismatch")
    signature = base64url_decode(capsule_value.signature_b64url)
    if len(signature) != 64:
        raise CapsuleError("Ed25519 signature must contain 64 bytes")
    if not verify_ed25519(
        trusted_key.public_key_pem.encode("utf-8"),
        capsule_value.signed_message,
        signature,
    ):
        raise CapsuleError("capsule signature verification failed")
    return {
        "schema_version": VERIFICATION_SCHEMA,
        "status": "valid",
        "capsule_id": claims.capsule_id,
        "issuer_id": claims.issuer_id,
        "subject_id": claims.subject_id,
        "key_id": claims.key_id,
        "algorithm": claims.algorithm,
        "audience": claims.audience,
        "issued_at_unix": claims.issued_at_unix,
        "not_before_unix": claims.not_before_unix,
        "expires_at_unix": claims.expires_at_unix,
        "verified_at_unix": now,
        "repository_full_name": claims.subject.repository_full_name,
        "policy_sha256": claims.subject.policy_sha256,
        "snapshot_sha256": claims.subject.snapshot_sha256,
        "plan_sha256": claims.subject.plan_sha256,
        "approval_ledger_head_sha256": claims.subject.approval_ledger_head_sha256,
        "transaction_journal_anchor_sha256": claims.subject.transaction_journal_anchor_sha256,
        "engine_evidence_sha256": claims.subject.engine_evidence_sha256,
        "payload_sha256": capsule_value.payload_sha256,
        "capsule_sha256": capsule_value.capsule_sha256,
        "trust_store_sha256": store.trust_store_sha256,
        "authority": AUTHORITY,
    }


def verify_capsule_against_engine(
    capsule: SignedGovernanceCapsule | dict[str, Any],
    trust_store: GovernanceTrustStore | dict[str, Any],
    engine: Any,
    *,
    at_unix: int | None = None,
    expected_audience: str | None = None,
) -> dict[str, Any]:
    capsule_value = (
        capsule
        if isinstance(capsule, SignedGovernanceCapsule)
        else SignedGovernanceCapsule.from_document(capsule)
    )
    engine_state = engine.verify(allow_pending=True)
    basic = verify_capsule(
        capsule_value,
        trust_store,
        at_unix=at_unix,
        expected_audience=expected_audience,
        expected_repository=engine_state["repository_full_name"],
        expected_plan_sha256=engine_state["plan_sha256"],
        expected_policy_sha256=engine_state["policy_sha256"],
    )
    subject = capsule_value.claims.subject
    checks = {
        "policy_id": engine_state["policy_id"],
        "transaction_id": engine_state["transaction_id"],
        "repository_full_name": engine_state["repository_full_name"],
        "policy_sha256": engine_state["policy_sha256"],
        "snapshot_sha256": engine_state["snapshot_sha256"],
        "plan_sha256": engine_state["plan_sha256"],
        "approval_ledger_head_sha256": engine_state["approval"]["head_sha256"],
        "decision": engine_state["decision"],
        "approval_status": engine_state["approval"]["status"],
    }
    for key, current in checks.items():
        if getattr(subject, key) != current:
            raise CapsuleError(f"capsule subject no longer matches engine field: {key}")
    journal = engine.orchestrator.journal.read()
    anchor = subject.transaction_journal_anchor_sha256
    journal_hashes = {entry["entry_sha256"] for entry in journal["entries"]}
    if anchor != journal["head_sha256"] and anchor not in journal_hashes:
        raise CapsuleError("transaction journal is not a descendant of capsule anchor")
    return {
        **basic,
        "engine_status": "matched",
        "current_transaction_journal_head_sha256": journal["head_sha256"],
        "transaction_journal_anchor_is_ancestor": True,
    }


class GovernanceCapsuleSession:
    """Require one valid capsule before every governed v0.9 execution boundary."""

    def __init__(
        self,
        engine: Any,
        *,
        capsule_path: str | Path,
        trust_store_path: str | Path,
        expected_audience: str,
        clock: Callable[[], int] | None = None,
    ):
        self.engine = engine
        self.capsule_path = Path(capsule_path)
        self.trust_store_path = Path(trust_store_path)
        self.expected_audience = identifier(expected_audience, "expected_audience")
        self.clock = clock or (lambda: int(time.time()))

    def verify(self) -> dict[str, Any]:
        return verify_capsule_against_engine(
            load_capsule(self.capsule_path),
            load_trust_store(self.trust_store_path),
            self.engine,
            at_unix=self.clock(),
            expected_audience=self.expected_audience,
        )

    def prepare_next(self) -> dict[str, Any]:
        verification = self.verify()
        prepared = self.engine.prepare_next()
        return {
            "schema_version": VERIFICATION_SCHEMA,
            "capsule": verification,
            "next_step": prepared["next_step"],
            "approval_status": prepared["approval_status"],
            "policy_decision": prepared["policy_decision"],
            "authority": AUTHORITY,
        }

    def authorize_step(self, **kwargs: Any) -> dict[str, Any]:
        self.verify()
        return self.engine.authorize_step(**kwargs)

    def run_next(self, connector: Any) -> dict[str, Any]:
        self.verify()
        return self.engine.run_next(connector)

    def run(self, connector: Any) -> dict[str, Any]:
        self.verify()
        return self.engine.run(connector)

    def record_user_message(self, **kwargs: Any) -> dict[str, Any]:
        return self.engine.record_user_message(**kwargs)

    def record_assistant_draft(self, **kwargs: Any) -> dict[str, Any]:
        return self.engine.record_assistant_draft(**kwargs)

    def record_claim(self, **kwargs: Any) -> dict[str, Any]:
        return self.engine.record_claim(**kwargs)

    def seal(self, **kwargs: Any) -> dict[str, Any]:
        self.verify()
        return self.engine.seal(**kwargs)

    def export_live_session(self, output_path: str | Path) -> dict[str, Any]:
        self.verify()
        return self.engine.export_live_session(output_path)
