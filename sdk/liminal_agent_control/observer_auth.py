"""Host-owned public-key enrollment and exact, single-use observer challenges.

Private keys live in observer processes or services, never this
database. Signatures authenticate enrolled principals; they do not establish
semantic truth or independence of their evidence. Workers must not access host
enrollment, revocation, clock or database administration.
"""
from __future__ import annotations

import json
import re
import secrets
from typing import Any, TYPE_CHECKING

from .authority import ControlError, canonical_bytes, connect, digest, validate_id
from .orientation import _hash, _time

if TYPE_CHECKING:
    from .brakes_store import SessionAuthority

ATTESTATION_DOMAIN = b"liminal-observer-attestation-v1\x00"
CHALLENGE_SCHEMA = "liminal-observer-challenge-v1"
_SUBJECT = ("action_id", "root_id", "execution_id", "epoch", "action_digest",
            "projection_digest", "center_id", "predecessor_hash")
_REQUEST_FIELDS = set(_SUBJECT) | {"schema", "nonce", "issued_at", "valid_until",
    "observer_id", "role", "key_id", "ring_profile_digest", "auth_profile_digest",
    "policy_digest", "objective_digest", "orientation_profile_digest"}
_ENVELOPE_FIELDS = {"request", "verdict", "evidence_digest", "observed_at", "valid_until", "signature"}


def initialize_schema(db: Any) -> None:
    for statement in (
        """CREATE TABLE IF NOT EXISTS observer_auth_profiles (
            root_id TEXT PRIMARY KEY REFERENCES observer_ring_profiles(root_id),
            epoch INTEGER NOT NULL, ring_profile_digest TEXT NOT NULL,
            profile_digest TEXT NOT NULL, profile_json TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS observer_auth_challenges (
            nonce TEXT PRIMARY KEY, root_id TEXT NOT NULL REFERENCES observer_auth_profiles(root_id),
            action_id TEXT NOT NULL, observer_id TEXT NOT NULL, key_id TEXT NOT NULL,
            request_digest TEXT NOT NULL, request_json TEXT NOT NULL,
            issued_at REAL NOT NULL, valid_until REAL NOT NULL, envelope_digest TEXT,
            attestation_digest TEXT, consumed_at REAL)""",
        """CREATE TABLE IF NOT EXISTS observer_auth_proofs (
            attestation_digest TEXT PRIMARY KEY REFERENCES observer_ring_attestations(attestation_digest),
            nonce TEXT UNIQUE NOT NULL REFERENCES observer_auth_challenges(nonce),
            envelope_digest TEXT UNIQUE NOT NULL, envelope_json TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS observer_auth_revocations (
            root_id TEXT NOT NULL REFERENCES observer_auth_profiles(root_id), key_id TEXT NOT NULL,
            reason TEXT NOT NULL, revoked_at REAL NOT NULL, PRIMARY KEY(root_id,key_id))""",
    ):
        db.execute(statement)
    from .observer_sources import initialize_schema as initialize_sources
    initialize_sources(db)


def _crypto() -> tuple[Any, Any]:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        return Ed25519PrivateKey, Ed25519PublicKey
    except (ImportError, AttributeError) as exc:
        raise ControlError("OBSERVER_AUTH_CRYPTO_UNAVAILABLE") from exc


def _hex(value: Any, length: int) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value) is None:
        raise ControlError("OBSERVER_AUTH_MALFORMED")
    return value


def _profile(value: Any) -> dict[str, Any]:
    if (not isinstance(value, dict) or set(value) != {"keys", "max_challenge_age_seconds", "max_challenges"}
            or len(canonical_bytes(value)) > 65536):
        raise ControlError("OBSERVER_AUTH_MALFORMED")
    value = json.loads(canonical_bytes(value))
    if not isinstance(value["keys"], list) or not 1 <= len(value["keys"]) <= 256:
        raise ControlError("OBSERVER_AUTH_MALFORMED")
    identities, keys, public_keys = set(), set(), set()
    for key in value["keys"]:
        if not isinstance(key, dict) or set(key) != {"observer_id", "key_id", "public_key"}:
            raise ControlError("OBSERVER_AUTH_MALFORMED")
        validate_id(key["observer_id"], "observer_id")
        validate_id(key["key_id"], "key_id")
        _hex(key["public_key"], 64)
        if key["observer_id"] in identities or key["key_id"] in keys or key["public_key"] in public_keys:
            raise ControlError("OBSERVER_AUTH_DUPLICATE_KEY")
        identities.add(key["observer_id"])
        keys.add(key["key_id"])
        public_keys.add(key["public_key"])
    if _time(value["max_challenge_age_seconds"]) <= 0:
        raise ControlError("OBSERVER_AUTH_MALFORMED")
    if type(value["max_challenges"]) is not int or not len(value["keys"]) <= value["max_challenges"] < 2**31:
        raise ControlError("OBSERVER_AUTH_MALFORMED")
    return value


def _load(db: Any, root_id: str) -> tuple[Any, Any]:
    row = db.execute("SELECT * FROM observer_auth_profiles WHERE root_id=?", (root_id,)).fetchone()
    try:
        profile = _profile(json.loads(row["profile_json"])) if row else None
    except (ControlError, TypeError, ValueError, KeyError):
        raise ControlError("OBSERVER_AUTH_BINDING_MISMATCH")
    return row, profile


def auth_required_in_transaction(db: Any, root_id: str) -> bool:
    return bool(db.execute("SELECT 1 FROM observer_auth_profiles WHERE root_id=?", (root_id,)).fetchone())


def profile_reason_in_transaction(db: Any, root_id: str, *, ring_row: Any, ring_profile: Any) -> str | None:
    try:
        row, profile = _load(db, root_id)
        if row is None:
            return None
        if (row["epoch"] != ring_row["epoch"] or row["ring_profile_digest"] != ring_row["profile_digest"]
                or digest(profile) != row["profile_digest"] or digest(ring_profile) != ring_row["profile_digest"]
                or {item["observer_id"] for item in profile["keys"]}
                != {item["observer_id"] for item in ring_profile["observers"]}):
            return "OBSERVER_AUTH_BINDING_MISMATCH"
        if db.execute("SELECT 1 FROM observer_auth_revocations WHERE root_id=?", (root_id,)).fetchone():
            return "OBSERVER_AUTH_KEY_REVOKED"
        _crypto()
    except ControlError as exc:
        return str(exc)
    except (TypeError, ValueError, KeyError):
        return "OBSERVER_AUTH_BINDING_MISMATCH"
    return None


def _request(value: Any) -> dict[str, Any]:
    if (not isinstance(value, dict) or set(value) != _REQUEST_FIELDS
            or len(canonical_bytes(value)) > 16384 or value.get("schema") != CHALLENGE_SCHEMA):
        raise ControlError("OBSERVER_AUTH_MALFORMED")
    for field in ("action_id", "root_id", "execution_id", "center_id", "observer_id", "role", "key_id"):
        validate_id(value[field], field)
    for field in ("nonce", "action_digest", "projection_digest", "predecessor_hash", "ring_profile_digest",
                  "auth_profile_digest", "policy_digest", "objective_digest", "orientation_profile_digest"):
        _hex(value[field], 64)
    if type(value["epoch"]) is not int or not 1 <= value["epoch"] < 2**63:
        raise ControlError("OBSERVER_AUTH_MALFORMED")
    if _time(value["valid_until"]) <= _time(value["issued_at"]):
        raise ControlError("OBSERVER_AUTH_MALFORMED")
    return json.loads(canonical_bytes(value))


def _envelope(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _ENVELOPE_FIELDS or len(canonical_bytes(value)) > 32768:
        raise ControlError("OBSERVER_AUTH_MALFORMED")
    _request(value["request"])
    if value["verdict"] not in {"SUPPORT", "UNKNOWN", "VETO"}:
        raise ControlError("OBSERVER_AUTH_MALFORMED")
    _hash(value["evidence_digest"])
    _hex(value["signature"], 128)
    if _time(value["valid_until"]) <= _time(value["observed_at"]):
        raise ControlError("OBSERVER_AUTH_MALFORMED")
    return json.loads(canonical_bytes(value))


def sign_attestation(request: dict[str, Any], *, private_key: bytes, verdict: str,
                     evidence_digest: str, observed_at: float, valid_until: float) -> dict[str, Any]:
    """Observer-side signing; the private key is never sent to the authority."""
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise ControlError("OBSERVER_AUTH_MALFORMED")
    body = {"request": _request(request), "verdict": verdict, "evidence_digest": evidence_digest,
            "observed_at": observed_at, "valid_until": valid_until}
    provisional = _envelope({**body, "signature": "0" * 128})
    body = {key: value for key, value in provisional.items() if key != "signature"}
    private, _ = _crypto()
    return {**body, "signature": private.from_private_bytes(private_key).sign(
        ATTESTATION_DOMAIN + canonical_bytes(body)).hex()}


def _verify(envelope: Any, public_key: str) -> None:
    _, public = _crypto()
    try:
        body = {key: value for key, value in envelope.items() if key != "signature"}
        public.from_public_bytes(bytes.fromhex(public_key)).verify(bytes.fromhex(envelope["signature"]),
            ATTESTATION_DOMAIN + canonical_bytes(body))
    except (ValueError, TypeError, KeyError) as exc:
        raise ControlError("OBSERVER_AUTH_SIGNATURE_INVALID") from exc
    except Exception as exc:
        # Includes cryptography.exceptions.InvalidSignature without importing it
        # eagerly for roots that retain the legacy host-authenticated adapter.
        raise ControlError("OBSERVER_AUTH_SIGNATURE_INVALID") from exc


def _binding_reason(db: Any, request: Any, challenge: Any, auth_row: Any,
                    profile: Any, ring_row: Any, ring_profile: Any, projection: Any) -> str | None:
    if (challenge is None or digest(request) != challenge["request_digest"]
            or canonical_bytes(request).decode() != challenge["request_json"]
            or any(request[field] != challenge[field] for field in
                   ("nonce", "root_id", "action_id", "observer_id", "key_id", "issued_at", "valid_until"))
            or request["auth_profile_digest"] != auth_row["profile_digest"]
            or request["ring_profile_digest"] != ring_row["profile_digest"]
            or any(request[field] != ring_row[field] for field in
                   ("epoch", "policy_digest", "objective_digest", "orientation_profile_digest"))
            or projection is None or any(type(request[field]) is not type(projection[field])
                or request[field] != projection[field] for field in _SUBJECT)):
        return "OBSERVER_AUTH_BINDING_MISMATCH"
    key = next((item for item in profile["keys"] if item["observer_id"] == request["observer_id"]), None)
    observer = next((item for item in ring_profile["observers"] if item["observer_id"] == request["observer_id"]), None)
    if key is None or observer is None or key["key_id"] != request["key_id"] or observer["role"] != request["role"]:
        return "OBSERVER_AUTH_BINDING_MISMATCH"
    return None


def attestation_reason_in_transaction(db: Any, stored: Any, attestation: Any, *, now: float | None = None) -> str | None:
    if not auth_required_in_transaction(db, stored["root_id"]):
        return None
    try:
        from .observer_ring import _load as load_ring, _projection, _projection_reason
        row, profile = _load(db, stored["root_id"])
        ring_row, ring_profile = load_ring(db, stored["root_id"])
        proof = db.execute("SELECT * FROM observer_auth_proofs WHERE attestation_digest=?",
                           (stored["attestation_digest"],)).fetchone()
        if proof is None:
            return "OBSERVER_AUTH_PROOF_REQUIRED"
        envelope = _envelope(json.loads(proof["envelope_json"]))
        request = envelope["request"]
        challenge = db.execute("SELECT * FROM observer_auth_challenges WHERE nonce=?", (proof["nonce"],)).fetchone()
        projection = _projection(db, stored["action_id"])
        reason = _binding_reason(db, request, challenge, row, profile, ring_row, ring_profile, projection)
        if reason:
            return reason
        if (_projection_reason(db, projection, ring_row) or request["nonce"] != proof["nonce"]
                or digest(envelope) != proof["envelope_digest"] or challenge["envelope_digest"] != proof["envelope_digest"]
                or challenge["attestation_digest"] != stored["attestation_digest"] or challenge["consumed_at"] is None
                or not challenge["issued_at"] <= challenge["consumed_at"] < challenge["valid_until"]
                or envelope["observed_at"] < challenge["issued_at"]
                or envelope["observed_at"] > challenge["consumed_at"]
                or envelope["valid_until"] > challenge["valid_until"]
                or envelope["valid_until"] <= challenge["consumed_at"]
                or challenge["valid_until"] > challenge["issued_at"] + profile["max_challenge_age_seconds"]
                or challenge["consumed_at"] - challenge["issued_at"] > profile["max_challenge_age_seconds"]
                or envelope["observed_at"] < projection["created_at"]
                or challenge["consumed_at"] - envelope["observed_at"] > ring_profile["max_attestation_age_seconds"]
                or envelope["valid_until"] > envelope["observed_at"] + ring_profile["max_attestation_age_seconds"]
                or (envelope["verdict"] != "VETO" and envelope["valid_until"]
                    > json.loads(projection["projection_json"])["deadline"])
                or stored["ingested_at"] != challenge["consumed_at"]):
            return "OBSERVER_AUTH_BINDING_MISMATCH"
        expected = {field: request[field] for field in _SUBJECT}
        expected.update(observer_id=request["observer_id"], role=request["role"],
            ring_profile_digest=request["ring_profile_digest"], **{field: envelope[field] for field in
                ("verdict", "evidence_digest", "observed_at", "valid_until")})
        expected["observed_at"] = _time(expected["observed_at"])
        expected["valid_until"] = _time(expected["valid_until"])
        if (canonical_bytes(expected) != canonical_bytes(attestation) or digest(expected) != stored["attestation_digest"]
                or any(stored[field] != expected[field] for field in ("root_id", "action_id", "observer_id"))
                or stored["slot"] != ("VETO" if envelope["verdict"] == "VETO" else "ASSESSMENT")):
            return "OBSERVER_AUTH_BINDING_MISMATCH"
        key = next(item for item in profile["keys"] if item["key_id"] == request["key_id"])
        _verify(envelope, key["public_key"])
        from .observer_sources import evidence_reason_in_transaction
        source_reason = evidence_reason_in_transaction(db, request, envelope, now=now, consumed_at=challenge["consumed_at"])
        if source_reason:
            return source_reason
    except ControlError as exc:
        return str(exc) if str(exc) in {"OBSERVER_AUTH_BINDING_MISMATCH",
            "OBSERVER_AUTH_SIGNATURE_INVALID", "OBSERVER_AUTH_CRYPTO_UNAVAILABLE"} else "OBSERVER_AUTH_BINDING_MISMATCH"
    except (TypeError, ValueError, KeyError, StopIteration):
        return "OBSERVER_AUTH_BINDING_MISMATCH"
    return None


class ObserverAuthStore:
    def __init__(self, authority: SessionAuthority) -> None:
        self.authority, self.db_path = authority, authority.db_path
        with connect(self.db_path) as db:
            initialize_schema(db)

    def _active(self, db: Any, root_id: str) -> Any:
        row, reason = self.authority._fresh(db, root_id)
        if reason:
            db.commit()
            raise ControlError(reason)
        return row

    @staticmethod
    def _require(db: Any, root_id: str) -> tuple[Any, Any, Any, Any]:
        from .observer_ring import _load as load_ring
        row, profile = _load(db, root_id)
        ring_row, ring_profile = load_ring(db, root_id)
        if row is None:
            raise ControlError("OBSERVER_AUTH_PROFILE_REQUIRED")
        reason = profile_reason_in_transaction(db, root_id, ring_row=ring_row, ring_profile=ring_profile)
        if reason:
            raise ControlError(reason)
        from .observer_sources import profile_reason_in_transaction as source_profile_reason
        source_reason = source_profile_reason(db, root_id)
        if source_reason:
            raise ControlError(source_reason)
        held = db.execute("SELECT reason FROM observer_ring_holds WHERE root_id=?", (root_id,)).fetchone()
        if held:
            raise ControlError(held[0])
        return row, profile, ring_row, ring_profile

    def install(self, root_id: str, profile: dict[str, Any]) -> dict[str, Any]:
        validate_id(root_id, "root_id")
        profile = _profile(profile)
        _crypto()
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            self._active(db, root_id)
            from .observer_ring import _load as load_ring
            ring_row, ring_profile = load_ring(db, root_id)
            if ring_row is None:
                raise ControlError("OBSERVER_AUTH_RING_REQUIRED")
            if digest(ring_profile) != ring_row["profile_digest"]:
                raise ControlError("OBSERVER_AUTH_BINDING_MISMATCH")
            if {item["observer_id"] for item in profile["keys"]} != {item["observer_id"] for item in ring_profile["observers"]}:
                raise ControlError("OBSERVER_AUTH_KEY_COVERAGE_REQUIRED")
            if auth_required_in_transaction(db, root_id):
                raise ControlError("observer auth profile is immutable")
            for table in ("orientation_seeds", "orientation_tickets", "brakes_actions", "observer_ring_attestations"):
                if db.execute(f"SELECT 1 FROM {table} WHERE root_id=?", (root_id,)).fetchone():
                    raise ControlError("observer auth profile requires a root with no seeds, tickets or actions")
            db.execute("INSERT INTO observer_auth_profiles VALUES (?,?,?,?,?)", (root_id, ring_row["epoch"],
                ring_row["profile_digest"], digest(profile), canonical_bytes(profile).decode()))
            return {"root_id": root_id, "epoch": ring_row["epoch"], "profile_digest": digest(profile),
                    "profile": profile, "execution_authorized": False}

    def challenge(self, action_id: str, observer_id: str, valid_until: float) -> dict[str, Any]:
        validate_id(action_id, "action_id")
        validate_id(observer_id, "observer_id")
        valid_until = _time(valid_until)
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            from .observer_ring import _projection, _projection_reason
            projection = _projection(db, action_id)
            if projection is None:
                raise ControlError("OBSERVER_RING_PROJECTION_REQUIRED")
            session = self._active(db, projection["root_id"])
            row, profile, ring_row, ring_profile = self._require(db, projection["root_id"])
            reason = _projection_reason(db, projection, ring_row)
            if reason:
                raise ControlError(reason)
            key = next((item for item in profile["keys"] if item["observer_id"] == observer_id), None)
            observer = next((item for item in ring_profile["observers"] if item["observer_id"] == observer_id), None)
            if key is None or observer is None:
                raise ControlError("OBSERVER_RING_UNKNOWN_OBSERVER")
            if observer_id == projection["execution_id"]:
                raise ControlError("OBSERVER_RING_SELF_ENDORSEMENT")
            now = session["last_now"]
            if not now < valid_until <= now + profile["max_challenge_age_seconds"]:
                raise ControlError("OBSERVER_AUTH_CHALLENGE_STALE")
            count = db.execute("SELECT COUNT(*) FROM observer_auth_challenges WHERE root_id=?", (projection["root_id"],)).fetchone()[0]
            if count >= profile["max_challenges"]:
                db.execute("INSERT OR IGNORE INTO observer_ring_holds VALUES (?, 'OBSERVER_AUTH_CHALLENGE_LIMIT', ?)",
                           (projection["root_id"], now))
                db.commit()
                raise ControlError("OBSERVER_AUTH_CHALLENGE_LIMIT")
            request = {field: projection[field] for field in _SUBJECT}
            request.update(schema=CHALLENGE_SCHEMA, nonce=secrets.token_hex(32), issued_at=now, valid_until=valid_until,
                observer_id=observer_id, role=observer["role"], key_id=key["key_id"],
                ring_profile_digest=ring_row["profile_digest"], auth_profile_digest=row["profile_digest"],
                **{field: ring_row[field] for field in ("policy_digest", "objective_digest", "orientation_profile_digest")})
            db.execute("INSERT INTO observer_auth_challenges VALUES (?,?,?,?,?,?,?,?,?,NULL,NULL,NULL)",
                (request["nonce"], projection["root_id"], action_id, observer_id, key["key_id"], digest(request),
                 canonical_bytes(request).decode(), now, valid_until))
            return request

    def ingest(self, envelope: dict[str, Any]) -> dict[str, Any]:
        envelope = _envelope(envelope)
        request = envelope["request"]
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            session = self._active(db, request["root_id"])
            row, profile, ring_row, ring_profile = self._require(db, request["root_id"])
            from .observer_ring import _projection, _projection_reason, _attest_in_transaction
            projection = _projection(db, request["action_id"])
            challenge = db.execute("SELECT * FROM observer_auth_challenges WHERE nonce=?", (request["nonce"],)).fetchone()
            reason = _binding_reason(db, request, challenge, row, profile, ring_row, ring_profile, projection)
            if reason:
                raise ControlError(reason)
            reason = _projection_reason(db, projection, ring_row)
            if reason:
                raise ControlError(reason)
            key = next(item for item in profile["keys"] if item["key_id"] == request["key_id"])
            _verify(envelope, key["public_key"])
            if challenge["consumed_at"] is not None:
                if digest(envelope) != challenge["envelope_digest"]:
                    raise ControlError("OBSERVER_AUTH_CHALLENGE_REPLAY")
                stored = db.execute("SELECT * FROM observer_ring_attestations WHERE attestation_digest=?",
                                    (challenge["attestation_digest"],)).fetchone()
                if stored is None:
                    raise ControlError("OBSERVER_AUTH_BINDING_MISMATCH")
                body = json.loads(stored["attestation_json"])
                reason = attestation_reason_in_transaction(db, stored, body)
                if reason:
                    raise ControlError(reason)
                return {**body, "attestation_digest": stored["attestation_digest"], "execution_authorized": False}
            now = session["last_now"]
            if (not request["issued_at"] <= now < request["valid_until"]
                    or now - request["issued_at"] > profile["max_challenge_age_seconds"]
                    or envelope["observed_at"] < request["issued_at"]
                    or envelope["observed_at"] > now or envelope["valid_until"] > request["valid_until"]):
                raise ControlError("OBSERVER_AUTH_CHALLENGE_STALE")
            from .observer_sources import evidence_reason_in_transaction
            source_reason = evidence_reason_in_transaction(db, request, envelope, now=now)
            if source_reason:
                raise ControlError(source_reason)
            result = _attest_in_transaction(db, request["action_id"], observer_id=request["observer_id"],
                verdict=envelope["verdict"], evidence_digest=envelope["evidence_digest"],
                observed_at=envelope["observed_at"], valid_until=envelope["valid_until"], session=session)
            if db.execute("SELECT 1 FROM observer_auth_proofs WHERE attestation_digest=?", (result["attestation_digest"],)).fetchone():
                # A second nonce cannot refresh or replace an immutable statement.
                raise ControlError("OBSERVER_AUTH_ATTESTATION_IMMUTABLE")
            db.execute("INSERT INTO observer_auth_proofs VALUES (?,?,?,?)", (result["attestation_digest"],
                request["nonce"], digest(envelope), canonical_bytes(envelope).decode()))
            db.execute("UPDATE observer_auth_challenges SET envelope_digest=?,attestation_digest=?,consumed_at=? WHERE nonce=?",
                (digest(envelope), result["attestation_digest"], now, request["nonce"]))
            return result

    def revoke(self, root_id: str, key_id: str, reason: str) -> dict[str, Any]:
        validate_id(root_id, "root_id")
        validate_id(key_id, "key_id")
        validate_id(reason, "revocation reason")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            row, profile = _load(db, root_id)
            if row is None or not any(item["key_id"] == key_id for item in profile["keys"]):
                raise ControlError("OBSERVER_AUTH_UNKNOWN_KEY")
            old = db.execute("SELECT * FROM observer_auth_revocations WHERE root_id=? AND key_id=?", (root_id, key_id)).fetchone()
            if old:
                return {**dict(old), "execution_authorized": False}
            session = self._active(db, root_id)
            now = session["last_now"]
            db.execute("INSERT INTO observer_auth_revocations VALUES (?,?,?,?)", (root_id, key_id, reason, now))
            db.execute("INSERT OR IGNORE INTO observer_ring_holds VALUES (?, 'OBSERVER_AUTH_KEY_REVOKED', ?)", (root_id, now))
            return {"root_id": root_id, "key_id": key_id, "reason": reason, "revoked_at": now, "execution_authorized": False}

    def snapshot(self, root_id: str) -> dict[str, Any]:
        validate_id(root_id, "root_id")
        with connect(self.db_path) as db:
            db.execute("BEGIN")
            from .observer_ring import _load as load_ring
            row = db.execute("SELECT * FROM observer_auth_profiles WHERE root_id=?", (root_id,)).fetchone()
            result = {"root_id": root_id, "profile": None, "challenges": [], "revocations": [],
                      "execution_authorized": False, "downstream_gates_required": True, "reason": None}
            if row is None:
                return result
            try:
                _, profile = _load(db, root_id)
                ring_row, ring_profile = load_ring(db, root_id)
                result.update(profile=profile, profile_digest=row["profile_digest"], epoch=row["epoch"],
                    reason=profile_reason_in_transaction(db, root_id, ring_row=ring_row, ring_profile=ring_profile))
            except ControlError as exc:
                result["reason"] = str(exc)
            result["challenges"] = [{**json.loads(item["request_json"]), "consumed_at": item["consumed_at"],
                "attestation_digest": item["attestation_digest"]} for item in db.execute(
                    "SELECT * FROM observer_auth_challenges WHERE root_id=? ORDER BY rowid", (root_id,))]
            result["revocations"] = [dict(item) for item in db.execute(
                "SELECT * FROM observer_auth_revocations WHERE root_id=? ORDER BY revoked_at,key_id", (root_id,))]
            held = db.execute("SELECT * FROM observer_ring_holds WHERE root_id=?", (root_id,)).fetchone()
            result["hold"] = dict(held) if held else None
            return result
