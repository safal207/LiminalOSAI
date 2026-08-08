"""Durable cross-process governance commit fence for LiminalOS.

This module lifts the existing in-process effect-commit composition into a
backend-neutral durable compare-and-swap protocol.  The reference backend uses
stdlib SQLite transactions; LiminalDB can implement the same store contract
without changing the effect protocol.

The safety claim is deliberately narrow: every cooperating governance mutation
and effect must use the same durable root.  This is not distributed consensus,
a kernel boundary, or a hostile-filesystem lease.
"""
from __future__ import annotations

from dataclasses import dataclass
import sqlite3
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from sdk.liminal_causal_effect_commit import (
    CausalBoundEffectCommitBroker,
    CausalEffectCommitError,
    FencedTrajectoryRiskLedger,
    build_effect_trajectory_event,
    verify_authorization_receipt as verify_causal_authorization_receipt,
)
from sdk.liminal_effect_commit import RuntimeCommitFence, ZERO_SHA256
from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_runtime_mediation import (
    ExecutionObservation,
    OPERATION_TO_CAPABILITY,
    RuntimeMediator,
    RuntimeOperation,
)

WORLD_SCHEMA = "liminal-durable-governance-world-v0.1"
STATE_SCHEMA = "liminal-durable-governance-state-v0.1"
RESERVATION_SCHEMA = "liminal-durable-governance-reservation-v0.1"
LEASE_SCHEMA = "liminal-durable-governance-effect-lease-v0.1"
COMMIT_SCHEMA = "liminal-durable-governance-effect-commit-v0.1"

AUTHORITY = {
    "mode": "durable_cross_process_governance_coordination",
    "durable_generation_cas": True,
    "cross_process_effect_reservation": True,
    "objective_state_binding": True,
    "causal_state_binding": True,
    "runtime_context_binding": True,
    "one_live_reservation_per_root": True,
    "automatic_reservation_expiry": False,
    "explicit_reconciliation_required": True,
    "inner_causal_objective_runtime_effect_required": True,
    "capability_grant": False,
    "causal_evidence_fabrication": False,
    "objective_policy_mutation": False,
    "runtime_mutation": False,
    "network_authority": False,
    "credential_authority": False,
    "automatic_rollback": False,
    "distributed_consensus": False,
    "hostile_network_filesystem_correctness": False,
    "kernel_enforcement": False,
}


class DurableGovernanceError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _sha(value: Any, name: str, *, allow_zero: bool = True) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise DurableGovernanceError(f"invalid_{name}")
    if not allow_zero and value == ZERO_SHA256:
        raise DurableGovernanceError(f"zero_{name}")
    return value


def _generation(value: Any, name: str = "generation") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DurableGovernanceError(f"invalid_{name}")
    return value


def _root(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or len(value) > 192:
        raise DurableGovernanceError("invalid_root_id")
    return value


@dataclass(frozen=True)
class GovernanceWorld:
    objective_state_sha256: str
    causal_state_sha256: str
    runtime_context_sha256: str
    world_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": WORLD_SCHEMA,
            "objective_state_sha256": self.objective_state_sha256,
            "causal_state_sha256": self.causal_state_sha256,
            "runtime_context_sha256": self.runtime_context_sha256,
            "authority_sha256": canonical_sha256(AUTHORITY),
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "world_sha256": self.world_sha256}

    @classmethod
    def build(
        cls,
        *,
        objective_state_sha256: str,
        causal_state_sha256: str,
        runtime_context_sha256: str,
    ) -> "GovernanceWorld":
        provisional = cls(
            objective_state_sha256=_sha(objective_state_sha256, "objective_state_sha256"),
            causal_state_sha256=_sha(causal_state_sha256, "causal_state_sha256"),
            runtime_context_sha256=_sha(runtime_context_sha256, "runtime_context_sha256"),
            world_sha256="",
        )
        return cls(**{**provisional.__dict__, "world_sha256": canonical_sha256(provisional.body())})

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "GovernanceWorld":
        raw = dict(document)
        expected = {
            "schema", "objective_state_sha256", "causal_state_sha256",
            "runtime_context_sha256", "authority_sha256", "world_sha256",
        }
        if set(raw) != expected or raw.get("schema") != WORLD_SCHEMA:
            raise DurableGovernanceError("world_schema_mismatch")
        if raw.get("authority_sha256") != canonical_sha256(AUTHORITY):
            raise DurableGovernanceError("world_authority_mismatch")
        item = cls(
            objective_state_sha256=_sha(raw["objective_state_sha256"], "objective_state_sha256"),
            causal_state_sha256=_sha(raw["causal_state_sha256"], "causal_state_sha256"),
            runtime_context_sha256=_sha(raw["runtime_context_sha256"], "runtime_context_sha256"),
            world_sha256=_sha(raw["world_sha256"], "world_sha256"),
        )
        if canonical_sha256(item.body()) != item.world_sha256:
            raise DurableGovernanceError("world_digest_mismatch")
        return item


@runtime_checkable
class DurableGovernanceStore(Protocol):
    def initialize(self, *, root_id: str, world: Mapping[str, Any]) -> dict[str, Any]: ...
    def read_state(self, *, root_id: str) -> dict[str, Any]: ...
    def reserve_effect(
        self, *, root_id: str, expected_generation: int, expected_world_sha256: str,
        reservation_id: str, reservation_payload_sha256: str,
    ) -> dict[str, Any]: ...
    def commit_effect(
        self, *, root_id: str, expected_generation: int, expected_world_sha256: str,
        reservation_id: str, reservation_payload_sha256: str,
        new_world: Mapping[str, Any], inner_commit_receipt_sha256: str,
    ) -> dict[str, Any]: ...
    def mutate_world(
        self, *, root_id: str, expected_generation: int, expected_world_sha256: str,
        new_world: Mapping[str, Any], transition_receipt_sha256: str,
    ) -> dict[str, Any]: ...
    def reconcile_reservation(
        self, *, root_id: str, expected_generation: int, expected_world_sha256: str,
        reservation_id: str, new_world: Mapping[str, Any],
        reconciliation_receipt_sha256: str,
    ) -> dict[str, Any]: ...


class SQLiteGovernanceStore:
    """Reference durable CAS backend using SQLite transactions.

    SQLite provides process-shared transactional serialization on a local
    filesystem. WAL + FULL synchronous settings are enabled. This does not imply
    distributed consensus or correctness on hostile/network filesystems.
    """

    def __init__(self, path: str) -> None:
        if not isinstance(path, str) or not path:
            raise DurableGovernanceError("sqlite_path_required")
        self.path = path
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _ensure_schema(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS governance_state (
                    root_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL,
                    objective_state_sha256 TEXT NOT NULL,
                    causal_state_sha256 TEXT NOT NULL,
                    runtime_context_sha256 TEXT NOT NULL,
                    last_commit_sha256 TEXT NOT NULL,
                    reservation_id_sha256 TEXT NOT NULL,
                    reservation_payload_sha256 TEXT NOT NULL,
                    reservation_active INTEGER NOT NULL CHECK (reservation_active IN (0,1))
                )
                """
            )
        finally:
            conn.close()

    def initialize(self, *, root_id: str, world: Mapping[str, Any]) -> dict[str, Any]:
        root = _root(root_id)
        item = GovernanceWorld.from_document(world)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = self._fetch_row(conn, root)
            if row is None:
                conn.execute(
                    "INSERT INTO governance_state VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        root, 0, item.objective_state_sha256, item.causal_state_sha256,
                        item.runtime_context_sha256, ZERO_SHA256, ZERO_SHA256,
                        ZERO_SHA256, 0,
                    ),
                )
            else:
                existing = self._state_from_row(row)
                if existing["generation"] != 0 or existing["world_sha256"] != item.world_sha256:
                    raise DurableGovernanceError("root_already_initialized")
            conn.execute("COMMIT")
        except Exception:
            self._rollback(conn)
            raise
        finally:
            conn.close()
        return self.read_state(root_id=root)

    def read_state(self, *, root_id: str) -> dict[str, Any]:
        root = _root(root_id)
        conn = self._connect()
        try:
            row = self._fetch_row(conn, root)
            if row is None:
                raise DurableGovernanceError("unknown_governance_root")
            return self._state_from_row(row)
        finally:
            conn.close()

    def reserve_effect(
        self, *, root_id: str, expected_generation: int, expected_world_sha256: str,
        reservation_id: str, reservation_payload_sha256: str,
    ) -> dict[str, Any]:
        root = _root(root_id)
        generation = _generation(expected_generation)
        expected_world = _sha(expected_world_sha256, "expected_world_sha256")
        reservation_hash = canonical_sha256(self._reservation_id(reservation_id))
        payload = _sha(reservation_payload_sha256, "reservation_payload_sha256", allow_zero=False)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            state = self._require_state(conn, root)
            self._expect_world(state, generation, expected_world)
            if state["reservation_active"]:
                raise DurableGovernanceError("durable_reservation_active")
            conn.execute(
                "UPDATE governance_state SET reservation_id_sha256=?, reservation_payload_sha256=?, reservation_active=1 WHERE root_id=?",
                (reservation_hash, payload, root),
            )
            state = self._require_state(conn, root)
            conn.execute("COMMIT")
            return state
        except Exception:
            self._rollback(conn)
            raise
        finally:
            conn.close()

    def commit_effect(
        self, *, root_id: str, expected_generation: int, expected_world_sha256: str,
        reservation_id: str, reservation_payload_sha256: str,
        new_world: Mapping[str, Any], inner_commit_receipt_sha256: str,
    ) -> dict[str, Any]:
        root = _root(root_id)
        generation = _generation(expected_generation)
        expected_world = _sha(expected_world_sha256, "expected_world_sha256")
        reservation_hash = canonical_sha256(self._reservation_id(reservation_id))
        payload = _sha(reservation_payload_sha256, "reservation_payload_sha256", allow_zero=False)
        commit_sha = _sha(inner_commit_receipt_sha256, "inner_commit_receipt_sha256", allow_zero=False)
        new_item = GovernanceWorld.from_document(new_world)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            state = self._require_state(conn, root)
            self._expect_world(state, generation, expected_world)
            self._expect_reservation(state, reservation_hash, payload)
            conn.execute(
                """
                UPDATE governance_state
                SET generation=?, objective_state_sha256=?, causal_state_sha256=?,
                    runtime_context_sha256=?, last_commit_sha256=?,
                    reservation_id_sha256=?, reservation_payload_sha256=?, reservation_active=0
                WHERE root_id=?
                """,
                (
                    generation + 1, new_item.objective_state_sha256,
                    new_item.causal_state_sha256, new_item.runtime_context_sha256,
                    commit_sha, ZERO_SHA256, ZERO_SHA256, root,
                ),
            )
            state = self._require_state(conn, root)
            conn.execute("COMMIT")
            return state
        except Exception:
            self._rollback(conn)
            raise
        finally:
            conn.close()

    def mutate_world(
        self, *, root_id: str, expected_generation: int, expected_world_sha256: str,
        new_world: Mapping[str, Any], transition_receipt_sha256: str,
    ) -> dict[str, Any]:
        root = _root(root_id)
        generation = _generation(expected_generation)
        expected_world = _sha(expected_world_sha256, "expected_world_sha256")
        transition_sha = _sha(transition_receipt_sha256, "transition_receipt_sha256", allow_zero=False)
        new_item = GovernanceWorld.from_document(new_world)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            state = self._require_state(conn, root)
            self._expect_world(state, generation, expected_world)
            if state["reservation_active"]:
                raise DurableGovernanceError("durable_reservation_active")
            conn.execute(
                """
                UPDATE governance_state
                SET generation=?, objective_state_sha256=?, causal_state_sha256=?,
                    runtime_context_sha256=?, last_commit_sha256=?
                WHERE root_id=?
                """,
                (
                    generation + 1, new_item.objective_state_sha256,
                    new_item.causal_state_sha256, new_item.runtime_context_sha256,
                    transition_sha, root,
                ),
            )
            state = self._require_state(conn, root)
            conn.execute("COMMIT")
            return state
        except Exception:
            self._rollback(conn)
            raise
        finally:
            conn.close()

    def reconcile_reservation(
        self, *, root_id: str, expected_generation: int, expected_world_sha256: str,
        reservation_id: str, new_world: Mapping[str, Any],
        reconciliation_receipt_sha256: str,
    ) -> dict[str, Any]:
        root = _root(root_id)
        generation = _generation(expected_generation)
        expected_world = _sha(expected_world_sha256, "expected_world_sha256")
        reservation_hash = canonical_sha256(self._reservation_id(reservation_id))
        receipt_sha = _sha(
            reconciliation_receipt_sha256, "reconciliation_receipt_sha256", allow_zero=False
        )
        new_item = GovernanceWorld.from_document(new_world)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            state = self._require_state(conn, root)
            self._expect_world(state, generation, expected_world)
            if not state["reservation_active"] or state["reservation_id_sha256"] != reservation_hash:
                raise DurableGovernanceError("reservation_reconciliation_mismatch")
            conn.execute(
                """
                UPDATE governance_state
                SET generation=?, objective_state_sha256=?, causal_state_sha256=?,
                    runtime_context_sha256=?, last_commit_sha256=?,
                    reservation_id_sha256=?, reservation_payload_sha256=?, reservation_active=0
                WHERE root_id=?
                """,
                (
                    generation + 1, new_item.objective_state_sha256,
                    new_item.causal_state_sha256, new_item.runtime_context_sha256,
                    receipt_sha, ZERO_SHA256, ZERO_SHA256, root,
                ),
            )
            state = self._require_state(conn, root)
            conn.execute("COMMIT")
            return state
        except Exception:
            self._rollback(conn)
            raise
        finally:
            conn.close()

    @staticmethod
    def _reservation_id(value: Any) -> str:
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            raise DurableGovernanceError("invalid_reservation_id")
        return value

    @staticmethod
    def _fetch_row(conn: sqlite3.Connection, root_id: str) -> tuple[Any, ...] | None:
        return conn.execute(
            "SELECT root_id,generation,objective_state_sha256,causal_state_sha256,runtime_context_sha256,last_commit_sha256,reservation_id_sha256,reservation_payload_sha256,reservation_active FROM governance_state WHERE root_id=?",
            (root_id,),
        ).fetchone()

    def _require_state(self, conn: sqlite3.Connection, root_id: str) -> dict[str, Any]:
        row = self._fetch_row(conn, root_id)
        if row is None:
            raise DurableGovernanceError("unknown_governance_root")
        return self._state_from_row(row)

    @staticmethod
    def _state_from_row(row: tuple[Any, ...]) -> dict[str, Any]:
        root_id, generation, objective_sha, causal_sha, runtime_sha, last_sha, reservation_sha, payload_sha, active = row
        world = GovernanceWorld.build(
            objective_state_sha256=_sha(objective_sha, "objective_state_sha256"),
            causal_state_sha256=_sha(causal_sha, "causal_state_sha256"),
            runtime_context_sha256=_sha(runtime_sha, "runtime_context_sha256"),
        )
        body = {
            "schema": STATE_SCHEMA,
            "root_id": _root(root_id),
            "generation": _generation(generation),
            "objective_state_sha256": world.objective_state_sha256,
            "causal_state_sha256": world.causal_state_sha256,
            "runtime_context_sha256": world.runtime_context_sha256,
            "world_sha256": world.world_sha256,
            "last_commit_sha256": _sha(last_sha, "last_commit_sha256"),
            "reservation_id_sha256": _sha(reservation_sha, "reservation_id_sha256"),
            "reservation_payload_sha256": _sha(payload_sha, "reservation_payload_sha256"),
            "reservation_active": bool(active),
            "authority": AUTHORITY,
        }
        return {**body, "state_sha256": canonical_sha256(body)}

    @staticmethod
    def _expect_world(state: Mapping[str, Any], generation: int, world_sha256: str) -> None:
        if state.get("generation") != generation:
            raise DurableGovernanceError("stale_governance_generation")
        if state.get("world_sha256") != world_sha256:
            raise DurableGovernanceError("stale_governance_world")

    @staticmethod
    def _expect_reservation(state: Mapping[str, Any], reservation_sha: str, payload_sha: str) -> None:
        if not state.get("reservation_active"):
            raise DurableGovernanceError("durable_reservation_missing")
        if state.get("reservation_id_sha256") != reservation_sha:
            raise DurableGovernanceError("durable_reservation_id_mismatch")
        if state.get("reservation_payload_sha256") != payload_sha:
            raise DurableGovernanceError("durable_reservation_payload_mismatch")

    @staticmethod
    def _rollback(conn: sqlite3.Connection) -> None:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass


WorldProvider = Callable[[], Mapping[str, Any]]


class DurableGovernanceCoordinator:
    """Trusted helper for durable world mutation/reconciliation."""

    def __init__(self, *, store: DurableGovernanceStore, root_id: str) -> None:
        if not isinstance(store, DurableGovernanceStore):
            raise DurableGovernanceError("durable_store_required")
        self.store = store
        self.root_id = _root(root_id)

    def state_document(self) -> dict[str, Any]:
        return self.store.read_state(root_id=self.root_id)

    def mutate_world(
        self,
        *,
        expected_generation: int,
        expected_world_sha256: str,
        new_world: Mapping[str, Any],
        transition_receipt_sha256: str,
    ) -> dict[str, Any]:
        return self.store.mutate_world(
            root_id=self.root_id,
            expected_generation=expected_generation,
            expected_world_sha256=expected_world_sha256,
            new_world=new_world,
            transition_receipt_sha256=transition_receipt_sha256,
        )

    def reconcile_reservation(
        self,
        *,
        expected_generation: int,
        expected_world_sha256: str,
        reservation_id: str,
        new_world: Mapping[str, Any],
        reconciliation_receipt_sha256: str,
    ) -> dict[str, Any]:
        return self.store.reconcile_reservation(
            root_id=self.root_id,
            expected_generation=expected_generation,
            expected_world_sha256=expected_world_sha256,
            reservation_id=reservation_id,
            new_world=new_world,
            reconciliation_receipt_sha256=reconciliation_receipt_sha256,
        )


@dataclass(frozen=True)
class DurableEffectAuthorizationReceipt:
    operation_id: str
    durable_lease_id_sha256: str
    root_id_sha256: str
    generation: int
    world_sha256: str
    durable_reserved_state_sha256: str
    reservation_payload_sha256: str
    runtime_kind: str
    scope_sha256: str
    payload_sha256: str
    capability_receipt_sha256: str
    causal_authorization_receipt_sha256: str
    issued_at_unix: int
    expires_at_unix: int
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": LEASE_SCHEMA,
            "operation_id": self.operation_id,
            "durable_lease_id_sha256": self.durable_lease_id_sha256,
            "root_id_sha256": self.root_id_sha256,
            "generation": self.generation,
            "world_sha256": self.world_sha256,
            "durable_reserved_state_sha256": self.durable_reserved_state_sha256,
            "reservation_payload_sha256": self.reservation_payload_sha256,
            "runtime_kind": self.runtime_kind,
            "scope_sha256": self.scope_sha256,
            "payload_sha256": self.payload_sha256,
            "capability_receipt_sha256": self.capability_receipt_sha256,
            "causal_authorization_receipt_sha256": self.causal_authorization_receipt_sha256,
            "issued_at_unix": self.issued_at_unix,
            "expires_at_unix": self.expires_at_unix,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


@dataclass(frozen=True)
class DurableEffectCommitReceipt:
    operation_id: str
    authorization_receipt_sha256: str
    durable_lease_id_sha256: str
    generation_before: int
    generation_after: int
    world_before_sha256: str
    world_after_sha256: str
    causal_authorization_receipt_sha256: str
    causal_commit_receipt_sha256: str
    durable_state_after_sha256: str
    committed_at_unix: int
    effect_outcome: str
    result_sha256: str
    reason_codes: tuple[str, ...]
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": COMMIT_SCHEMA,
            "operation_id": self.operation_id,
            "authorization_receipt_sha256": self.authorization_receipt_sha256,
            "durable_lease_id_sha256": self.durable_lease_id_sha256,
            "generation_before": self.generation_before,
            "generation_after": self.generation_after,
            "world_before_sha256": self.world_before_sha256,
            "world_after_sha256": self.world_after_sha256,
            "causal_authorization_receipt_sha256": self.causal_authorization_receipt_sha256,
            "causal_commit_receipt_sha256": self.causal_commit_receipt_sha256,
            "durable_state_after_sha256": self.durable_state_after_sha256,
            "committed_at_unix": self.committed_at_unix,
            "effect_outcome": self.effect_outcome,
            "result_sha256": self.result_sha256,
            "reason_codes": list(self.reason_codes),
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


@dataclass
class _DurableLease:
    durable_lease_id: str
    causal_lease_id: str
    operation: RuntimeOperation
    generation: int
    world_sha256: str
    reservation_payload_sha256: str
    capability_receipt_sha256: str
    causal_authorization_receipt_sha256: str
    authorization_receipt_sha256: str
    issued_at_unix: int
    expires_at_unix: int
    consumed: bool = False


class DurableGovernanceEffectBroker:
    """Durable outer reservation around CausalBoundEffectCommitBroker."""

    def __init__(
        self,
        *,
        store: DurableGovernanceStore,
        root_id: str,
        world_provider: WorldProvider,
        delegate: CausalBoundEffectCommitBroker,
        commit_fence: RuntimeCommitFence,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(store, DurableGovernanceStore):
            raise DurableGovernanceError("durable_store_required")
        if not isinstance(delegate, CausalBoundEffectCommitBroker):
            raise DurableGovernanceError("causal_bound_effect_delegate_required")
        if not isinstance(commit_fence, RuntimeCommitFence) or delegate.commit_fence is not commit_fence:
            raise DurableGovernanceError("shared_commit_fence_required")
        if not callable(world_provider):
            raise DurableGovernanceError("world_provider_required")
        self.store = store
        self.root_id = _root(root_id)
        self.world_provider = world_provider
        self.delegate = delegate
        self.commit_fence = commit_fence
        self.clock = clock or delegate.clock
        self._leases: dict[str, _DurableLease] = {}
        self._authorizations: list[DurableEffectAuthorizationReceipt] = []
        self._commits: list[DurableEffectCommitReceipt] = []

    def bootstrap(self) -> dict[str, Any]:
        with self.commit_fence.hold():
            return self.store.initialize(root_id=self.root_id, world=self._local_world().as_document())

    def issue_for_trusted_adapter(
        self,
        *,
        operation: RuntimeOperation,
        capability_decision: Mapping[str, Any],
        objective_decision: Mapping[str, Any],
        proposed_event: Mapping[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        operation.validate()
        with self.commit_fence.hold():
            durable = self.store.read_state(root_id=self.root_id)
            if durable["reservation_active"]:
                raise DurableGovernanceError("durable_reservation_active")
            local_world = self._local_world()
            self._require_world_match(durable, local_world)

            causal_lease_id, causal_auth = self.delegate.issue_for_trusted_adapter(
                operation=operation,
                capability_decision=capability_decision,
                objective_decision=objective_decision,
                proposed_event=proposed_event,
            )
            verify_causal_authorization_receipt(causal_auth)
            capability_sha = _sha(
                capability_decision.get("receipt_sha256"), "capability_receipt_sha256", allow_zero=False
            )
            issued = int(causal_auth["issued_at_unix"])
            expires = int(causal_auth["expires_at_unix"])
            durable_lease_id = (
                f"durable-effect-lease:{durable['generation']}:"
                f"{canonical_sha256({'root': self.root_id, 'world': durable['world_sha256'], 'inner': causal_auth['receipt_sha256'], 'operation': operation.operation_id})[:24]}"
            )
            reservation_payload = canonical_sha256({
                "schema": RESERVATION_SCHEMA,
                "root_id_sha256": canonical_sha256(self.root_id),
                "generation": durable["generation"],
                "world_sha256": durable["world_sha256"],
                "operation_id_sha256": canonical_sha256(operation.operation_id),
                "runtime_kind": operation.kind,
                "scope_sha256": canonical_sha256(operation.normalized_scope()),
                "payload_sha256": operation.payload_sha256,
                "capability_receipt_sha256": capability_sha,
                "causal_authorization_receipt_sha256": causal_auth["receipt_sha256"],
                "authority_sha256": canonical_sha256(AUTHORITY),
            })
            reserved = self.store.reserve_effect(
                root_id=self.root_id,
                expected_generation=durable["generation"],
                expected_world_sha256=durable["world_sha256"],
                reservation_id=durable_lease_id,
                reservation_payload_sha256=reservation_payload,
            )
            provisional = DurableEffectAuthorizationReceipt(
                operation_id=operation.operation_id,
                durable_lease_id_sha256=canonical_sha256(durable_lease_id),
                root_id_sha256=canonical_sha256(self.root_id),
                generation=durable["generation"],
                world_sha256=durable["world_sha256"],
                durable_reserved_state_sha256=reserved["state_sha256"],
                reservation_payload_sha256=reservation_payload,
                runtime_kind=operation.kind,
                scope_sha256=canonical_sha256(operation.normalized_scope()),
                payload_sha256=operation.payload_sha256,
                capability_receipt_sha256=capability_sha,
                causal_authorization_receipt_sha256=causal_auth["receipt_sha256"],
                issued_at_unix=issued,
                expires_at_unix=expires,
                receipt_sha256="",
            )
            receipt = DurableEffectAuthorizationReceipt(**{
                **provisional.__dict__, "receipt_sha256": canonical_sha256(provisional.body())
            })
            self._authorizations.append(receipt)
            self._leases[durable_lease_id] = _DurableLease(
                durable_lease_id=durable_lease_id,
                causal_lease_id=causal_lease_id,
                operation=operation,
                generation=durable["generation"],
                world_sha256=durable["world_sha256"],
                reservation_payload_sha256=reservation_payload,
                capability_receipt_sha256=capability_sha,
                causal_authorization_receipt_sha256=causal_auth["receipt_sha256"],
                authorization_receipt_sha256=receipt.receipt_sha256,
                issued_at_unix=issued,
                expires_at_unix=expires,
            )
            return durable_lease_id, receipt.as_document()

    def consume_for_trusted_adapter(
        self,
        durable_lease_id: str,
        *,
        adapter_token: str,
        executor: Callable[[RuntimeOperation], ExecutionObservation],
    ) -> ExecutionObservation:
        with self.commit_fence.hold():
            lease = self._require_live_lease(durable_lease_id)
            now = self._now()
            if now < lease.issued_at_unix or now > lease.expires_at_unix:
                lease.consumed = True
                raise DurableGovernanceError("durable_lease_time_invalid")

            durable = self.store.read_state(root_id=self.root_id)
            self._require_reservation_match(durable, lease)
            local_before = self._local_world()
            self._require_world_match(durable, local_before)

            # Burn the in-process handle before handing control to the inner
            # effect stack. The durable reservation intentionally remains active
            # until the post-effect world has been durably acknowledged.
            lease.consumed = True
            before_inner = len(self.delegate.commit_receipts())
            try:
                observation = self.delegate.consume_for_trusted_adapter(
                    lease.causal_lease_id,
                    adapter_token=adapter_token,
                    executor=executor,
                )
            except Exception as exc:
                inner_sha = self._latest_inner_commit(before_inner)
                current = self.store.read_state(root_id=self.root_id)
                self._append_commit(
                    lease=lease,
                    generation_after=current["generation"],
                    world_after_sha256=current["world_sha256"],
                    causal_commit_receipt_sha256=inner_sha,
                    durable_state_after_sha256=current["state_sha256"],
                    committed_at_unix=now,
                    outcome="EFFECT_FAILED_RESERVATION_STUCK",
                    result_sha256=canonical_sha256({"error_type": type(exc).__name__}),
                    reasons=("durable_reservation_retained", "inner_effect_failed_or_unknown"),
                )
                raise DurableGovernanceError("inner_effect_failed_reservation_stuck") from exc

            inner_sha = self._latest_inner_commit(before_inner)
            if inner_sha == ZERO_SHA256:
                current = self.store.read_state(root_id=self.root_id)
                self._append_commit(
                    lease=lease,
                    generation_after=current["generation"],
                    world_after_sha256=current["world_sha256"],
                    causal_commit_receipt_sha256=ZERO_SHA256,
                    durable_state_after_sha256=current["state_sha256"],
                    committed_at_unix=now,
                    outcome="EFFECT_SUCCEEDED_DURABLE_COMMIT_FAILED",
                    result_sha256=observation.result_sha256,
                    reasons=("durable_reservation_retained", "inner_commit_receipt_missing"),
                )
                raise DurableGovernanceError("inner_commit_receipt_missing_after_effect")

            local_after = self._local_world()
            try:
                committed = self.store.commit_effect(
                    root_id=self.root_id,
                    expected_generation=lease.generation,
                    expected_world_sha256=lease.world_sha256,
                    reservation_id=lease.durable_lease_id,
                    reservation_payload_sha256=lease.reservation_payload_sha256,
                    new_world=local_after.as_document(),
                    inner_commit_receipt_sha256=inner_sha,
                )
            except Exception as exc:
                current = self.store.read_state(root_id=self.root_id)
                self._append_commit(
                    lease=lease,
                    generation_after=current["generation"],
                    world_after_sha256=current["world_sha256"],
                    causal_commit_receipt_sha256=inner_sha,
                    durable_state_after_sha256=current["state_sha256"],
                    committed_at_unix=now,
                    outcome="EFFECT_SUCCEEDED_DURABLE_COMMIT_FAILED",
                    result_sha256=observation.result_sha256,
                    reasons=("effect_succeeded", "durable_reservation_retained", "durable_finalize_failed"),
                )
                raise DurableGovernanceError("durable_finalize_failed_after_effect") from exc

            self._append_commit(
                lease=lease,
                generation_after=committed["generation"],
                world_after_sha256=committed["world_sha256"],
                causal_commit_receipt_sha256=inner_sha,
                durable_state_after_sha256=committed["state_sha256"],
                committed_at_unix=now,
                outcome="SUCCEEDED",
                result_sha256=observation.result_sha256,
                reasons=(
                    "durable_generation_rechecked",
                    "durable_world_rechecked",
                    "exclusive_reservation_verified",
                    "inner_causal_objective_runtime_effect_committed",
                    "post_effect_world_durably_published",
                    "durable_generation_advanced",
                ),
            )
            return observation

    def commit_authorized_effect(
        self,
        *,
        operation: RuntimeOperation,
        capability_decision: Mapping[str, Any],
        objective_decision: Mapping[str, Any],
        proposed_event: Mapping[str, Any],
        adapter_token: str,
        executor: Callable[[RuntimeOperation], ExecutionObservation],
    ) -> ExecutionObservation:
        lease_id, _ = self.issue_for_trusted_adapter(
            operation=operation,
            capability_decision=capability_decision,
            objective_decision=objective_decision,
            proposed_event=proposed_event,
        )
        return self.consume_for_trusted_adapter(
            lease_id, adapter_token=adapter_token, executor=executor
        )

    def authorization_receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._authorizations)

    def commit_receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._commits)

    def state_document(self) -> dict[str, Any]:
        durable = self.store.read_state(root_id=self.root_id)
        body = {
            "schema": "liminal-durable-governance-effect-state-v0.1",
            "root_id_sha256": canonical_sha256(self.root_id),
            "generation": durable["generation"],
            "world_sha256": durable["world_sha256"],
            "reservation_active": durable["reservation_active"],
            "durable_state_sha256": durable["state_sha256"],
            "authorization_count": len(self._authorizations),
            "commit_count": len(self._commits),
            "authority": AUTHORITY,
        }
        return {**body, "state_sha256": canonical_sha256(body)}

    def _local_world(self) -> GovernanceWorld:
        try:
            raw = dict(self.world_provider())
        except Exception as exc:
            raise DurableGovernanceError("world_provider_failed") from exc
        return GovernanceWorld.build(
            objective_state_sha256=_sha(raw.get("objective_state_sha256"), "objective_state_sha256"),
            causal_state_sha256=_sha(raw.get("causal_state_sha256"), "causal_state_sha256"),
            runtime_context_sha256=_sha(raw.get("runtime_context_sha256"), "runtime_context_sha256"),
        )

    @staticmethod
    def _require_world_match(state: Mapping[str, Any], local: GovernanceWorld) -> None:
        if state.get("world_sha256") != local.world_sha256:
            raise DurableGovernanceError("local_durable_world_mismatch")

    def _require_reservation_match(self, state: Mapping[str, Any], lease: _DurableLease) -> None:
        if state.get("generation") != lease.generation:
            raise DurableGovernanceError("stale_governance_generation")
        if state.get("world_sha256") != lease.world_sha256:
            raise DurableGovernanceError("stale_governance_world")
        if state.get("reservation_active") is not True:
            raise DurableGovernanceError("durable_reservation_missing")
        if state.get("reservation_id_sha256") != canonical_sha256(lease.durable_lease_id):
            raise DurableGovernanceError("durable_reservation_id_mismatch")
        if state.get("reservation_payload_sha256") != lease.reservation_payload_sha256:
            raise DurableGovernanceError("durable_reservation_payload_mismatch")

    def _require_live_lease(self, durable_lease_id: str) -> _DurableLease:
        if not isinstance(durable_lease_id, str) or not durable_lease_id:
            raise DurableGovernanceError("unknown_durable_lease")
        lease = self._leases.get(durable_lease_id)
        if lease is None:
            raise DurableGovernanceError("unknown_durable_lease")
        if lease.consumed:
            raise DurableGovernanceError("durable_lease_replayed")
        return lease

    def _latest_inner_commit(self, before_count: int) -> str:
        commits = self.delegate.commit_receipts()
        if len(commits) <= before_count:
            return ZERO_SHA256
        value = commits[-1].get("receipt_sha256")
        return _sha(value, "causal_commit_receipt_sha256")

    def _append_commit(
        self,
        *,
        lease: _DurableLease,
        generation_after: int,
        world_after_sha256: str,
        causal_commit_receipt_sha256: str,
        durable_state_after_sha256: str,
        committed_at_unix: int,
        outcome: str,
        result_sha256: str,
        reasons: tuple[str, ...],
    ) -> None:
        provisional = DurableEffectCommitReceipt(
            operation_id=lease.operation.operation_id,
            authorization_receipt_sha256=lease.authorization_receipt_sha256,
            durable_lease_id_sha256=canonical_sha256(lease.durable_lease_id),
            generation_before=lease.generation,
            generation_after=_generation(generation_after, "generation_after"),
            world_before_sha256=lease.world_sha256,
            world_after_sha256=_sha(world_after_sha256, "world_after_sha256"),
            causal_authorization_receipt_sha256=lease.causal_authorization_receipt_sha256,
            causal_commit_receipt_sha256=_sha(causal_commit_receipt_sha256, "causal_commit_receipt_sha256"),
            durable_state_after_sha256=_sha(durable_state_after_sha256, "durable_state_after_sha256"),
            committed_at_unix=_generation(committed_at_unix, "committed_at_unix"),
            effect_outcome=outcome,
            result_sha256=_sha(result_sha256, "result_sha256"),
            reason_codes=tuple(sorted(set(reasons))),
            receipt_sha256="",
        )
        receipt = DurableEffectCommitReceipt(**{
            **provisional.__dict__, "receipt_sha256": canonical_sha256(provisional.body())
        })
        self._commits.append(receipt)

    def _now(self) -> int:
        value = self.clock()
        return _generation(value, "trusted_clock")


ProposalFactory = Callable[[RuntimeOperation, Mapping[str, Any], FencedTrajectoryRiskLedger], Mapping[str, Any]]


class DurableGovernanceRuntimeMediator(RuntimeMediator):
    """Opt-in path: objective → capability → causal → durable effect commit."""

    def __init__(
        self,
        *,
        durable_effect_broker: DurableGovernanceEffectBroker,
        adapter_token: str,
        proposal_factory: ProposalFactory,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        if not isinstance(durable_effect_broker, DurableGovernanceEffectBroker):
            raise DurableGovernanceError("durable_effect_broker_required")
        if not isinstance(adapter_token, str) or not adapter_token:
            raise DurableGovernanceError("adapter_token_required")
        if not callable(proposal_factory):
            raise DurableGovernanceError("trusted_proposal_factory_required")
        self.durable_effect_broker = durable_effect_broker
        self.causal_effect_broker = durable_effect_broker.delegate
        self.guard = self.causal_effect_broker.delegate.guard
        self.adapter_token = adapter_token
        self.proposal_factory = proposal_factory

    def mediate(
        self,
        operation: RuntimeOperation,
        executor: Callable[[RuntimeOperation], ExecutionObservation],
    ) -> dict[str, Any]:
        operation.validate()
        scope = operation.normalized_scope()
        scope_sha = canonical_sha256(scope)
        if self._contained:
            return self._finish(
                operation=operation, capability_receipt_sha=ZERO_SHA256,
                admission="BLOCK", outcome="NOT_EXECUTED", result_sha=ZERO_SHA256,
                reasons=("containment_active", "durable_governance_effect_blocked"),
                capability_id=None, scope_sha=scope_sha,
            )
        gate = self.guard.evaluate_operation(operation)
        if gate["decision"] != "ALLOW":
            return self._finish(
                operation=operation, capability_receipt_sha=ZERO_SHA256,
                admission="BLOCK", outcome="NOT_EXECUTED", result_sha=ZERO_SHA256,
                reasons=("objective_integrity_gate_blocked",), capability_id=None,
                scope_sha=scope_sha,
            )
        capability = self.broker.authorize(
            subject_id=operation.subject_id,
            capability_type=OPERATION_TO_CAPABILITY[operation.kind],
            policy_sha256=operation.policy_sha256,
            requested_scope=scope,
            action={
                "operation_id": operation.operation_id,
                "runtime_kind": operation.kind,
                "scope_sha256": scope_sha,
                "payload_sha256": operation.payload_sha256,
                "objective_decision_receipt_sha256": gate["receipt_sha256"],
                "objective_observation_head_sha256": gate["observation_head_sha256"],
            },
            at_unix=operation.at_unix,
        )
        if capability["decision"] != "ALLOW":
            return self._finish(
                operation=operation, capability_receipt_sha=capability["receipt_sha256"],
                admission="BLOCK", outcome="NOT_EXECUTED", result_sha=ZERO_SHA256,
                reasons=tuple(capability["reason_codes"]), capability_id=None,
                scope_sha=scope_sha,
            )
        try:
            proposal = dict(self.proposal_factory(
                operation, capability, self.causal_effect_broker.ledger
            ))
            observation = self.durable_effect_broker.commit_authorized_effect(
                operation=operation,
                capability_decision=capability,
                objective_decision=gate,
                proposed_event=proposal,
                adapter_token=self.adapter_token,
                executor=executor,
            )
        except Exception as exc:
            return self._finish(
                operation=operation, capability_receipt_sha=capability["receipt_sha256"],
                admission="ALLOW", outcome="FAILED",
                result_sha=canonical_sha256({"error_type": type(exc).__name__}),
                reasons=("durable_governance_effect_commit_failed",),
                capability_id=capability.get("capability_id"), scope_sha=scope_sha,
            )
        return self._finish(
            operation=operation, capability_receipt_sha=capability["receipt_sha256"],
            admission="ALLOW", outcome="SUCCEEDED", result_sha=observation.result_sha256,
            reasons=(
                "objective_integrity_allow", "capability_admitted",
                "causal_projection_allow", "durable_governance_reservation_committed",
                "host_executor_succeeded",
            ),
            capability_id=capability.get("capability_id"), scope_sha=scope_sha,
        )


def default_world_provider(
    *,
    objective_guard: Any,
    trajectory_ledger: Any,
    runtime_provider: Any,
) -> Callable[[], dict[str, Any]]:
    """Build a digest-only local world provider from existing trusted components."""
    def provider() -> dict[str, Any]:
        objective = objective_guard.state_document()
        causal = trajectory_ledger.state_document()
        runtime = runtime_provider.state_document()
        return {
            "objective_state_sha256": _sha(objective.get("state_sha256"), "objective_state_sha256"),
            "causal_state_sha256": _sha(causal.get("state_sha256"), "causal_state_sha256"),
            "runtime_context_sha256": canonical_sha256(dict(runtime)),
        }
    return provider


def verify_authorization_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    digest = raw.pop("receipt_sha256", None)
    if raw.get("schema") != LEASE_SCHEMA or raw.get("authority") != AUTHORITY:
        raise DurableGovernanceError("authorization_receipt_schema_mismatch")
    if digest != canonical_sha256(raw):
        raise DurableGovernanceError("authorization_receipt_digest_mismatch")
    return dict(document)


def verify_commit_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    digest = raw.pop("receipt_sha256", None)
    allowed = {
        "SUCCEEDED",
        "EFFECT_FAILED_RESERVATION_STUCK",
        "EFFECT_SUCCEEDED_DURABLE_COMMIT_FAILED",
    }
    if raw.get("schema") != COMMIT_SCHEMA or raw.get("authority") != AUTHORITY:
        raise DurableGovernanceError("commit_receipt_schema_mismatch")
    if raw.get("effect_outcome") not in allowed:
        raise DurableGovernanceError("commit_receipt_outcome_invalid")
    if digest != canonical_sha256(raw):
        raise DurableGovernanceError("commit_receipt_digest_mismatch")
    return dict(document)


__all__ = [
    "AUTHORITY",
    "COMMIT_SCHEMA",
    "DurableEffectAuthorizationReceipt",
    "DurableEffectCommitReceipt",
    "DurableGovernanceCoordinator",
    "DurableGovernanceEffectBroker",
    "DurableGovernanceError",
    "DurableGovernanceRuntimeMediator",
    "DurableGovernanceStore",
    "GovernanceWorld",
    "LEASE_SCHEMA",
    "RESERVATION_SCHEMA",
    "SQLiteGovernanceStore",
    "STATE_SCHEMA",
    "WORLD_SCHEMA",
    "default_world_provider",
    "verify_authorization_receipt",
    "verify_commit_receipt",
]
