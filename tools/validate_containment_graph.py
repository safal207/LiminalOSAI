#!/usr/bin/env python3
"""Check the fixed four-space assurance model; never authorize an execution.

A structural PASS checks the declared graph and its current source bindings. It
does not establish containment. Runtime reports are optional and must pass the
existing independent receiver verifier at the exact checked-out Git revision.
"""
from __future__ import annotations

import argparse
import ast
from collections import deque
import copy
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MAX_GRAPH_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_REPORT_BYTES = 24 * 1024 * 1024
SCHEMA = "liminal-containment-assurance-graph-v1"
BASIS_COMMIT = "69dedf3796d190fbf2da54fb95dfc6560a3663e6"
BASIS_TREE = "e834916ff40ec4e30601cef3f45c0993986fe7b8"
CLAIM = ("Declared G03 synthetic receiver effect paths require the listed existing controls; "
         "this file is an assurance model, not a new runtime gate.")
ASSUMPTIONS = {"trusted_host", "trusted_operator_keys", "trusted_authority_stores",
               "trusted_docker_daemon", "trusted_host_clock", "declared_routes_complete"}
TEMPORAL = {"expiry": "BEGIN_ADMISSION_ONLY", "stop_linearization": "RECEIVER_TRANSACTION_WINNER",
            "unknown": "PRESERVE_RESERVATION_QUERY_ONLY", "committed": "IMMUTABLE_AFTER_STOP",
            "no_effect": "SIGNED_RECEIVER_FENCE_ONLY", "future_plan": "NOT_AUTHORIZATION"}
GAPS = {"g03_orientation": "NOT_CONNECTED", "kernel_escape_resistance": "NOT_ESTABLISHED",
        "compromised_host_or_daemon": "NOT_ESTABLISHED", "live_llm": "NOT_RUN",
        "unknown_channels": "NOT_ESTABLISHED", "independent_operator_reproduction": "NOT_ESTABLISHED"}
GUARDS = ["launch", "bridge", "authorization", "begin", "dispatch_recheck", "receiver_fence"]
REQUIREMENTS = [{"id": "g03_receiver_effect", "entry": "proposal", "target": "synthetic_effect",
                 "ordered_guards": GUARDS}]
CHANNEL_MODES = dict(zip((
    "worker_network", "worker_workspace", "worker_host_filesystem", "worker_control_sockets_devices",
    "worker_host_namespaces", "worker_local_tmpfs_processes", "worker_stdio_proposals", "worker_stdio_claims",
    "worker_stderr", "host_command_lifecycle", "host_endpoint_effect", "host_authority_control",
    "host_watchdog_stop_reconciliation", "external_model_mcp_host_shell_delegation", "host_receiver_fence_control",
), ("DENIED", "READ_ONLY", "DENIED", "DENIED", "RESTRICTED", "CONFINED", "MEDIATED", "OBSERVATION_ONLY",
    "OBSERVATION_ONLY", "MEDIATED", "MEDIATED", "TRUSTED_CONTROL", "TRUSTED_CONTROL", "DENIED", "TRUSTED_CONTROL")))
_SDK = "sdk/liminal_agent_control/"
BINDINGS = {
    "idea_store": (_SDK + "center_continuity.py", "CenterContinuityStore.record_idea"),
    "projection_store": (_SDK + "center_continuity.py", "CenterContinuityStore.project"),
    "orientation": (_SDK + "orientation.py", "admission_in_transaction"),
    "session_authority": (_SDK + "brakes_store.py", "SessionAuthority"),
    "observer_auth": (_SDK + "observer_auth.py", "ObserverAuthStore.ingest"),
    "launch_inventory": (_SDK + "external_agent_launch.py", "build_channel_inventory"),
    "launch_gate": (_SDK + "external_agent_launch.py", "ClosedChannelLaunchGate.assert_ready"),
    "channel_inspect": (_SDK + "external_agent_channels.py", "verify_agent_channels"),
    "proposal_bridge": (_SDK + "external_agent_bridge.py", "ExternalAgentBridge"),
    "effect_gateway": (_SDK + "external_agent_receiver_gateway.py", "ReceiverFencedEffectGateway"),
    "effect_authority": (_SDK + "external_authority.py", "ExternalAuthorityStore"),
    "begin_permit": (_SDK + "external_authority.py", "ExternalAuthorityStore.begin"),
    "dispatch_recheck": (_SDK + "external_agent_effect_gateway.py", "ClosedChannelEffectGateway._before_endpoint_commit"),
    "receiver_store": (_SDK + "external_agent_receiver.py", "ReceiverFenceStore"),
    "coordinator": (_SDK + "external_agent_coordinator.py", "ExternalAgentCoordinator"),
    "receiver_demo": (_SDK + "external_agent_receiver_demo.py", None),
    "receiver_verifier": ("scripts/verify_external_agent_receiver_evidence.py", "verify_report"),
}
NODES = {
    "idea": ("ideas", "idea", "idea_store"), "projection": ("project", "projection", "projection_store"),
    "orientation_admission": ("project", "control", "orientation"),
    "session_admission": ("project", "control", "session_authority"),
    "signed_observation": ("real", "evidence", "observer_auth"), "proposal": ("ideas", "proposal", None),
    "launch": ("project", "control", "launch_gate"), "inventory": ("project", "control", "launch_inventory"),
    "inspect": ("real", "control", "channel_inspect"), "bridge": ("project", "control", "proposal_bridge"),
    "authorization": ("project", "control", "effect_authority"), "begin": ("time", "control", "begin_permit"),
    "dispatch_recheck": ("time", "control", "dispatch_recheck"),
    "receiver_fence": ("real", "control", "receiver_store"), "synthetic_effect": ("real", "effect", "receiver_store"),
    "stop": ("time", "control", "coordinator"), "unknown_query": ("time", "control", "effect_gateway"),
    "runtime_report": ("real", "evidence", "receiver_demo"),
    "independent_verifier": ("project", "evidence", "receiver_verifier"),
}
GRAPH_KEYS = {"schema", "classification", "execution_authorized", "scope", "spaces", "source_bindings",
              "nodes", "edges", "requirements", "channels", "evidence_roles", "temporal_contract", "gaps"}
NONFLOW_EDGES = frozenset({
    ("idea", "projection", "describes"),
    ("projection", "orientation_admission", "describes"),
    ("orientation_admission", "session_admission", "supports"),
    ("signed_observation", "orientation_admission", "supports"),
    ("inventory", "launch", "supports"),
    ("inspect", "launch", "supports"),
    ("runtime_report", "independent_verifier", "supports"),
    ("independent_verifier", "receiver_fence", "supports"),
    ("stop", "begin", "invalidates"),
    ("stop", "dispatch_recheck", "invalidates"),
    ("stop", "receiver_fence", "requests_fence"),
    ("receiver_fence", "unknown_query", "describes"),
})


def _unique(items: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON field: " + key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite JSON value: " + value)


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite JSON number")
    return result


def _read_json(path: Path, maximum: int) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("JSON file exceeds byte limit")
    try:
        result = json.loads(raw, object_pairs_hook=_unique, parse_constant=_reject_constant, parse_float=_finite_float)
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("invalid or excessively nested JSON") from exc
    if type(result) is not dict:
        raise ValueError("JSON root must be an object")
    return result


def load_graph(path: Path | str) -> dict:
    """Read bounded strict JSON, rejecting duplicate fields and NaN/Infinity."""
    return _read_json(Path(path), MAX_GRAPH_BYTES)


def _hex(value: Any, length: int) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def _source_file(root: Path, name: Any) -> Path:
    if (type(name) is not str or not name or len(name) > 256 or "\\" in name or ":" in name
            or any(part in {"", ".", ".."} for part in name.split("/")) or PurePosixPath(name).is_absolute()):
        raise ValueError("unsafe source path")
    path = root / name
    if not path.resolve(strict=True).is_relative_to(root) or not path.is_file():
        raise ValueError("source path escapes repository or is not a file")
    return path


def _symbol(tree: ast.AST, name: str) -> ast.AST | None:
    node = tree
    for part in name.split("."):
        choices = [child for child in getattr(node, "body", ())
                   if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == part]
        if len(choices) != 1:
            return None
        node = choices[0]
    return node


def _inventory_modes(tree: ast.AST) -> dict:
    """Inspect literal channel declarations without importing runtime code."""
    function = _symbol(tree, "build_channel_inventory")
    if function is None:
        raise ValueError("launch inventory function is absent")
    modes = {}

    def add(key: ast.AST, item: ast.AST) -> None:
        if not isinstance(key, ast.Constant) or type(key.value) is not str or not isinstance(item, ast.Dict):
            raise ValueError("channel declaration is not statically inspectable")
        values = [value for name, value in zip(item.keys, item.values)
                  if isinstance(name, ast.Constant) and name.value == "mode"]
        if (key.value in modes or len(values) != 1 or not isinstance(values[0], ast.Constant)
                or type(values[0].value) is not str):
            raise ValueError("duplicate or non-literal channel mode")
        modes[key.value] = values[0].value

    for node in ast.walk(function):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "channels":
                if not isinstance(node.value, ast.Dict):
                    raise ValueError("channel dictionary declaration is not literal")
                for key, item in zip(node.value.keys, node.value.values):
                    add(key, item)
            elif (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                  and target.value.id == "channels"):
                add(target.slice, node.value)
    return modes


def _cyclic(adjacency: dict[str, set[str]]) -> bool:
    indegree = {node: 0 for node in adjacency}
    for targets in adjacency.values():
        for target in targets:
            indegree[target] += 1
    queue = deque(node for node, degree in indegree.items() if degree == 0)
    visited = 0
    while queue:
        node = queue.popleft()
        visited += 1
        for target in adjacency[node]:
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    return visited != len(indegree)


def validate_graph(graph: Any, repository_root: Path) -> dict:
    """Validate the fixed v1 model, retaining all declared assurance gaps."""
    errors: list[str] = []

    def require(condition: bool, message: str) -> bool:
        if not condition:
            errors.append(message)
        return condition

    result = {"schema": "liminal-containment-assurance-check-v1", "model_status": "FAIL", "errors": errors,
              "execution_authorized": False, "containment_status": "NOT_ESTABLISHED", "readiness": "HOLD",
              "gaps": copy.deepcopy(GAPS)}
    if not require(type(graph) is dict, "graph must be an object"):
        return result
    require(set(graph) == GRAPH_KEYS, "unknown or missing graph fields require a new schema review")
    require(graph.get("schema") == SCHEMA, "unsupported graph schema")
    require(graph.get("classification") == "EVIDENCE_ONLY", "graph is evidence only")
    require(graph.get("execution_authorized") is False, "graph cannot grant execution authority")
    spaces = graph.get("spaces")
    require(type(spaces) is list and len(spaces) == 4 and all(type(x) is str for x in spaces)
            and set(spaces) == {"ideas", "project", "real", "time"}, "the four declared spaces are required")
    scope = graph.get("scope")
    if require(type(scope) is dict, "scope must be an object"):
        require(set(scope) == {"claim", "basis_commit", "basis_tree", "universal_escape_prevention", "assumptions"},
                "scope fields differ from v1 contract")
        require(scope.get("claim") == CLAIM, "scope claim differs from the bounded v1 meaning")
        require(scope.get("basis_commit") == BASIS_COMMIT and scope.get("basis_tree") == BASIS_TREE,
                "historical graph basis differs from the frozen v1 commit/tree")
        require(scope.get("universal_escape_prevention") is False, "universal escape prevention is not established")
        assumptions = scope.get("assumptions")
        require(type(assumptions) is list and len(assumptions) == len(ASSUMPTIONS)
                and all(type(x) is str for x in assumptions) and set(assumptions) == ASSUMPTIONS,
                "all six explicit trust assumptions are required")
    require(graph.get("temporal_contract") == TEMPORAL, "temporal contract differs from fixed v1 meanings")
    require(graph.get("gaps") == GAPS, "mandatory gaps cannot be removed or claimed closed by this model")
    require(graph.get("requirements") == REQUIREMENTS, "fixed G03 entry, effect and ordered guards are required")

    bindings, trees, paths = {}, {}, {}
    source_bindings = graph.get("source_bindings")
    if require(type(source_bindings) is list and len(source_bindings) == len(BINDINGS), "all 17 source bindings are required"):
        try:
            root = Path(repository_root).resolve(strict=True)
        except (OSError, ValueError, TypeError, RuntimeError) as exc:
            errors.append("repository root unavailable: " + str(exc))
            root = None
        for binding in source_bindings:
            if not require(type(binding) is dict, "source binding must be an object"):
                continue
            name = binding.get("id")
            if not require(type(name) is str and name in BINDINGS and name not in bindings, "unknown or duplicate binding ID"):
                continue
            bindings[name] = binding
            expected_path, expected_symbol = BINDINGS[name]
            expected_keys = {"id", "path", "sha256"} | ({"symbol"} if expected_symbol is not None else set())
            require(set(binding) == expected_keys, "source binding fields differ: " + name)
            require(binding.get("path") == expected_path and binding.get("symbol") == expected_symbol,
                    "source path/symbol contract differs: " + name)
            if root is None:
                continue
            try:
                path = _source_file(root, binding.get("path"))
                with path.open("rb") as stream:
                    raw = stream.read(MAX_SOURCE_BYTES + 1)
                if len(raw) > MAX_SOURCE_BYTES:
                    raise ValueError("source byte limit exceeded")
                require(_hex(binding.get("sha256"), 64) and hashlib.sha256(raw).hexdigest() == binding.get("sha256"),
                        "source SHA256 mismatch: " + name)
                tree = ast.parse(raw, filename=str(path))
                if expected_symbol is not None:
                    require(_symbol(tree, expected_symbol) is not None, "bound AST symbol is absent: " + name)
                trees[name], paths[name] = tree, path.resolve()
            except (OSError, ValueError, SyntaxError, RecursionError, RuntimeError) as exc:
                errors.append("invalid source binding " + name + ": " + str(exc))
    require(set(bindings) == set(BINDINGS), "source binding set differs from v1")
    if "launch_inventory" in trees:
        try:
            require(_inventory_modes(trees["launch_inventory"]) == CHANNEL_MODES,
                    "actual LaunchInventory channel IDs/modes differ from the fixed 15-channel contract")
        except ValueError as exc:
            errors.append(str(exc))

    nodes = {}
    raw_nodes = graph.get("nodes")
    if require(type(raw_nodes) is list and len(raw_nodes) == len(NODES), "all 19 nodes are required"):
        for node in raw_nodes:
            if not require(type(node) is dict, "node must be an object"):
                continue
            name = node.get("id")
            if not require(type(name) is str and name in NODES and name not in nodes, "unknown or duplicate node ID"):
                continue
            nodes[name] = node
            space, kind, binding = NODES[name]
            require(set(node) == ({"id", "space", "kind"} | ({"binding"} if binding else set()))
                    and (node.get("space"), node.get("kind"), node.get("binding")) == (space, kind, binding),
                    "node kind/space/source contract differs: " + name)
            if binding is not None:
                require(binding in bindings, "node lacks its source binding: " + name)
    require(set(nodes) == set(NODES), "fixed node set cannot be renamed or removed")

    roles = graph.get("evidence_roles")
    require(roles == {"producer": "receiver_demo", "verifier": "receiver_verifier"}, "independent evidence roles differ")
    if type(roles) is dict:
        producer, verifier = roles.get("producer"), roles.get("verifier")
        require(type(producer) is str and type(verifier) is str and producer != verifier
                and producer in paths and verifier in paths and paths[producer] != paths[verifier],
                "evidence producer and verifier require distinct source bindings AND source files")

    channels = graph.get("channels")
    seen_channels = set()
    if require(type(channels) is list and len(channels) == 15, "exactly 15 channels are required"):
        for channel in channels:
            if not require(type(channel) is dict, "channel must be an object"):
                continue
            name = channel.get("id")
            if not require(type(name) is str and name in CHANNEL_MODES and name not in seen_channels,
                           "unknown or duplicate channel ID"):
                continue
            seen_channels.add(name)
            barrier = "receiver_fence" if name == "host_receiver_fence_control" else "launch"
            require(set(channel) == {"id", "mode", "barrier", "inventory_binding", "inspection_binding"}
                    and channel.get("mode") == CHANNEL_MODES[name] and channel.get("barrier") == barrier
                    and channel.get("inventory_binding") == "launch_inventory"
                    and channel.get("inspection_binding") == "channel_inspect", "channel route contract differs: " + name)
            barrier_binding = nodes.get(barrier, {}).get("binding")
            require(nodes.get(barrier, {}).get("kind") == "control" and type(barrier_binding) is str
                    and barrier_binding in bindings, "channel barrier is not a source-bound control: " + name)
    require(seen_channels == set(CHANNEL_MODES), "channel inventory set is incomplete")

    flow = {name: set() for name in nodes}
    supports = {name: set() for name in nodes}
    edges = graph.get("edges")
    seen_edges = set()
    if require(type(edges) is list and 0 < len(edges) <= 128, "edge list is missing or oversized"):
        for edge in edges:
            if not require(type(edge) is dict and set(edge) == {"from", "to", "kind"}, "invalid edge fields"):
                continue
            origin, target, kind = edge.get("from"), edge.get("to"), edge.get("kind")
            if not require(all(type(x) is str for x in (origin, target, kind))
                           and origin in nodes and target in nodes
                           and kind in {"flow", "supports", "describes", "invalidates", "requests_fence"},
                           "dangling edge or unknown edge kind"):
                continue
            key = (origin, target, kind)
            require(key not in seen_edges, "duplicate edge")
            seen_edges.add(key)
            if kind == "flow":
                flow[origin].add(target)
                require(origin in {"proposal", *GUARDS} and target in {*GUARDS, "synthetic_effect"},
                        "a non-G03 node cannot be claimed connected to this fixed effect route")
                require((nodes[origin].get("kind") == "control" or origin == "proposal")
                        and nodes[target].get("kind") in ("control", "effect"),
                        "ideas, projections or evidence cannot grant effect flow; proposal is the sole untrusted entry")
            elif kind == "supports":
                supports[origin].add(target)
    require({edge for edge in seen_edges if edge[2] != "flow"} == NONFLOW_EDGES,
            "the 12 fixed four-space nonflow connections and their meanings are required")
    flow_cycle = _cyclic(flow)
    require(not flow_cycle, "flow graph contains a cycle")
    require(not _cyclic(supports), "supports dependencies contain a cycle")
    if not flow_cycle and "proposal" in nodes:
        queue, visited, reached = deque([("proposal", 0)]), set(), False
        while queue:
            node, count = queue.popleft()
            if (node, count) in visited:
                continue
            visited.add((node, count))
            if node == "synthetic_effect":
                reached = True
                require(count == len(GUARDS), "an entry-to-effect path bypasses or reorders a required guard")
            for target in flow[node]:
                next_count = count
                if target in GUARDS:
                    next_count = count + 1 if 0 <= count < len(GUARDS) and target == GUARDS[count] else -1
                queue.append((target, next_count))
        require(reached, "fixed G03 entry-to-effect path is absent")
    result["model_status"] = "FAIL" if errors else "PASS"
    return result


def inspect_receiver_report(report_path: Path | str, repo_root: Path) -> dict:
    """Check a report in a trusted repository whose graph/source bindings passed.

    The caller supplies that trust boundary; the CLI validates it before calling
    this function. A temporary test repository can exercise source transitions,
    but does not establish that the actual G03 runtime produced any evidence.
    """
    result: dict[str, Any] = {"runtime_evidence": "FAIL", "errors": [], "execution_authorized": False,
                              "containment_status": "NOT_ESTABLISHED", "readiness": "HOLD"}
    try:
        root = Path(repo_root).resolve(strict=True)
        report_path = Path(report_path).resolve(strict=True)
        report = _read_json(report_path, MAX_REPORT_BYTES)
        with report_path.open("rb") as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("report file exceeds byte limit")
        raw_hash = hashlib.sha256(raw).hexdigest()
        result["report_sha256"] = raw_hash
        identity = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD", "HEAD^{tree}"],
                                  capture_output=True, text=True, check=True, timeout=10).stdout.splitlines()
        if len(identity) != 2 or not all(_hex(value, 40) for value in identity):
            raise ValueError("current Git source identity is invalid")
        expected = {"commit": identity[0], "tree": identity[1]}
        result["expected_source"] = expected
        status = subprocess.run(["git", "-C", str(root), "status", "--porcelain"],
                                capture_output=True, text=True, check=True, timeout=10).stdout
        source = report.get("source")
        if (status or type(source) is not dict or source.get("commit") != expected["commit"]
                or source.get("tree") != expected["tree"] or source.get("dirty") is not False):
            result["runtime_evidence"] = "STALE"
            result["errors"].append("report does not bind the exact current clean Git HEAD/tree")
            return result
        verifier = _source_file(root, BINDINGS["receiver_verifier"][0])
        checked = subprocess.run([sys.executable, "-I", "-B", str(verifier), str(report_path),
                                  "--expected-source-sha", expected["commit"], "--expected-report-sha256", raw_hash],
                                 cwd=root, capture_output=True, text=True, timeout=45)
        final_identity = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD", "HEAD^{tree}"],
                                        capture_output=True, text=True, check=True, timeout=10).stdout.splitlines()
        final_status = subprocess.run(["git", "-C", str(root), "status", "--porcelain"],
                                      capture_output=True, text=True, check=True, timeout=10).stdout
        if final_identity != identity or final_status:
            result["runtime_evidence"] = "STALE"
            result["errors"].append("checked-out source identity or cleanliness changed during independent verification")
            return result
        verification = json.loads(checked.stdout, object_pairs_hook=_unique, parse_constant=_reject_constant,
                                  parse_float=_finite_float)
        if (checked.returncode != 0 or type(verification) is not dict
                or verification.get("schema") != "liminal-external-agent-receiver-verification-v1"
                or verification.get("status") != "PASS" or verification.get("execution_authorized") is not False
                or verification.get("report_sha256") != raw_hash):
            raise ValueError("existing independent receiver verifier did not validate this report")
        result["verification"] = verification
        result["runtime_evidence"] = "PASS"
    except (OSError, ValueError, TypeError, subprocess.SubprocessError, RecursionError) as exc:
        result["errors"].append(str(exc))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", type=Path)
    parser.add_argument("--root", "--repo-root", dest="root", type=Path, default=ROOT)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--require-current-report", action="store_true")
    args = parser.parse_args(argv)
    try:
        graph = load_graph(args.graph or args.root / "docs/containment_assurance_graph.v1.json")
        result = validate_graph(graph, args.root)
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        result = {"schema": "liminal-containment-assurance-check-v1", "model_status": "FAIL", "errors": [str(exc)],
                  "execution_authorized": False, "containment_status": "NOT_ESTABLISHED", "readiness": "HOLD",
                  "gaps": copy.deepcopy(GAPS)}
    runtime = (inspect_receiver_report(args.report, args.root)
               if args.report and result["model_status"] == "PASS" else {"runtime_evidence": "NOT_RUN"})
    if args.report and result["model_status"] != "PASS":
        result["errors"].append("runtime report was not inspected because the graph/source bindings failed")
    result["errors"].extend("runtime report: " + error for error in runtime.pop("errors", []))
    result.update(runtime)
    result["meaning"] = "Model consistency is separate from runtime evidence; neither authorizes execution or establishes containment."
    print(json.dumps(result, indent=2, sort_keys=True))
    return int(result["model_status"] != "PASS" or (args.report is not None or args.require_current_report)
               and result["runtime_evidence"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
