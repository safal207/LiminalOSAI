# Connected GitHub Runtime Harness v0.7

## Purpose

The Connected GitHub Runtime Harness is the fixed dispatcher above the v0.6
GitHub Agent Bridge.

It removes per-operation callback wiring. A host supplies one already connected
GitHub namespace or one generic invoker:

```text
validated GitHubOperation
→ fixed v0.7 action registry
→ exact connected GitHub tool name
→ connector response normalization
→ GitHub Agent Bridge v0.6
→ Host Integration Adapter v0.5
→ Session Recorder v0.4
→ Live Session Exporter v0.3
→ Conversation Normalizer v0.2
→ Liminal Adapter v0.1
```

The runtime does not discover tools, accept arbitrary method names, obtain
credentials, or attach itself to hosted ChatGPT. It dispatches only the fixed
registry compiled into v0.7.

## Python API

```python
from sdk.liminal_github_bridge import GitHubAgentBridge, GitHubOperation
from sdk.liminal_github_runtime import (
    ConnectedGitHubRuntime,
    ConnectorNamespaceInvoker,
)

GitHubAgentBridge.create(
    "reports/github-bridge.json",
    host_trace_path="reports/host-trace.json",
    recorder_path="reports/session-journal.json",
    session_id="session-1",
    high_stakes=False,
    requires_current_information=True,
    allowed_repositories=["owner/repository"],
)

runtime = ConnectedGitHubRuntime.create(
    "reports/connected-runtime.json",
    bridge_config_path="reports/github-bridge.json",
)

operation = GitHubOperation(
    call_id="create-branch-1",
    action="create_branch",
    arguments={
        "repository_full_name": "owner/repository",
        "branch_name": "agent/review-branch",
        "base_ref": "main",
    },
)

runtime.authorize_operation(
    event_id="authorization-1",
    text="Authorize exactly create-branch-1",
    operation=operation,
)

receipt = runtime.execute(
    operation,
    ConnectorNamespaceInvoker(connected_github_namespace),
)
```

`ConnectorNamespaceInvoker` calls the method whose name is fixed by the
registry and passes the normalized arguments as keyword arguments. A host that
already exposes `invoke(tool_name, arguments)` may pass that invoker directly.

## Fixed registry

v0.7 maps only these v0.6 actions:

### Reads

- `get_repo`
- `fetch_file`
- `fetch_pr`
- `compare_commits`
- `get_commit_combined_status`
- `list_pr_changed_filenames`

### Writes

- `create_branch`
- `create_file`
- `update_file`
- `delete_file`
- `create_blob`
- `create_tree`
- `create_commit`
- `update_ref`
- `create_pull_request`
- `merge_pull_request`

Every action maps one-to-one to the same connected GitHub tool name. The full
mapping has a deterministic `registry_sha256` stored in the signed runtime
configuration.

Arbitrary names, aliases, URLs, shell commands, GraphQL text, REST paths, and
credential fields are not accepted.

## Response normalization

The connector may return either a direct JSON payload or a bounded envelope:

```json
{
  "result": {"branch": "agent/review-branch", "sha": "..."},
  "error": null
}
```

v0.7:

1. canonicalizes the complete raw response;
2. rejects non-JSON values;
3. enforces `max_response_bytes`;
4. calculates `raw_response_sha256`;
5. unwraps a successful result or preserves an explicit connector error;
6. applies an action-specific success contract;
7. calculates `normalized_payload_sha256`;
8. supplies the result to v0.6 for recorder and host-trace correlation.

Examples of action-specific contracts:

- branch creation requires a non-empty branch;
- file writes require a full commit SHA;
- blob, tree, and commit creation require a full Git SHA;
- pull-request creation requires a URL or positive PR number;
- merge succeeds only with `merged=true` and a full merge SHA;
- `merged=false` is recorded as a failure rather than success.

The runtime does not reinterpret a malformed success payload as success.

## Receipts

A successful or explicit connector-failure dispatch returns a
`chatgpt-connected-github-runtime-v0.7` receipt containing:

- exact call ID and action;
- connector name and fixed tool name;
- v0.6 `request_sha256`;
- `raw_response_sha256`;
- `normalized_payload_sha256`;
- status and locator;
- `bridge_receipt_sha256`;
- recorder event ID and recorder head;
- host-trace head;
- fixed no-authority map.

The raw response body is not copied into the receipt.

## Authorization and branch safety

v0.7 inherits all v0.6 controls before the connector can run:

- exact repository allowlist;
- explicit prior authorization for every write call ID;
- direct writes to `main` and `master` blocked by default;
- no force ref updates;
- merge requires exact `expected_head_sha`;
- strict repository paths and Git refs;
- bounded request size.

A missing connected namespace method is rejected during preflight, before a
host tool-call start record is written.

## Failure behavior

- Explicit connector error envelopes become recorded `failure` outcomes.
- `merged=false` becomes a recorded `failure`.
- Connector exceptions are recorded by v0.5 as failed tool calls and re-raised.
- Oversized, non-JSON, or malformed successful responses fail closed.
- Configuration or registry tampering fails verification.
- Unsupported actions never reach the connector.

## CLI

The CLI manages deterministic lifecycle state but does not obtain connector
credentials or execute GitHub calls itself.

```bash
python3 tools/chatgpt_connected_github_runtime.py init \
  --runtime-config reports/connected-runtime.json \
  --bridge-config reports/github-bridge.json \
  --host-trace reports/host-trace.json \
  --journal reports/session-journal.json \
  --session-id session-1 \
  --allowed-repository owner/repository \
  --requires-current-information

python3 tools/chatgpt_connected_github_runtime.py bindings \
  --runtime-config reports/connected-runtime.json

python3 tools/chatgpt_connected_github_runtime.py validate \
  --runtime-config reports/connected-runtime.json \
  --operation operation.json

python3 tools/chatgpt_connected_github_runtime.py verify \
  --runtime-config reports/connected-runtime.json
```

Additional lifecycle commands are `authorize`, `seal`, and `export`.

## Authority boundary

The runtime has no authority to:

- discover or invoke arbitrary tools;
- access credentials;
- bypass v0.6 authorization or protected-branch controls;
- fabricate connector responses, statuses, locators, or source truth;
- approve response delivery;
- merge or deploy independently;
- force-push;
- inspect hidden messages or chain-of-thought;
- modify model weights;
- write hidden model memory.

The connected host remains responsible for connector installation,
authentication, availability, rate limits, and product-level permissions.
