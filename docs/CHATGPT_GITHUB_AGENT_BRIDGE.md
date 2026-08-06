# ChatGPT GitHub Agent Bridge v0.6

## Purpose

The GitHub Agent Bridge is a typed, fail-closed layer between a host-owned
GitHub connector and the existing Liminal session pipeline.

```text
explicit user authorization
→ typed GitHubOperation
→ repository/ref/payload policy validation
→ Host Integration Adapter v0.5
→ host invokes its real GitHub connector
→ explicit GitHubExecutorResult
→ Session Recorder v0.4
→ Live Session Exporter v0.3
→ Conversation Normalizer v0.2
→ Liminal Adapter v0.1
→ ALLOW | REVISE | VERIFY | NO_SIGNAL
```

The bridge does not connect itself to hosted ChatGPT or GitHub. A host
application supplies the real executor callback. The bridge validates the exact
action and arguments before that callback can run and records the observed
outcome through v0.5.

## Python API

```python
from sdk.liminal_github_bridge import (
    GitHubAgentBridge,
    GitHubExecutorResult,
    GitHubOperation,
)

bridge = GitHubAgentBridge.create(
    "reports/github-bridge-config.json",
    host_trace_path="reports/host-trace.json",
    recorder_path="reports/session-journal.json",
    session_id="session-1",
    high_stakes=False,
    requires_current_information=True,
    allowed_repositories=["owner/repository"],
)

operation = GitHubOperation(
    call_id="create-branch-1",
    action="create_branch",
    arguments={
        "repository_full_name": "owner/repository",
        "branch_name": "agent/change-1",
        "base_ref": "main",
    },
)

bridge.authorize_operation(
    event_id="auth-1",
    text="Authorize exactly create-branch-1",
    operation=operation,
)

def github_executor(action, arguments):
    # The host dispatches to its connected GitHub tool here.
    connector_payload = real_github_dispatch(action, arguments)
    return GitHubExecutorResult.success(
        locator="refs/heads/agent/change-1@<commit-sha>",
        payload=connector_payload,
    )

receipt = bridge.execute(operation, github_executor)
```

`execute` passes a deep copy of validated arguments to the callback. The
callback must return an explicit `success`, `failure`, or `cancelled` result,
with a non-empty evidence locator and JSON-serializable payload. The bridge
never converts optimistic prose into a success result.

## Supported actions

Read actions:

- `get_repo`
- `fetch_file`
- `fetch_pr`
- `compare_commits`
- `get_commit_combined_status`
- `list_pr_changed_filenames`

Write actions:

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

Unknown actions and unknown argument fields fail closed.

## Exact connector-shaped arguments

The normalized argument object uses the GitHub connector's parameter names.
For example, `fetch_file` uses `repository_full_name`, while `fetch_pr` and
`compare_commits` use `repo_full_name`.

The executor receives only the validated normalized object. Credentials, tokens,
headers, arbitrary URLs, and caller-supplied hidden metadata are not accepted by
any v0.6 operation schema.

## Authorization

Every write action uses its `GitHubOperation.call_id` as the exact v0.5 tool call
ID.

```text
user_authorization → exact GitHub call ID → host tool start → GitHub connector
```

A positive-sounding user message is not authorization. The host must explicitly
record a `user_authorization` event targeting the exact call ID before
`execute`. If that edge is absent, v0.5 stops the write before the executor
callback is invoked.

Read operations do not require a write authorization edge, but they are still
recorded as evidence-eligible tool events.

## Repository and ref policy

A bridge config has an immutable, SHA-256 protected repository allowlist. Every
operation must target one exact `owner/name` entry.

Default protected branches are `main` and `master`.

The following direct operations are blocked when their target is protected:

- `create_file`
- `update_file`
- `delete_file`
- `update_ref`
- creation of a new branch using a protected branch name

File writes require an explicit non-protected `branch`; omitting a branch is not
allowed because a connector default could silently write to the repository's
default branch.

Creating a pull request whose base is `main` is allowed. Merging a pull request
is separately authorized and requires `expected_head_sha`, preventing the merge
from silently accepting a moved PR head.

Force ref updates are not supported in v0.6.

## Request and result integrity

Every normalized operation receives a deterministic SHA-256 over:

```json
{
  "call_id": "...",
  "action": "...",
  "arguments": {}
}
```

The digest is embedded in the v0.5 operation summary. Large content is therefore
bound to the audit trace without being copied into the human-readable operation
string.

The returned receipt contains:

- operation request SHA-256;
- result payload SHA-256;
- explicit status and locator;
- recorder event ID and head SHA-256;
- host trace head SHA-256;
- the fixed no-authority map.

A receipt is a returned artifact, not a substitute for connector-side
verification. The claim evidence used downstream remains the recorded tool event
and locator.

## Write-specific safeguards

- `create_branch` requires exactly one of `sha` or `base_ref`.
- `update_file` and `delete_file` require the current blob SHA.
- `update_ref` rejects `force=true`.
- `merge_pull_request` requires the exact expected PR head SHA.
- repository paths reject absolute paths, empty components, `.` and `..`.
- Git SHAs must be full 40-character hexadecimal values.
- branch/ref names reject dangerous Git ref syntax.
- requests larger than `max_request_bytes` fail before execution.

## CLI

The CLI manages the durable bridge configuration and visible-session lifecycle.
It deliberately does not provide a command that pretends to perform a GitHub
connector call.

```bash
python3 tools/chatgpt_github_agent_bridge.py init \
  --config reports/github-bridge-config.json \
  --trace reports/host-trace.json \
  --journal reports/session-journal.json \
  --session-id session-1 \
  --allow-repo owner/repository \
  --requires-current-information

python3 tools/chatgpt_github_agent_bridge.py validate-operation \
  --config reports/github-bridge-config.json \
  --operation operation.json

python3 tools/chatgpt_github_agent_bridge.py verify \
  --config reports/github-bridge-config.json
```

Additional commands are `append`, `seal`, and `export`. Real connector execution
uses the Python callback API so the host start and finish records surround the
actual invocation.

## Deterministic safety properties

1. Only a fixed action catalog is accepted.
2. Every action has an exact field schema.
3. Every repository must appear in the SHA-protected allowlist.
4. Direct writes to configured protected branches are rejected.
5. Every write requires a prior authorization edge to the exact call ID.
6. Unauthorized writes stop before the executor callback.
7. Force ref updates are rejected.
8. PR merge requires `expected_head_sha`.
9. Request size is bounded before execution.
10. Executor arguments are deep-copied.
11. Status, locator, and payload are explicit host outputs.
12. Request and response payloads receive deterministic SHA-256 receipts.
13. v0.5 continues to enforce pending-call, tamper, and recorder correlation
    rules.
14. The full exported session continues through v0.3, v0.2, and v0.1.

## Authority boundary

The bridge has no authority to:

- access hidden messages, chain-of-thought, or model state;
- infer user authorization or factual claims from prose;
- obtain or store GitHub credentials;
- choose repositories outside its allowlist;
- perform GitHub calls without a host-supplied executor;
- fabricate connector results or evidence locators;
- force-push;
- approve, merge, deploy, publish, or deliver on its own;
- modify model weights;
- write hidden or persistent model memory.

The host remains responsible for real credentials, GitHub permissions, connector
availability, sensitive-content redaction, and translating the connector's
actual response into an explicit `GitHubExecutorResult`.
