# Main Branch Protection Runbook

Status: required repository control for `main` before production or strong security claims.

Tracked by: #134

## Why this exists

LiminalOSAI can fail closed inside its governance runtime, but an unprotected GitHub default branch is an external authority bypass around that evidence chain. A direct push, force push, branch deletion, or merge that bypasses review/check gates can invalidate the assumptions made by exact-head verification and portable receipts.

This runbook defines the repository-level control plane that must surround the runtime governance stack.

## Required target state

`main` MUST satisfy all of the following:

1. Direct pushes are rejected for ordinary development.
2. Changes reach `main` only through pull requests.
3. Required CI checks pass on the exact PR head before merge.
4. The PR branch is up to date with `main` before merge, or an equivalent exact-head merge queue/ruleset guarantee is enforced.
5. Review conversations are resolved before merge.
6. Force pushes are disabled.
7. Branch deletion is disabled.
8. Administrator/bypass use is restricted and treated as break-glass activity.
9. Merge commits remain attributable and GitHub verification status is preserved where supported.
10. Any emergency bypass produces durable evidence and a follow-up review.

## Minimum always-required checks

The current Core CI workflow produces three always-on jobs that should be required for `main`:

- `gcc strict build`
- `clang strict build`
- `ASan and UBSan`

Repository security workflows that are intentionally path- or feature-scoped must also be required whenever they are applicable to a PR. Prefer a GitHub Ruleset / required-workflow configuration for this when available, because static branch-protection check contexts are a poor fit for jobs that do not run on every change.

Examples of security-critical workflow families currently present in the repository include governance/identity, portable receipts, capability broker, egress, causal escalation, containment, runtime mediation, session recorder, and isolated execution checks. Do not mark a path-scoped check as globally required unless the workflow is guaranteed to emit that check for every pull request; otherwise merges can become permanently blocked on an expected-but-never-created check.

## Recommended GitHub configuration

Use a repository Ruleset targeting the default branch if available. Otherwise use classic branch protection with equivalent settings.

### Pull request gate

- Require a pull request before merging.
- Require at least one approving review for non-documentation security/runtime changes.
- Dismiss stale approvals when new commits are pushed.
- Require review-thread resolution.
- Do not permit ordinary direct pushes to `main`.

### Status gate

- Require status checks before merging.
- Require the branch to be up to date before merging, unless a merge queue/ruleset provides an equivalent exact-head guarantee.
- Require the three Core CI jobs listed above.
- Add security-critical path-specific workflows through required-workflow rules where GitHub supports them.

### History / destructive operations

- Disable force pushes.
- Disable branch deletion.
- Keep signed/verified GitHub merge history where supported.
- Do not use bypass permissions as a normal merge path.

## Exact-head invariant

The final merge decision MUST bind to the reviewed PR head SHA.

Before merge:

1. read the current PR head SHA;
2. confirm all required checks belong to that SHA and are successful;
3. confirm no unresolved review thread exists;
4. confirm the base/head relationship still satisfies repository policy;
5. merge with an expected-head guard where the API supports it;
6. verify the resulting `main` commit and GitHub signature state after merge.

A previously green SHA is not evidence for a newer PR head.

## Break-glass procedure

Break-glass is only for repository recovery when the normal PR/check path cannot safely restore service or integrity.

### Preconditions

- Normal PR flow is unavailable or would materially worsen the incident.
- A named human operator explicitly authorizes the bypass.
- The exact intended mutation is documented before execution when circumstances permit.

### Required evidence

Record:

- incident ID or issue URL;
- human authorizer identity;
- reason normal governance could not be used;
- `main` SHA before the bypass;
- exact files/refs/settings changed;
- command/API operation or GitHub UI action used;
- `main` SHA after the bypass;
- verification/check results available immediately afterward;
- credentials or secret values: NEVER record these, only non-secret identifiers/digests where needed;
- recovery/rollback result;
- follow-up PR or review issue.

### Mandatory follow-up

After any bypass:

1. restore ordinary protection immediately;
2. run the complete relevant CI/security suite against the resulting exact head;
3. open a review issue describing the event and evidence;
4. reproduce the emergency mutation through the normal PR path when practical;
5. verify that branch protection/ruleset enforcement is active again;
6. do not describe the repository as fully governed until the bypass has been reconciled.

## Controlled negative test

After protection is enabled, perform a non-destructive enforcement test from a disposable branch/worktree or API client:

1. record current `main` SHA;
2. attempt a direct non-force update to `main` using an ordinary developer credential without bypass permission;
3. expect GitHub to reject the update because required branch/ruleset policy is not satisfied;
4. re-read `main` and prove its SHA did not change;
5. preserve the rejection response/status as evidence;
6. do NOT use a destructive force-push test.

The acceptance result is fail-closed only when GitHub rejects the mutation and the branch SHA remains unchanged.

## Verification checklist for #134

The issue may be closed only when all are true:

- [ ] GitHub branch/ruleset metadata reports protection/enforcement for `main`.
- [ ] Direct ordinary pushes are rejected.
- [ ] PRs are required.
- [ ] Core CI required checks are configured.
- [ ] Applicable security-critical workflows are enforced without creating permanently pending checks.
- [ ] Exact-head/up-to-date behavior is enforced.
- [ ] Force pushes are blocked.
- [ ] Branch deletion is blocked.
- [ ] Review-thread resolution is required.
- [ ] Break-glass policy is documented and evidence requirements are explicit.
- [ ] Controlled negative test proves `main` remains unchanged after a rejected direct mutation.

## Non-claims

This document does not itself enable GitHub protection, prove that a ruleset is active, or turn repository configuration into runtime authority. The configured GitHub control plane remains an external trust dependency and must be verified from GitHub metadata.