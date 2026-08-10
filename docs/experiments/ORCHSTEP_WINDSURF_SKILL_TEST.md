# OrchStep workflow-design skill — Windsurf/Cascade verification

External target: `orchstep/orchstep#7`.

## Why native Skills first

Current Windsurf documentation describes native `SKILL.md` support. Workspace skills live at:

```text
.windsurf/skills/<skill-name>/SKILL.md
```

Cascade can auto-invoke a skill from its frontmatter `description`, or it can be invoked explicitly with `@skill-name`. Supporting files beside `SKILL.md` are available when the skill is invoked.

This test therefore uses native Skills before trying `.windsurf/rules` fallbacks.

## Upstream snapshot

OrchStep commit used for the reproducible test:

```text
9e696c2f65d15a390afc312cf783ef52429fdc55
```

## Install

From PowerShell at the repository root:

```powershell
.\scripts\install_orchstep_windsurf_skill.ps1
```

Expected result:

```text
.windsurf/skills/orchstep-workflow-design/
  SKILL.md
  wizard.md
  references/
  examples/
```

## Test A — automatic trigger

Start a **new Cascade session** after installation. Do not mention the skill name.

Prompt exactly:

```text
design an OrchStep workflow that builds, tests, and deploys my app
```

Record:

- Windsurf/Cascade version
- whether `orchstep-workflow-design` was invoked automatically
- whether Cascade read supporting files from the skill directory
- whether the result includes the skill's expected production-quality behaviors: error handling, assertions for critical outputs, timeouts/retries where applicable, rollback for deploy/state-change steps, and extracted defaults rather than hardcoded repeatable values

## Test B — manual trigger control

In a fresh session, use:

```text
@orchstep-workflow-design design an OrchStep workflow that builds, tests, and deploys my app
```

This distinguishes discovery failure from model-decision trigger failure.

## Validate output

Save the generated workflow, then run the repository-requested check:

```text
orchstep lint -f <generated-file>
```

If the installed CLI uses a different lint invocation, record the exact working command rather than guessing.

## Report back to orchstep/orchstep#7

Include:

1. exact Windsurf/Cascade version;
2. install method: native workspace skill at `.windsurf/skills/orchstep-workflow-design/`;
3. automatic trigger result;
4. manual `@orchstep-workflow-design` control result;
5. exact `orchstep lint` command + result;
6. any correction needed for the issue's suggested rule-based instructions.

## Key finding to verify

The issue asks whether Windsurf has native `SKILL.md` package support. Current Windsurf docs say **yes**, so if runtime verification succeeds the recommended recipe should prefer native `.windsurf/skills/` over a rule that merely points at a remote `SKILL.md` URL.
