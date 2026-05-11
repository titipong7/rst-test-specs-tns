# CrewAI-Style Agent Workflow in Cursor

This workflow defines how agents collaborate for auto development in this
repository while keeping human approval before merge.

## End-to-End Flow

1. `Planner` receives requirement and creates executable plan.
2. `Builder` implements approved scope and adds tests.
3. `Tester` validates acceptance criteria and reports confidence.
4. `Reviewer` performs risk-based review and enforces severity gate.
5. Human approves and proceeds to PR merge.

## Handoff Contract

### Planner -> Builder

Planner output must include:

- Scope and non-goals
- Task breakdown
- Acceptance criteria
- Candidate files to touch
- Assumptions and risks

### Builder -> Tester

Builder output must include:

- Changed files list
- Diff summary mapped to acceptance criteria
- Commands executed
- Known limitations/deferred items

### Tester -> Reviewer

Tester output must include:

- Test matrix (`criterion`, `command`, `result`)
- Failures with root-cause hypothesis
- Distinction between new failures and pre-existing issues
- Confidence statement (`high`, `medium`, `low`)

### Reviewer -> Human

Reviewer output must include:

- Findings grouped by severity
- Must-fix items before merge
- Explicit statement: `merge_ready: true|false`

## Artifact Storage Convention

- Plan: `docs/agent-artifacts/<feature>/plan.md`
- Build notes: `docs/agent-artifacts/<feature>/build.md`
- Test report: `docs/agent-artifacts/<feature>/test.md`
- Review report: `docs/agent-artifacts/<feature>/review.md`

## Operational Rules

- No role may skip required output fields.
- Scope changes require explicit re-plan.
- Any `blocker`/`high` review finding prevents merge.