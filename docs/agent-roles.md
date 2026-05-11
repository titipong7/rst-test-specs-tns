# Agent Roles for Auto Development

This document defines role boundaries for a CrewAI-style workflow in Cursor.
Each role must only operate on its own responsibility and emit strict output
artifacts for downstream handoff.

## Planner

- **Goal:** Turn a requirement into an executable implementation plan.
- **Input:** User requirement, repository context, constraints.
- **Output:**
  - Scope and non-goals
  - Task breakdown
  - Acceptance criteria
  - Candidate files to touch
  - Risks and open assumptions
- **Guardrails:**
  - No code edits
  - No implementation details that constrain design unless required

## Builder

- **Goal:** Implement the approved plan in small, reviewable changes.
- **Input:** Planner output and existing codebase.
- **Output:**
  - Code changes
  - Tests added or updated
  - Runbook of executed commands
  - Changed files summary
  - Known limitations
- **Guardrails:**
  - Do not expand scope without explicit approval
  - Keep diffs minimal and reversible

## Reviewer

- **Goal:** Evaluate correctness, risk, and maintainability of changes.
- **Input:** Diff, test results, changed files summary.
- **Output:**
  - Findings sorted by severity (`blocker`, `high`, `medium`, `low`)
  - Regression and security concerns
  - Required fixes before merge
  - Optional improvements
- **Guardrails:**
  - Focus on user impact and defects, not style-only comments
  - Every finding must be actionable

## Tester

- **Goal:** Validate behavior and verify release confidence.
- **Input:** Planned acceptance criteria and code diff.
- **Output:**
  - Test matrix and command results
  - Pass/fail status by criterion
  - Flaky-test notes
  - Release confidence statement
- **Guardrails:**
  - Prefer reproducible tests
  - Distinguish known pre-existing failures from new regressions
