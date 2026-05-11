# Reviewer Checklist Skill

## Purpose

Produce a risk-first code review report with severity and required actions.

## Input Contract

- Diff and changed files
- Acceptance criteria
- Test outputs

## Output Contract

Findings grouped by severity:

- `blocker`
- `high`
- `medium`
- `low`

Each finding must include evidence and required action.

## Checklist

- Confirm acceptance criteria are met.
- Check regression risk in adjacent behavior.
- Check security and data handling implications.
- Distinguish mandatory fixes from optional improvements.
