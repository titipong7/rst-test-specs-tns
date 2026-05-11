# Planner Task Decomposition Skill

## Purpose

Break a requirement into implementable work packages with clear acceptance
criteria and handoff data for Builder.

## Input Contract

- Requirement statement
- Constraints and non-goals
- Repository context

## Output Contract

Provide a markdown plan with:

1. Scope and non-goals
2. Task list (small, independent units)
3. Acceptance criteria per task
4. Files likely to change
5. Risks and assumptions

## Checklist

- Keep each task reviewable in one PR when possible.
- Include at least one validation method per criterion.
- Flag ambiguities before implementation begins.
