# Tester Validation Skill

## Purpose

Validate implemented behavior against acceptance criteria and report confidence.

## Input Contract

- Acceptance criteria
- Test strategy
- Changed files

## Output Contract

1. Test matrix (`criterion`, `test`, `result`)
2. Commands and outcomes
3. Failure analysis
4. Release confidence summary

## Checklist

- Cover happy path and critical edge cases.
- Separate pre-existing failures from introduced regressions.
- Recommend follow-up tests when full suite cannot run.
