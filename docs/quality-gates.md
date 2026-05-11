# Quality Gates

This repository uses a staged gate model before merge.

## Gate Definitions

1. **Gate 1 - Lint/Build Integrity**
   - Command: `make lint`
   - Expected: YAML and EPP extension lint checks pass.

2. **Gate 2 - Python Test Integrity**
   - Command: `pytest -q tests`
   - Expected: compliance suite passes for touched behavior.

3. **Gate 3 - Review Severity Gate**
   - Required: no open `blocker` or `high` reviewer findings.

## Unified Gate Command

Use `make quality-gate` to run Gate 1 and Gate 2 in sequence.
The target now prepares generated YAML inputs (`includes` + `yaml`) before linting.

## Bootstrap Dependencies (Dev/CI)

Before first run on a new machine, install gate dependencies:

- `make bootstrap-quality-gate`

This installs required Perl modules and `schemalint`.
The lint target resolves `schemalint` from `~/.local/bin` automatically.

In CI, `.github/workflows/quality-gate.yaml` performs bootstrap first and then
runs `make quality-gate`.
The workflow is configured for **PR only** and uses cache layers for:

- pip (via `actions/setup-python` cache)
- go module/build cache (via `actions/setup-go` cache)
- cpan artifacts (`~/.cpanm` and `~/perl5`)

## Merge Criteria

Changes are merge-ready only when:

- `make quality-gate` passes
- Reviewer marks `merge_ready: true`
- Human approval is provided
