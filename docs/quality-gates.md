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

## Dashboard

`make dashboard` (or `python3 internal-rst-checker/rst_dashboard.py --dry-run`)
regenerates two artefacts under `internal-rst-checker/reports/`:

- `report.json` — additive structured summary (suite coverage, fixture
  inventory, error-code coverage, maturity rollup, etc.). The legacy
  keys (`eppSuiteCoverage`, `etcRequirementCoverage`, …) are preserved
  for backwards compatibility.
- `dashboard.html` — self-contained human-readable view (no JS).
  Pair it with `report.html` (the pytest-html test-execution report)
  for full visibility.

CLI knobs: `--suite <name>` (repeatable), `--skip-fixtures`,
`--skip-errors`, `--dashboard-html <PATH>`, `--no-dashboard`.

## Combined Python sweep (`make test-all`)

`make test-all` runs `pytest internal-rst-checker/tests tests` in a single
invocation. The project-wide `import-mode = importlib` setting in
`pyproject.toml` ensures basename collisions (e.g. `test_dnssec_zone_health.py`
exists in both roots) no longer fire `import file mismatch` collection
errors. A regression test (`tests/test_combined_pytest_invocation.py`) keeps
the combined invocation green. See review finding Info-1.

## Merge Criteria

Changes are merge-ready only when:

- `make quality-gate` passes
- Reviewer marks `merge_ready: true`
- Human approval is provided
