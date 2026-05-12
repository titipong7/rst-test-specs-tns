# Build Notes — Dashboard multi-suite coverage

**Role**: Builder (`builder-implementation` SKILL)
**Branch**: `feat/dashboard-multi-suite-coverage`
**Plan**: [`plan.md`](./plan.md) (approved)
**Spec reference**: [`rst-test-specs v2026.04`](https://icann.github.io/rst-test-specs/v2026.04/rst-test-specs.html)

## Outcome

The internal dashboard (`src/rst_compliance/rst_dashboard.py`, run via
`internal-rst-checker/rst_dashboard.py`) now covers every default suite
(DNS, DNSSEC, DNSSEC-Ops, EPP, IDN, Integration, RDAP, RDE, SRSGW) and
emits four new additive sections in `report.json`:

| key                 | shape                                                  |
|---------------------|--------------------------------------------------------|
| `suiteCoverage`     | `{suite: {matrix:[…], summary:{covered, partial, missing}}}` |
| `fixtureInventory`  | `{suite: [{caseId, files, parses}]}`                   |
| `errorCodeCoverage` | `{suite: {exercised, unexercised, summary}}`           |
| `maturitySummary`   | `{suite: {GAMMA, BETA, ALPHA, UNKNOWN, total}}`        |

A self-contained `dashboard.html` is now produced alongside the existing
`report.html` (pytest-html, untouched). Legacy keys (`eppSuiteCoverage`,
`etcRequirementCoverage`, `schemaInventory`, …) remain in place exactly as
before — the entire change is additive.

## Commit map

The diff is grouped into the seven commits the contract asked for so the
reviewer can step through each behavioural slice independently:

| # | Commit                                              | Files                                                | LOC ±     |
|---|-----------------------------------------------------|------------------------------------------------------|-----------|
| 1 | `feat(dashboard): generalize case-id regex`         | dashboard module + 1 baseline test                   | +23 / −5  |
| 2 | `feat(dashboard): per-suite coverage summarizer`    | dashboard module (loaders, summarizers, maturity)    | +251 / −14 |
| 3 | `feat(dashboard): fixture inventory`                | dashboard module (`scan_fixture_inventory` + wrapper)| +162 / −2 |
| 4 | `feat(dashboard): error-code coverage`              | dashboard module (`compute_error_code_coverage`)     | +98 / 0   |
| 5 | `feat(dashboard): richer HTML report`               | dashboard module (`render_html_report` + CSS)        | +373 / −2 |
| 6 | `test(dashboard): cover new summarizers and HTML`   | `tests/test_rst_dashboard.py`                         | +563 / −7 |
| 7 | `build(make): add dashboard target`                 | Makefile, `docs/quality-gates.md`, `docs/dashboard-suites.md`, `plan.md` | +612 / −1 |

Each commit leaves the test suite green (`pytest -q tests/test_rst_dashboard.py`)
and the dashboard runnable (`make dashboard`); reviewers can bisect freely.

## Canonical contract surface

| Function                                                       | Where                                | Notes                                              |
|----------------------------------------------------------------|--------------------------------------|----------------------------------------------------|
| `CASE_ID_PATTERN`                                              | top of module                        | Single compiled regex covering every spec suite.   |
| `load_active_case_ids(suite, inc_root) -> tuple[str, ...]`     | per Builder spec                     | Reads `<inc_root>/<suite>/cases.yaml`.             |
| `load_error_codes(suite, inc_root) -> set[str]`                | per Builder spec                     | Reads `<inc_root>/<suite>/errors.yaml`.            |
| `summarize_suite_coverage(suite, *, spec_mapping, case_results, active_case_ids)` | per Builder spec | Generic coverage matrix.                           |
| `scan_fixture_inventory(fixtures_root, suite) -> list[dict]`   | per Builder spec                     | Per-suite inventory with parseability check.       |
| `compute_error_code_coverage(fixtures, error_codes) -> dict`   | per Builder spec                     | `{exercised, unexercised, summary}` envelope.      |
| `rollup_maturity(cases_yaml_path) -> dict`                     | per Builder spec                     | Numeric `{GAMMA, BETA, ALPHA, UNKNOWN, total}`.    |
| `render_html_report(summary) -> str`                           | per Builder spec                     | Self-contained dashboard HTML, no JS.              |

Legacy names preserved as thin aliases (deliberate — keeps external
callers and previous tests green): `summarize_epp_suite_coverage`,
`render_dashboard_html`, `render_placeholder_html`, `CASE_ID_PATTERNS`.

## Commands run during build

```bash
# Sanity loop per commit (and at the end):
PYTHONPATH=src pytest -q tests/test_rst_dashboard.py
PYTHONPATH=src python internal-rst-checker/rst_dashboard.py --dry-run

# Final, full sweep across both pytest roots and the make entry point:
PYTHONPATH=src pytest -q tests                                # 354 passed
PYTHONPATH=src pytest -q internal-rst-checker/tests           # 315 passed, 14 skipped
make dashboard                                                # → report.json 97 KB + dashboard.html 48 KB
grep -c '<script' internal-rst-checker/reports/dashboard.html # → 0
```

## Verification matrix vs. plan.md §3 acceptance criteria

| AC                                                                   | Result                                                              |
|----------------------------------------------------------------------|---------------------------------------------------------------------|
| All nine default suites surfaced in `report.json`                    | OK — `suiteCoverage`/`fixtureInventory`/`errorCodeCoverage`/`maturitySummary` keys all enumerate the nine suites in a smoke run. |
| Fixture inventory shows files + parses status per case               | OK — verified for `rdap-01` (success+failure+http), `rde-04` (capped list test), `rde-02` (PGP armor sniff). |
| Error-code coverage lists exercised + unexercised codes              | OK — RDAP shows `{exercised: 8, unexercised: 14, total: 22}` against real fixtures. |
| Dashboard HTML self-contained, no `<script>`                         | OK — `grep -c '<script'` → 0; only external URL is the ICANN spec link in the header. |
| Legacy `eppSuiteCoverage` key untouched                              | OK — present in dry-run output, EPP-22 historical override preserved. |
| `make dashboard` produces both `report.json` and `dashboard.html`    | OK — two artefacts written, sizes 97 KB / 48 KB.                    |
| `--suite`, `--skip-fixtures`, `--skip-errors`, `--no-dashboard` work | OK — covered by `test_dashboard_main_*` cases.                      |
| Backwards-compat unit tests pass                                     | OK — `test_summarize_epp_suite_coverage_wrapper_remains_backwards_compatible`, `test_case_id_pattern_alias_preserves_existing_epp_match`, `test_dashboard_main_preserves_legacy_keys_additive_only`. |

## Known limitations / deferred work

- **Perl-side `make quality-gate` not run locally.** The local environment
  is missing `Data::Mirror` / `ICANN::RST::Spec`, so the full Make target
  was exercised only through `quality-gate-python`. CI installs those
  prerequisites via `apt`. This matches the limitation called out in
  earlier Tester/Reviewer notes for PR #24 and is unrelated to this change.
- **Combined `pytest internal-rst-checker/tests tests`** still produces
  collection errors caused by duplicate test-module names across the two
  roots. CI runs the two roots separately, so this is a pre-existing
  repository condition, not a regression from this change.
- **Maturity column inside the suite coverage block** is left empty in
  the HTML view because `summarize_maturity_rollup` returns numeric counts
  only (matches the Builder contract). A future enhancement could plumb a
  per-case maturity lookup into `render_html_report`; intentionally not
  added here to keep the rollup payload numeric per the contract.

## Hand-off

Builder complete. Tester may run the acceptance commands listed in
[`plan.md` §3](./plan.md#3-acceptance-criteria-measurable) and record results
in `test.md`.
