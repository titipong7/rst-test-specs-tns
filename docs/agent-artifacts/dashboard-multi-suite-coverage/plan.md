# Plan — Multi-Suite Dashboard Coverage + Fixture / Error / Maturity Visibility

> Role: **Planner** (`.cursor/skills/planner-task-decomposition/SKILL.md`).
> Read-only phase — no code, no fixtures, no test edits in this round.
> Awaiting Human approval before Builder takes over.
>
> Spec reference: `ICANN RST v2026.04`
> (`https://icann.github.io/rst-test-specs/v2026.04/rst-test-specs.html`).
> Workflow contract: `docs/agent-roles.md`, `docs/agent-workflow.md`.
> Quality gates: `docs/quality-gates.md`.
> Severity gate: `.cursor/rules/review-severity-gate.mdc`.

---

## 0. Verified context (read, not guessed)

| Source                                                                      | Confirmed                                                                                                                                                                                                                                                                                                              |
| --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/rst_compliance/rst_dashboard.py:20`                                    | `CASE_ID_PATTERN = re.compile(r"\b(?:dns|rdap|epp|rde)-\d+\b", re.IGNORECASE)` — misses `dnssec`, `dnssec-ops`, `srsgw`, `idn`, `integration`, and the `dns-zz-*` IDs.                                                                                                                                                  |
| `src/rst_compliance/rst_dashboard.py:35`                                    | `EPP_CASE_IDS = tuple(f"epp-{n:02d}" for n in range(1, 28))` — only suite that has a hard-coded coverage matrix.                                                                                                                                                                                                       |
| `src/rst_compliance/rst_dashboard.py:186-268`                               | `summarize_epp_suite_coverage` exists; no per-suite generalisation; preserves the `epp-22 → partial` historical override.                                                                                                                                                                                              |
| `src/rst_compliance/rst_dashboard.py:330-359`                               | `caseResults` is sourced from `parse_junit_report(report_file=…)` only.                                                                                                                                                                                                                                                |
| `src/rst_compliance/rst_dashboard.py:388-406`                               | `render_placeholder_html` is a 18-line table-only fallback used **only** when `--dry-run` is set and `report.html` doesn't already exist (i.e. when pytest-html didn't run).                                                                                                                                          |
| `internal-rst-checker/reports/report.json`                                  | Existing top-level keys: `caseResults, discoveredTests, epp01Connectivity, eppSuiteCoverage, etcRequirementCoverage, fipsCheck, generatedAt, projectRoot, repoRoot, reportsRoot, rstSpecVersion, run, schemaInventory, schemasRoot, specMapping, testFileCount, testsRoot`. **No edits to existing keys are allowed.** |
| `inc/<suite>/cases.yaml` — top-level keys                                  | `dns(2), dnssec(3), dnssec-ops(3), epp(26), idn(2), integration(5), minimum-rpms(N≥1), rdap(12), rde(14), srsgw(14)`. Each case has `Maturity: {GAMMA|BETA|ALPHA}` and `Errors: [...]`.                                                                                                                            |
| `inc/<suite>/errors.yaml`                                                   | Exists for all 10 suite folders (including `minimum-rpms`). Each entry is `<ERROR_CODE>: {Severity, Description}` — flat top-level keys.                                                                                                                                                                             |
| `internal-rst-checker/fixtures/<suite>/` (flat layout)                      | `epp(21), dns(6), dnssec(7), dnssec-ops(8), rde(31), rdap(25), srsgw(42), idn(5), integration(20)` files. `<NN>-<slug>-{success,failure}.<ext>` naming convention enforced by per-suite guard tests.                                                                                                                  |
| `Makefile`                                                                  | Targets: `quality-gate`, `quality-gate-python`, `bootstrap-quality-gate`, `lint`, `includes`. **No `dashboard` target exists.**                                                                                                                                                                                       |
| `tests/test_rst_dashboard.py`                                               | 9 existing tests covering ensure-layout, discover-tests, map-spec-criteria, schema-summary, junit-parse, build-summary, etc-coverage, epp-coverage, dry-run main. **All must remain green (AC5).**                                                                                                                  |

In-scope suites for this work item: **`dns, dnssec, dnssec-ops, rdap,
rde, srsgw, idn, integration, epp`** (9 suites). `minimum-rpms` is
read-only acknowledged but **out of scope** for the F2–F5 matrices
because no `internal-rst-checker/fixtures/minimum-rpms/` directory
exists (consistent with the prior fixtures PR).

---

## 1. Scope & non-goals

### Scope

Extend `src/rst_compliance/rst_dashboard.py` (and surface it through the
existing entry point `internal-rst-checker/rst_dashboard.py`) so the
dashboard:

1. **Recognises every suite's `case_id`** — DNS (incl. `dns-zz-*`),
   DNSSEC, DNSSEC-Ops, RDAP, RDE, SRSGW, IDN, Integration, EPP.
2. **Produces a per-suite coverage matrix** keyed by the same
   `case_id`s, sourced from `inc/<suite>/cases.yaml`.
3. **Inventories the on-disk fixtures** under
   `internal-rst-checker/fixtures/<suite>/`, mapping each fixture to
   its `case_id` and reporting parseability.
4. **Surfaces error-code coverage** by cross-referencing the spec's
   `inc/<suite>/errors.yaml` with the error codes that appear in the
   `*-failure.*` fixtures committed by the previous PR.
5. **Surfaces a maturity rollup** (counts of `GAMMA/BETA/ALPHA` cases
   per suite) so reviewers can read maturity at a glance.
6. **Renders a richer self-contained HTML view** that exposes the
   spec version, generated-at, run status, every per-suite coverage
   table, the fixture inventory, the error-code coverage, and the
   familiar `caseResults` block.
7. **Adds CLI ergonomics**: `--suite <name>` (repeatable),
   `--skip-fixtures`, `--skip-errors`, plus a `make dashboard` alias.

### Non-goals

(as explicitly stated by the user; repeated here for the Builder contract)

- **Do not** modify spec sources (`rst-test-specs.html`,
  `rst-test-specs.json`, `inc/**/*.yaml`).
- **Do not** alter the existing `pytest-html` artefact
  (`internal-rst-checker/reports/report.html`). That file is the
  pytest-html test-execution report and remains owned by the
  `pytest --html` plugin. The richer dashboard view ships as a
  **new** file (see §3.6 / F6).
- **Do not** break the `report.json` schema. Net change is
  **additive only**: existing keys
  (`eppSuiteCoverage`, `etcRequirementCoverage`,
  `epp01Connectivity`, `caseResults`, `specMapping`, …) keep their
  current shape, with new keys added next to them.
- **Do not** introduce a web framework, JS bundler, or external CSS
  dependency. The new HTML is a single self-contained file (inline
  `<style>`, no `<script>`, no external network fetch).
- **Do not** require new third-party Python dependencies. Plain
  stdlib (`pathlib`, `re`, `json`, `xml.etree.ElementTree`, `csv`)
  must be sufficient. Existing transitive PyYAML access is
  acceptable but the loader should fall back to a minimal regex
  parser so the dashboard runs in minimal environments.

---

## 2. Feature breakdown (PR-sized tasks)

> Each Fn is small enough to land as a single commit on the same PR
> branch. Tasks are sequenced top-down — the later features build on
> earlier ones — but each is independently testable.

### F1 — Generalise `case_id` regex

**Why**: `CASE_ID_PATTERN` misses 6 of 9 suites today.

**Builder will**:

- Replace the single regex with a tuple `CASE_ID_PATTERNS` covering:
  ```python
  CASE_ID_PATTERNS = (
      re.compile(r"\bdns-zz-[a-z0-9-]+\b", re.IGNORECASE),
      re.compile(
          r"\b(?:dns|dnssec|rdap|rde|epp|srsgw|idn|integration)-\d+\b",
          re.IGNORECASE,
      ),
      re.compile(r"\bdnssecOps\d{2}-[A-Za-z]+\b"),
  )
  ```
- Keep the old `CASE_ID_PATTERN` symbol exported (aliased to the
  unified regex) for backwards compatibility (`# noqa: F401, kept for
  callers importing this constant`).
- Update `map_spec_criteria` to scan with every pattern and de-dupe
  matches. Output ordering stays sorted-lowercase as today.

**Unit tests (F1.t)**:

- One parametrised test sourced from each in-scope suite's
  `cases.yaml` first key:
  `dns-zz-idna2008-compliance`, `dnssec-91`, `dnssecOps01-ZSKRollover`,
  `rdap-01`, `rde-01`, `srsgw-01`, `idn-01`, `integration-01`,
  `epp-14`. Each must round-trip through `map_spec_criteria` on a
  synthetic test file whose docstring carries the case_id.

---

### F2 — Per-suite coverage summariser (DRY)

**Why**: Today only EPP has a coverage matrix; the other 8 suites
have no machine-readable view of "which case is covered".

**Builder will**:

- Add `load_active_case_ids(suite: str, *, repo_root: Path) ->
  list[str]` that reads `inc/<suite>/cases.yaml` and returns the
  ordered case_id list. Implementation uses a minimal line-by-line
  regex (`^([A-Za-z0-9_-]+):\s*$`) — same approach as the per-suite
  guard tests — so PyYAML stays a transitive optional dependency,
  not a runtime requirement.
- Add `summarize_suite_coverage(suite: str, *, case_ids, spec_mapping,
  case_results) -> dict` that returns
  `{"matrix": [{"caseId","status","reason","tests"}], "summary":
  {"covered":n,"partial":n,"missing":n}}`. Same status semantics as
  the existing EPP variant: `covered` = ≥1 mapped test passed and
  none failed; `partial` = mapped test exists but didn't pass /
  results absent; `missing` = no mapped test.
- Refactor `summarize_epp_suite_coverage` into a thin wrapper around
  `summarize_suite_coverage(suite="epp", case_ids=EPP_CASE_IDS, …)`
  that preserves the `epp-22 → partial (removed from v2026.04)`
  historical override.
- Add `summarize_all_suite_coverage(*, repo_root, spec_mapping,
  case_results) -> dict[str, dict]` that walks every in-scope suite
  and returns `{suite: {matrix, summary}}`.
- Inject a new field `suiteCoverage` into `build_summary`. Keep
  `eppSuiteCoverage` as an **alias** of `suiteCoverage["epp"]`
  (backwards compatibility — AC5).

**Unit tests (F2.t)**:

- `test_load_active_case_ids_reads_inc_yaml_keys` — tmp_path
  synthetic `inc/foo/cases.yaml` with three top-level keys, assert
  loader returns them in declaration order.
- `test_summarize_suite_coverage_handles_arbitrary_suite` —
  pass-through smoke (covered/partial/missing) for a non-EPP suite.
- `test_summarize_all_suite_coverage_includes_every_in_scope_suite` —
  uses the real repo root in `tmp_path` (or `monkeypatch.setattr`
  on the suite list); assert keys
  `{dns, dnssec, dnssec-ops, rdap, rde, srsgw, idn, integration, epp}`
  all present.
- Existing `test_summarize_epp_suite_coverage_reports_*` stays green
  (regression lock on the wrapper).

---

### F3 — Fixture inventory

**Why**: The previous PR added fixtures for every non-EPP suite but
nothing surfaces them in the dashboard.

**Builder will**:

- Add `summarize_fixture_inventory(*, fixtures_root: Path) ->
  dict[str, list[dict]]` returning, per suite folder, a list:
  ```python
  [
      {
          "caseId": "rdap-01",
          "files": ["01-domain-query-success.json", "01-domain-query-failure.json"],
          "parses": {"01-domain-query-success.json": True, "01-domain-query-failure.json": True},
      },
      ...
  ]
  ```
- Parseability matrix:
  - `.xml` → `xml.etree.ElementTree.fromstring(...)` (raises → `False`).
  - `.json` → `json.loads(...)` (raises → `False`).
  - `.csv` → `csv.reader(...)` exhaustion (raises → `False`).
  - `.asc`, `.gpg` → `len(bytes) > 0 and b"-----BEGIN PGP" in body`.
  - `.txt`, `.example`, `.ryde.example`, `.env.example` → only checked
    for non-zero length (parseability marked `True` if size > 0).
- Mapping `<NN>-…` → `caseId` reuses the per-suite `CASE_PREFIX`
  lookup baked into the guard tests; this is consolidated into a
  single dashboard-side constant `SUITE_CASE_PREFIX` (one dict per
  suite) so the dashboard does not reach into the test modules.
- Inject a new field `fixtureInventory` into `build_summary`.
  Suites with no fixtures directory are omitted from the dict (not
  represented as an empty list).

**Unit tests (F3.t)**:

- `test_summarize_fixture_inventory_lists_success_and_failure_paths`
  — tmp_path fixture set with `01-x-success.xml`, `01-x-failure.xml`,
  `02-y-success.json`; assert each `caseId` entry has the expected
  files and `parses == True`.
- `test_summarize_fixture_inventory_marks_malformed_payloads` —
  tmp_path with a `01-bad-success.json` containing `not json`;
  assert `parses["01-bad-success.json"] is False`.
- `test_summarize_fixture_inventory_handles_pgp_armored_files` —
  one `.asc` with `-----BEGIN PGP` header, one without; assert
  parseability mirror.

---

### F4 — Error-code coverage

**Why**: The Reviewer of the previous PR (PR #24) flagged that 45 of
53 failure fixtures never name the spec `Errors[]` code they exercise.
This feature gives that visibility a machine-readable home.

**Builder will**:

- Add `load_error_codes(suite: str, *, repo_root: Path) ->
  list[str]` reading `inc/<suite>/errors.yaml` top-level keys via the
  same minimal regex loader as F2.
- Add `summarize_error_code_coverage(*, suite, error_codes,
  fixture_inventory) -> dict` that scans every failure fixture's
  bytes for substring matches against the known error codes and
  returns:
  ```python
  {
      "exercised":   ["RDE_INVALID_FILENAME", ...],
      "unexercised": ["RDE_XML_PARSE_ERROR", ...],
      "summary":     {"exercised": n, "unexercised": m, "total": n+m},
  }
  ```
- Inject `errorCodeCoverage = {suite: {exercised, unexercised,
  summary}}` into `build_summary`.

**Unit tests (F4.t)**:

- `test_summarize_error_code_coverage_finds_codes_in_failure_fixtures`
  — tmp_path with `errors.yaml: {FOO_ERROR_A, FOO_ERROR_B}` and a
  failure fixture containing `"FOO_ERROR_A"`; assert exercised ==
  `[FOO_ERROR_A]`, unexercised == `[FOO_ERROR_B]`.
- `test_summarize_error_code_coverage_handles_empty_failure_set` —
  no failure fixtures → exercised empty, unexercised == all codes.

---

### F5 — Maturity rollup

**Why**: Maturity per case (`GAMMA/BETA/ALPHA`) is in the spec but
invisible today.

**Builder will**:

- Extend `load_active_case_ids` (or a sibling `load_case_maturity`)
  to return both the case_id and its `Maturity` field. Implementation
  scans the same `inc/<suite>/cases.yaml`, looking for the first
  `Maturity:\s+(\w+)` line after each top-level key.
- Add `summarize_maturity_rollup(*, suite, case_maturity) -> dict`
  returning `{"GAMMA": n, "BETA": n, "ALPHA": n, "UNKNOWN": n,
  "total": n}`.
- Inject `maturitySummary = {suite: {<level>: n, ...}}` into
  `build_summary`.

**Unit tests (F5.t)**:

- `test_summarize_maturity_rollup_counts_by_level` — tmp_path
  `inc/foo/cases.yaml` with 2 GAMMA + 1 BETA cases; assert rollup
  matches.
- `test_summarize_maturity_rollup_marks_unknown_when_field_missing`
  — case without `Maturity:` line → counted as `UNKNOWN`.

---

### F6 — Richer HTML report

**Why**: The dry-run placeholder is currently 18 lines of barely-styled
HTML; the user wants a readable single-file dashboard.

**Builder will**:

- Rename `render_placeholder_html` → `render_dashboard_html` and
  rewrite it to emit a self-contained HTML5 document with:
  1. **Header card** — RST spec version, generated-at timestamp,
     run status (`run.status`, `caseResults` totals).
  2. **Per-suite coverage matrix** — one collapsible
     `<details><summary>` block per suite, with a table:
     `case_id | maturity | status | mapped tests | reason`.
  3. **Fixture inventory table** — one row per `(suite, caseId)`
     listing files + parse-OK indicator.
  4. **Error-code coverage table** — exercised vs unexercised by
     suite (badge counts).
  5. **Maturity rollup card** — small bar chart rendered with
     `<div>` blocks and inline `style="width:Npx;…"` (no JS, no SVG
     download).
  6. **Case results table** — preserves the existing
     `Test Case | Status | Reason` matrix.
  7. **Footer** — links to `report.json`, `report.html` (pytest-html),
     `report-junit.xml`.
- Inline CSS only — one `<style>` block at the top. Use CSS
  variables for the status palette (`green #2ea44f`, `amber #bf8700`,
  `red #cf222e`). Per-fixture file lists are capped at 4 entries
  with `+N more` to keep file size bounded (R5).
- File destination: **`internal-rst-checker/reports/dashboard.html`**
  (a new path — see R2). The richer renderer is always invoked,
  regardless of `--dry-run`. The existing `report.html` remains
  pytest-html's territory and is **not** overwritten.
- Keep a tiny `render_legacy_placeholder_html` (≤ 15 lines) for the
  `--dry-run + report.html doesn't already exist` corner case
  guarded today by `if args.dry_run and not html_report.exists():`
  — preserves the no-regression promise.

**Unit tests (F6.t)**:

- `test_render_dashboard_html_includes_every_section` — feed a
  synthetic summary with 2 suites + 1 fixture + 1 error code +
  1 case result; assert the rendered string contains the header card,
  each suite's `<details>` block, the fixture inventory table, the
  error-code table, the maturity rollup, and the case-results table.
- `test_render_dashboard_html_is_self_contained_no_js` — rendered
  string has zero `<script>` tags and zero external `http://` /
  `https://` references except the single spec link in the header.
- `test_render_dashboard_html_caps_fixture_lists_at_four_entries` —
  feed `caseId` with 6 fixture files; assert the HTML shows the
  first 4 and a `+2 more` suffix.

---

### F7 — CLI + Makefile

**Why**: Operators need to focus the dashboard on a subset of suites
in CI smoke runs.

**Builder will**:

- Add CLI flags to `build_arg_parser`:
  - `--suite NAME` (repeatable, `action="append"`) — filter
    `suiteCoverage` / `fixtureInventory` / `errorCodeCoverage` /
    `maturitySummary` to the named suites. Default: all in-scope.
  - `--skip-fixtures` — set the fixture-inventory output to an empty
    dict and skip the on-disk walk. Useful for minimal CI containers
    that don't check out fixtures.
  - `--skip-errors` — set the error-code coverage to an empty dict
    and skip `errors.yaml` parsing.
  - `--dashboard-html PATH` — override the dashboard HTML output
    path (default `<reports>/dashboard.html`).
  - `--no-dashboard` — skip rendering the dashboard HTML entirely.
- Add a `dashboard` target to the root `Makefile`:
  ```makefile
  dashboard:
  	@echo "Generating internal RST dashboard..."
  	@PYTHONPATH=src python3 internal-rst-checker/rst_dashboard.py --dry-run
  ```
  Wired as a `.PHONY` target; documented in
  `docs/quality-gates.md` under "Dashboard".

**Unit tests (F7.t)**:

- `test_dashboard_cli_filters_to_named_suites` — invoke `main` with
  `--suite rdap --suite rde --dry-run`; assert
  `summary["suiteCoverage"]` keys == `{rdap, rde}` and the unrelated
  suites are absent.
- `test_dashboard_cli_respects_skip_fixtures_flag` — invoke `main`
  with `--skip-fixtures --dry-run`; assert
  `summary["fixtureInventory"] == {}`.
- `test_dashboard_cli_respects_skip_errors_flag` — analogous to
  the fixtures variant.
- `test_dashboard_cli_no_dashboard_skips_html_write` — invoke `main`
  with `--no-dashboard --dry-run`; assert
  `<reports>/dashboard.html` does **not** exist after the run while
  `<reports>/report.json` does.

---

## 3. Acceptance criteria (measurable)

| AC   | Statement                                                                                                                            | Validation                                                                                                                                                                  |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| AC1  | `summary["suiteCoverage"]` carries keys `{dns, dnssec, dnssec-ops, rdap, rde, srsgw, idn, integration, epp}`                          | `python -c "import json; d=json.load(open('internal-rst-checker/reports/report.json')); print(sorted(d['suiteCoverage']))"`                                                 |
| AC2  | For each suite, every `case_id` in `inc/<suite>/cases.yaml` appears in `suiteCoverage[suite].matrix[*].caseId`                       | Per-suite count assertion in F2.t test + `Tester` re-run on the real `cases.yaml`                                                                                           |
| AC3  | `summary["fixtureInventory"][<suite>]` lists every fixture under `internal-rst-checker/fixtures/<suite>/**` and reports `parses=True` for valid payloads | F3.t tests + Tester `find … -type f | wc -l` cross-check                                                                                                                    |
| AC4  | `summary["errorCodeCoverage"][<suite>].exercised + .unexercised == load(errors.yaml).keys()`                                          | F4.t test + Tester one-liner comparing the union to the YAML keys                                                                                                           |
| AC5  | `summary["maturitySummary"][<suite>]` totals match the count of cases in `inc/<suite>/cases.yaml`                                    | F5.t test + Tester `python -c "…sum…"` cross-check                                                                                                                          |
| AC6  | `dashboard.html` shows the 6 sections from §2 F6.1–F6.6, has zero `<script>` tags, and is < 1 MB                                      | F6.t tests + Tester `wc -c <reports>/dashboard.html` + `grep -c '<script' <reports>/dashboard.html`                                                                          |
| AC7  | **No field from the original `report.json` schema is removed.** Existing keys keep their previous shape.                            | F2.t alias test + Tester `python -c "…assert set(prev_keys).issubset(new_keys)"`                                                                                            |
| AC8  | `pytest -q tests` and `pytest -q internal-rst-checker/tests` are green                                                               | Tester runs both verbatim                                                                                                                                                  |
| AC9  | `make quality-gate-python` is green; `make quality-gate` either passes locally **or** the pre-existing Perl-bootstrap failure is unchanged | Tester runs both, separates new vs. pre-existing failure                                                                                                                    |
| AC10 | `make dashboard` exists, runs `--dry-run`, and produces `report.json` + `dashboard.html`                                              | Tester runs `make dashboard` and `ls` on the output                                                                                                                         |
| AC11 | `git diff main…HEAD -- inc rst-test-specs.html rst-test-specs.json .github` is empty (no protected paths touched)                    | Reviewer phase                                                                                                                                                              |
| AC12 | Reviewer severity gate records `merge_ready: true` with `blocker=0` and `high=0`                                                     | Reviewer phase                                                                                                                                                              |

---

## 4. Files likely to change

| Path                                                                                | Type     | Approx LOC / change                                          |
| ----------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------ |
| `src/rst_compliance/rst_dashboard.py`                                               | edit     | +320 / −30                                                   |
| `tests/test_rst_dashboard.py`                                                       | edit     | +200 (≈ 16 new test functions, F1.t … F7.t)                 |
| `Makefile`                                                                          | edit     | +5 (`dashboard` target, `.PHONY` entry)                      |
| `docs/quality-gates.md`                                                             | edit     | +6 (one "Dashboard" paragraph)                               |
| `docs/dashboard-suites.md`                                                          | new      | ~60 lines (suite list + how to read the new HTML)            |
| `docs/agent-artifacts/dashboard-multi-suite-coverage/build.md`                      | new      | Builder runbook                                              |
| `docs/agent-artifacts/dashboard-multi-suite-coverage/test.md`                       | new      | Tester report                                                |
| `docs/agent-artifacts/dashboard-multi-suite-coverage/review.md`                     | new      | Reviewer report                                              |
| `internal-rst-checker/rst_dashboard.py`                                             | **unchanged** | n/a — entry-point shim continues to import from `rst_compliance.rst_dashboard` |
| `internal-rst-checker/reports/dashboard.html`                                       | regenerated at runtime | n/a — built artefact, expected to be `.gitignore`d alongside `report.html` |

**Total estimated diff**: ~540 lines added across 4 source/doc files
(plus the 3 agent-artifact markdown deliverables produced by Builder,
Tester, Reviewer).

---

## 5. Risks & assumptions

### Risks

- **R1 (medium): `CASE_ID_PATTERN` is a module-level public constant.**
  External scripts importing it would see different match behaviour.
  *Mitigation*: keep the old name aliased to the unified regex; add a
  regression test that locks in the EPP matches; document the change
  in `build.md`. (Pattern callers in this repo: none outside the
  module itself — verified via `Grep`.)
- **R2 (medium): pytest-html `report.html` vs. new `dashboard.html`
  confusion.** Operators may not realise there are two HTML files
  with different roles. *Mitigation*: F6.6 footer cross-links the
  two files; `docs/quality-gates.md` "Dashboard" paragraph names
  both; `dashboard.html` header explicitly says "internal coverage
  dashboard — for test-execution results see `report.html`".
- **R3 (medium): `cases.yaml` and `errors.yaml` parsing without
  PyYAML.** A nested-key edge case could trip the minimal regex
  parser. *Mitigation*: Builder will attempt a `try: import yaml`
  fast path with the regex parser as fallback, and document in
  `build.md`. Verified against all 10 suites in §0 — flat top-level
  keys only.
- **R4 (low): Outlier case_id formats** (`dns-zz-*`,
  `dnssecOpsNN-Name`). *Mitigation*: F1 covers both with explicit
  regex variants; F3's `SUITE_CASE_PREFIX` carries the inverse
  lookup. Verified by per-suite guard tests in
  `internal-rst-checker/tests/<suite>/test_<suite>_fixtures_present.py`.
- **R5 (low): `dashboard.html` size.** A naïve renderer that inlines
  every fixture path could blow past 1 MB. *Mitigation*: cap each
  per-case file list at 4 entries with a `+N more` suffix in F6;
  Tester verifies size via `wc -c`.
- **R6 (low): `make dashboard` invokes `python3` directly.** On
  hosts without a `python3` on PATH this fails. *Mitigation*: the
  Makefile target uses `$(PYTHON)` with a `PYTHON ?= python3`
  default so contributors can override.

### Assumptions

- **A1**: The user accepts a **new** file at
  `internal-rst-checker/reports/dashboard.html` rather than
  co-mingling the dashboard into the pytest-html `report.html`. This
  is required because pytest-html owns the contents of its target
  file (Non-goal #2 above).
- **A2**: The `inc/<suite>/cases.yaml` and `inc/<suite>/errors.yaml`
  files keep their current flat top-level-keys shape across the spec
  version in scope (`v2026.04`). Verified §0.
- **A3**: The dashboard runs against a checked-out repo (fixtures on
  disk, `inc/` on disk). No live network access required.
- **A4**: "อ่านง่ายขึ้น" = CSS-only readability (typography, status
  badges, `<details>` accordions). No JS-driven filtering / sorting
  — those would require a script tag, violating Non-goal #4.
- **A5**: `internal-rst-checker/reports/dashboard.html` is a build
  artefact, regenerated by every dashboard run. Builder will add an
  entry to `.gitignore` if not already covered by the existing
  `reports/*` glob.
- **A6**: `minimum-rpms` (the 10th suite in `inc/`) is intentionally
  excluded from the dashboard matrices because no fixtures were
  ever planned for it. If the user wants it included, add to the
  suite list with a one-liner change.

---

## 6. Out of plan / explicit defer list

- Interactive HTML filters / sortable columns — would require JS.
- Per-fixture **schema** validation against the RDE / RDAP /
  Zonemaster schemas. The guard tests already exercise
  well-formedness; the dashboard reports parseability only.
- A "this `case_id` is mentioned in another suite's docstring"
  cross-suite dedupe pass — `criteriaIds` keeps every match today.
- Live spec re-fetch from `icann.github.io` — dashboard reads
  the on-disk `inc/` tree exclusively.
- Fixing the three duplicate test module names that block
  combined-pytest runs (`tests/test_dnssec_zone_health.py`,
  `tests/test_epp_host_constraints.py`,
  `tests/test_rdap_conformance.py`) — pre-existing repo hygiene
  item already tracked in the prior PR's `review.md`.
- Promoting the "Expected `Errors[]`" header line into every
  failure fixture — Reviewer follow-up from PR #24. The
  errorCodeCoverage feature in F4 makes the absence visible
  (the unexercised list), which is enough for now.

---

## 7. Handoff request to Human

Please confirm before Builder takes over:

- [ ] §1 scope & 9 in-scope suites (excluding `minimum-rpms`) are
      correct.
- [ ] Non-goal interpretation is correct: keep `report.html` as the
      pytest-html artefact; ship the new view as
      `internal-rst-checker/reports/dashboard.html` (and use it as
      the F6 destination). Alternative names if you prefer:
      `coverage.html`, `internal-dashboard.html`,
      `multi-suite-dashboard.html`.
- [ ] F1–F7 task split is acceptable. The biggest single commit
      will be F6 (HTML renderer + CSS, ≈ 180 LOC); each other Fn is
      ≤ 80 LOC.
- [ ] Estimated diff (~540 lines across 4 files) is within tolerance
      for a single PR.
- [ ] CLI surface in F7 is acceptable
      (`--suite/--skip-fixtures/--skip-errors/--dashboard-html/--no-dashboard`)
      and the `make dashboard` target is the right name (alternative:
      `make report`, `make internal-dashboard`).
- [ ] R1 risk handling (keep the old `CASE_ID_PATTERN` constant
      aliased) is acceptable.

Once approved, Builder may proceed using
`docs/agent-artifacts/dashboard-multi-suite-coverage/build.md` to log
the runbook (file paths added, commands executed, deferred items).

`merge_ready: false` (Plan stage only — awaiting human approval).
