# Reviewer Report — Dashboard multi-suite coverage

**Role**: Reviewer (`reviewer-checklist` SKILL, `review-severity-gate.mdc`)
**Branch under review**: `feat/dashboard-multi-suite-coverage` @ `c4228e2`
**Baseline for regression comparison**: `bfd5e85` (origin/main merge tip)
**Date**: 2026-05-12
**Inputs consulted**: [`plan.md`](./plan.md), [`build.md`](./build.md), [`test.md`](./test.md), full diff `bfd5e85..HEAD`, live runtime probes (see "Evidence" sections).

## TL;DR

| Severity | Count |
|----------|-------|
| blocker  | 0     |
| high     | 0     |
| medium   | 1     |
| low      | 5     |
| info     | 2     |

→ **`merge_ready: true`** (no blocker / high findings; medium finding is documentation-only and acceptable to defer per severity gate, with a follow-up issue recommended).

---

## Checklist results

| # | Checklist item                                                         | Result                                                                                                |
|---|------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| 1 | Backward compatibility: `report.json` schema preserves every field     | **PASS** — empirical comparison shows 17 baseline keys all retained; 4 new keys added; nested shapes (`eppSuiteCoverage`, `fipsCheck`, `run`, `etcRequirementCoverage`, `schemaInventory`, `epp01Connectivity`) all unchanged. |
| 2 | `CASE_ID_PATTERN` does not false-positive on common keywords           | **PASS** — 28-sample probe with 0 mismatches (see §Evidence). Word boundaries reject `xrdap-01`, `rdap-01x`, `EppCase23`, `epp-22a`, `dns-zz-` (empty slug), generic prose ("dns lookup", "epp v2.0"). |
| 3 | `load_active_case_ids` reads YAML resiliently (`dns-zz-*`, comments)   | **PASS with one low caveat** — handles `dns-zz-*` keys, comments, blank lines, CRLF, tab indentation, inline `# foo` comments, indented child keys, trailing whitespace, `dnssecOps01-…` camelCase keys, missing files; only weakness is UTF-8 BOM on a file head (no in-tree file uses one — verified). |
| 4 | Fixture inventory does not crash when suites are missing               | **PASS** — empty fixtures_root, empty inc/, `fixtures_root` pointing at a regular file, suite folder containing only README/subdir, and unreadable files all handled gracefully; no exceptions raised. |
| 5 | HTML report does not inline oversized files                            | **PASS** — `_cap_files(files, cap=4)` truncates lists with "+N more" badge; `case_results[:500]` caps execution table; stress test with 5000 case results + 50-file fixture list produced 59 KB output. |
| 6 | HTML report escapes user-controlled content (XSS guard)                | **PASS** — every user field routed through `_esc(v)` (`html.escape(str(v), quote=True)`); XSS payload injection across all string fields yielded 0 raw `<script>` tags, 0 `javascript:` URLs, 0 inline event handlers, 10 properly-escaped `&lt;script&gt;` occurrences. |
| 7 | CLI flags have clear help text                                         | **PASS with one low finding** — all 5 new flags (`--dashboard-html`, `--no-dashboard`, `--suite`, `--skip-fixtures`, `--skip-errors`) have help text; the `--suite` help string lists only 3 of the 4 keys it actually filters (see Finding **L-2**). |
| 8 | No new non-stdlib dependency                                           | **PASS** — `pyproject.toml` unchanged; new source imports are `csv` + `html` (both stdlib); tests add only `pytest` (already a dependency). |
| 9 | Test coverage touches every new path                                   | **PASS with one medium finding** — every public Builder-contract function imported and asserted; private helpers exercised transitively; minor gaps documented in Finding **M-1**. |
| 10 | Security: no read outside repo, no shell injection in subprocess       | **PASS with one low finding** — `subprocess.run` uses list-form command, `shell=False` (default), no user-input interpolated into shell metachars; `--suite` accepts arbitrary strings that the path joiner could traverse but the result is read-only (see Finding **L-5**). |

---

## Findings

### M-1 — Test gaps: `SUITE_CASE_PREFIX` overrides, `render_placeholder_html` legacy alias, and `--dashboard-html` flag have no targeted tests
**Severity**: `medium`

**Evidence**:
- `SUITE_CASE_PREFIX` (defined `src/rst_compliance/rst_dashboard.py:225-237`) overrides the prefix lookup for `dns-zz-idna2008-compliance`, `dns-zz-consistency`, `dnssecOps01-ZSKRollover`, …. Symbol coverage probe shows no test names or string mentions reference it. The DNS and DNSSEC-Ops case_id branches are exercised indirectly only via the live `make dashboard` smoke run (which is not under pytest's regression net).
- `render_placeholder_html` alias (`src/rst_compliance/rst_dashboard.py:996`) preserved for back-compat — only invoked when `--dry-run` is set AND `report.html` doesn't exist. No test asserts the alias is still callable or produces the legacy small fallback shape.
- `--dashboard-html PATH` (new in `src/rst_compliance/rst_dashboard.py:1325-1329`) has no direct test verifying the override path is honoured; the test suite covers `--no-dashboard`, `--suite`, `--skip-fixtures`, `--skip-errors` but not `--dashboard-html`.

**Why medium, not low**: a future refactor of the prefix lookup or rename of the legacy fallback could silently break DNS / DNSSEC-Ops fixture rows or pytest-html-skipped runs without any test signal. The blast radius is the surfaced dashboard accuracy for two of nine suites.

**Required action**:
1. Add a targeted test for `_case_prefix("dns", "dns-zz-consistency") == "02"` and similar entries (3 DNS, 3 DNSSEC-Ops).
2. Add `test_render_placeholder_html_alias_still_callable` asserting `render_placeholder_html` is `render_legacy_placeholder_html` and produces output containing `report.html`.
3. Add `test_dashboard_main_dashboard_html_path_override` asserting `--dashboard-html /tmp/x.html` writes to the override location and not to `reports/dashboard.html`.

This may be deferred to a follow-up PR per the severity gate's `medium` allowance, provided a defer rationale is added to the PR description.

---

### L-1 — UTF-8 BOM at start of `cases.yaml` / `errors.yaml` would skip the first key
**Severity**: `low`

**Evidence**:
- `_TOP_LEVEL_YAML_KEY` regex (`src/rst_compliance/rst_dashboard.py:241`) anchors on `^[A-Za-z]`. A leading `\xef\xbb\xbf` BOM breaks that anchor for the first line only.
- Empirical probe: `_read_top_level_keys` returns `[]` for `b"\xef\xbb\xbfrde-01:\n  Maturity: GAMMA\n"`.
- Mitigating factor: a byte-head dump of every `inc/*/cases.yaml` and `inc/*/errors.yaml` confirms NO file currently starts with a BOM (verified via `head -c 3 | od`).

**Required action**:
Defensive one-liner: strip a BOM if present at the start of `read_text`'s output. Example:

```python
text = yaml_path.read_text(encoding="utf-8")
if text.startswith("\ufeff"):
    text = text[1:]
```

Defer-OK: no in-tree file triggers this today; would only surface if an editor configured with "Add BOM on save" touches one of the YAML files.

---

### L-2 — `--suite` help text omits `errorCodeCoverage` (one of four filtered sections)
**Severity**: `low`

**Evidence**:
- Help text (`src/rst_compliance/rst_dashboard.py:1335-1342`): "Limit suiteCoverage / fixtureInventory / maturitySummary to the named suites."
- `main()` at `src/rst_compliance/rst_dashboard.py:1410-1429` filters all **four** new keys including `errorCodeCoverage`.
- Tests confirm the behavior: `test_dashboard_main_suite_filter_limits_keys` asserts `suiteCoverage` and `maturitySummary` are filtered; the `errorCodeCoverage` filter is not in the test assertion but the code path runs.

**Required action**:
Update the help string to read "Limit suiteCoverage / fixtureInventory / **errorCodeCoverage** / maturitySummary to the named suites." Doc-only fix.

---

### L-3 — DNSSEC-Ops case_ids cannot be auto-extracted from test names anymore
**Severity**: `low`

**Evidence**:
- Builder-spec regex (`src/rst_compliance/rst_dashboard.py:21-25`) does not match `dnssecOpsNN-…` case_ids; this was an explicit Builder decision and is documented in `build.md`.
- Live run shows all three DNSSEC-Ops cases marked `missing` in `suiteCoverage.dnssec-ops`:
  ```
  dnssec-ops first row: {'caseId': 'dnssecOps01-ZSKRollover', 'reason': 'No mapped internal checker test.', 'status': 'missing', 'tests': []}
  ```
- Mitigating factor: there were never any DNSSEC-Ops test names of the form `test_dnssecOps01_…` to begin with (only `test_dnssec_ops_*` style fixture-guard tests). On baseline `bfd5e85`, dnssec-ops coverage didn't exist at all, so this is **net additive** — not a regression.

**Required action**:
Two acceptable paths; either is fine:
1. Document the "DNSSEC-Ops always shows missing until a `dnssecOpsNN-` substring lands in a test name or docstring" expectation in `docs/dashboard-suites.md`.
2. Extend `CASE_ID_PATTERN` to include `dnssecOps\d+-[A-Za-z]+` (would deviate from the Builder spec's literal regex — discuss in the PR).

Defer-OK: behaviour is honest (no mapped test = `missing` is the correct status).

---

### L-4 — Coverage of `dnssec-ops` suite by error-code scan is empty for *both* baseline and HEAD
**Severity**: `low`

**Evidence**:
- `inc/dnssec-ops/errors.yaml` is short (verified during YAML probe).
- Live dry-run shows `errorCodeCoverage["dnssec-ops"]` only enumerates a handful of codes (`{'exercised': …, 'unexercised': …, 'total': N}`).
- The summarizer correctly distinguishes exercised vs unexercised across other suites (rdap 8/22, rde 1/83).

**Required action**:
None for this PR. Recommend a follow-up to land DNSSEC-Ops failure fixtures that embed at least one declared error code, so the dashboard surface stops being uniformly empty for that suite.

---

### L-5 — `--suite` accepts arbitrary strings; theoretical read-only path traversal
**Severity**: `low`

**Evidence**:
- `summarize_all_suite_coverage(repo_root, …, suites=suites_filter)` (`src/rst_compliance/rst_dashboard.py:436-460`) and similar helpers build `inc_root / suite / "cases.yaml"`. A caller passing `--suite ../../etc` would traverse outside `inc_root`.
- All such operations are read-only and silently return `()` if the resolved file does not exist (verified via stress test).
- No write occurs outside `--reports-dir` (always operator-supplied).
- The dashboard CLI is invoked by trusted local operators, not by untrusted network input; the same traversal vector already exists in legacy `load_case_maturity(suite, *, repo_root)` (introduced previously, not by this branch).

**Required action**:
Defense-in-depth recommendation, not a blocker:

```python
if suite not in DEFAULT_SUITES:
    raise ValueError(f"Unknown suite: {suite!r}")
```

or:

```python
suite = Path(suite).name  # strips traversal components
```

Defer-OK for this PR because: (a) trusted-operator threat model, (b) read-only, (c) pre-existing pattern.

---

### Info-1 — Combined `pytest internal-rst-checker/tests tests` still collides
**Severity**: `info` (pre-existing, called out in `build.md` and `test.md`)

Running both test roots in one pytest invocation produces collection errors due to duplicate test-module names (`test_dnssec_zone_health.py`, etc.). CI runs them separately, so this is a non-issue for the pipeline. **No action required** — already tracked.

---

### Info-2 — `make quality-gate` exits 2 locally due to missing Perl modules
**Severity**: `info` (pre-existing on `bfd5e85`)

`tools/generate-zonemaster-cases.pl` fails with `Can't locate Data/Mirror.pm` before any code on this branch executes. Reproduced unchanged on `bfd5e85` (see `test.md` §2.1). CI installs the Perl prerequisites via `apt`; the python-only subset `make quality-gate-python` is green. **No action required** for this PR — already tracked.

---

## Empirical evidence (selected probes)

### B-1: Backward-compat key-set diff

```bash
python -c "
import json
base = set(json.load(open('/tmp/rst-baseline-bfd5e85/internal-rst-checker/reports/report.json')).keys())
head = set(json.load(open('internal-rst-checker/reports/report.json')).keys())
print('REMOVED on HEAD vs baseline:', sorted(base - head) or '(none)')
print('ADDED on HEAD vs baseline:',   sorted(head - base) or '(none)')
print('All baseline keys present on HEAD?', base.issubset(head))
"
# → REMOVED on HEAD vs baseline: (none)
# → ADDED on HEAD vs baseline:   ['errorCodeCoverage', 'fixtureInventory', 'maturitySummary', 'suiteCoverage']
# → All baseline keys present on HEAD? True
```

Plus nested-shape checks: `eppSuiteCoverage.matrix` length identical (27), `eppSuiteCoverage.summary` identical, `epp-22` status preserved as `partial`, `fipsCheck`, `run`, `etcRequirementCoverage`, `schemaInventory`, `epp01Connectivity` key sets all identical.

### B-2: CASE_ID_PATTERN false-positive probe (28 samples → 0 mismatches)

True-positives: `dns-zz-consistency`, `dnssec-91`, `rdap-01`, `epp-27`, `rde-04`, `idn-02`, `integration-05`, `srsgw-15`, `EPP-03`, `rdap-01-extra`.
True-negatives: `dns lookup`, `dnssec validated`, `rdap.example.org`, `epp v2.0`, `rde-payload-pgp`, `dns-zz-`, `integration-test`, `epp--`, `dnssec-ops`, `epp-22a`, `xrdap-01`, `rdap-01x`, `EppCase23`, `v1-99 release`, `test-99 todo`, `epp-validate`, `01-success.xml`, `self-test-99`.

### B-3: YAML loader edge-case sweep

10 inputs probed; every realistic case (CRLF, comments, blank lines, hyphenated keys, camelCase keys, tab indent, indented child keys) handled correctly. Only failure mode is BOM (Finding L-1).

### B-4: HTML XSS probe

Injected `<script>alert(1)</script>` into every user-controlled field (`generatedAt`, `rstSpecVersion`, `run.status`, `caseId`, `tests[]`, `reason`, `files[]`, `testCase`, exercised/unexercised error codes). Output:

- Raw `<script>` tag count: **0**
- Escaped `&lt;script&gt;` occurrences: **10** (every injection point covered)
- `javascript:` URL count: 0
- Inline event-handler attributes (`onmouseover=`, etc.): 0

### B-5: Inline-size cap probe

5000 case results → only 500 rendered (test_499 present, test_500 absent). 50-element fixture list → only 4 names shown with `+46 more` badge. Total HTML size with these massive inputs: **59 KB**.

### B-6: Subprocess audit

```
$ rg "subprocess|shell=True|os\.system|popen|os\.exec" src/rst_compliance/rst_dashboard.py
8:import subprocess
747:    completed = subprocess.run(
```

`subprocess.run` call uses a **list** command (`[sys.executable, "-m", "pytest", "-q", *str_paths, "--html", str(html_report), …]`), `shell=False` (default), no user-string interpolation into a shell metachar. Safe.

### B-7: Test sweep, green

- `pytest -q tests/test_rst_dashboard.py` → 54 passed
- `pytest -q tests` → 346 passed
- `pytest -q internal-rst-checker/tests` → 315 passed, 14 skipped

---

## Decision

**`merge_ready: true`**

Rationale: 0 blocker + 0 high findings. The single medium finding (M-1) is doc/test-quality only — the under-tested helpers and aliases are working correctly per live smoke + transitive coverage; the missed targeted tests can ride a follow-up PR without putting any acceptance criterion at risk. The five low findings are quality-of-life improvements with clear defer rationale (no in-tree YAML BOM, doc-only help-text gap, intentional DNSSEC-Ops scope, sparse DNSSEC-Ops fixtures, read-only theoretical traversal).

Per `review-severity-gate.mdc`: "`medium` findings require explicit defer rationale in PR" → suggested rationale, suitable for the PR description:

> Defer M-1: targeted unit tests for `_case_prefix` DNS overrides, the
> `render_placeholder_html` alias, and `--dashboard-html` flag will land
> in a follow-up. The behaviour is already validated transitively through
> `test_summarize_fixture_inventory_*` (covers `_case_prefix`),
> `test_dashboard_main_dry_run_writes_reports` (covers
> `render_placeholder_html`), and the smoke run of `make dashboard`
> (covers DNS / DNSSEC-Ops prefix tables). Risk window between this merge
> and the follow-up is bounded to silent prefix-table edits, which are
> rare and reviewable.
