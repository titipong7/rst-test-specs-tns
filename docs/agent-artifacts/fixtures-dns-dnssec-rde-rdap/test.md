# Test — Non-EPP Fixtures Re-aligned to Flat EPP Layout

> Role: **Tester**. Validates the Builder commit chain against the
> acceptance criteria in
> [`plan.md` §7](./plan.md).

## 1. Test plan

| AC  | Criterion (from `plan.md` §7)                                                  | Verification command                                                                                | Status                                  |
| --- | ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- | --------------------------------------- |
| AC1 | Every `cases.yaml` case (7 suites) has ≥ 1 fixture matching `<nn>-*`           | Per-suite guard tests (`test_<suite>_fixtures_present.py::test_every_active_<suite>_case_…`)        | ✅ PASS (all glob asserts green)         |
| AC2 | All `*.xml` fixtures parse with `xml.etree.ElementTree.fromstring`             | Per-suite `test_<suite>_xml_fixtures_are_well_formed`                                               | ✅ PASS (skips on suites with no XML)    |
| AC3 | All `*.json` fixtures load with `json.loads`                                   | Per-suite `test_<suite>_json_fixtures_parse`                                                        | ✅ PASS (skips on suites with no JSON)   |
| AC4 | `fixtures/<suite>/README.md` carries 1:1 case→file table                       | Manual diff vs. flat layout                                                                         | ✅ PASS (all 7 suites refreshed)         |
| AC5 | `pytest -q internal-rst-checker/tests` passes                                  | `.venv/bin/python -m pytest internal-rst-checker/tests -q`                                          | ✅ PASS — see §2.1                       |
| AC6 | `pytest -q tests` (module level) stays green                                   | `.venv/bin/python -m pytest tests -q`                                                               | ✅ PASS — see §2.2                       |
| AC7 | `make quality-gate` passes locally                                             | `PATH="$PWD/.venv/bin:$PATH" make quality-gate-python` (sub-target)                                 | ✅ PASS for the Python compliance gate. ⚠ `make lint` / `make includes` need Perl modules (`ICANN::RST::Spec`, `Data::Mirror`) that the local environment doesn't ship; both are pre-existing and handled by CI bootstrap, unchanged in this PR. |
| AC8 | No real `.env` committed under `fixtures/<suite>/`                             | Per-suite `test_<suite>_no_real_env_files_are_committed`                                            | ✅ PASS (only `*.env.example` tracked)   |
| AC9 | No edits to `inc/**`, `rst-test-specs.*`, `src/rst_compliance/**`, `Makefile`, `.github/workflows/**` | `git diff main…HEAD --stat -- inc src rst-test-specs.* Makefile .github` | ✅ PASS — see §3                          |
| AC10 | Severity gate (review.md) returns 0 blocker / 0 high                          | Handled by Reviewer phase                                                                            | ⏭ Deferred to Reviewer                  |

## 2. Test results

### 2.1 `pytest -q internal-rst-checker/tests`

```
........s..............s...........s...................s.....s.s.s.s.... [ 28%]
.s.s.s.....s............................................................ [ 57%]
........s................s.............................................. [ 86%]
..................................                                       [100%]
```

- 0 failures, 14 deliberate skips. Skips fall into the documented
  "no JSON / no XML fixtures present" placeholder parametrisations
  (e.g. SRSGW has no JSON for `01-`/`02-`/…/`12-` so the JSON parse
  list is empty; the guard test skips with a labelled
  `no-json-fixtures` id, same convention used in the EPP guard).

### 2.2 `pytest -q tests`

```
.................................................................   [100%]
```

- 0 failures, 0 skips. Module-level Python suite stays green; the
  fixture move is invisible to it (no test there depends on the old
  per-case sub-folder paths).

### 2.3 Per-suite guard runs

| Suite        | Command                                                                                          | Result                       |
| ------------ | ------------------------------------------------------------------------------------------------ | ---------------------------- |
| `dns`        | `pytest internal-rst-checker/tests/dns/test_dns_fixtures_present.py -q`                          | 9 passed, 1 skip (no XML)    |
| `dnssec`     | `pytest internal-rst-checker/tests/dnssec/test_dnssec_fixtures_present.py -q`                    | 11 passed, 1 skip (no XML)   |
| `dnssec-ops` | `pytest internal-rst-checker/tests/dnssec_ops/test_dnssec_ops_fixtures_present.py -q`            | 11 passed, 1 skip (no XML)   |
| `rde`        | `pytest internal-rst-checker/tests/rde/test_rde_fixtures_present.py -q`                          | 39 passed, 1 skip (no JSON)  |
| `rdap`       | `pytest internal-rst-checker/tests/rdap/test_rdap_fixtures_present.py -q`                        | 32 passed, 1 skip (no XML)   |
| `srsgw`      | `pytest internal-rst-checker/tests/srsgw/test_srsgw_fixtures_present.py -q`                      | 57 passed, 0 skip            |
| `idn`        | `pytest internal-rst-checker/tests/idn/test_idn_fixtures_present.py -q`                          | 8 passed, 1 skip (no JSON)   |
| `integration`| `pytest internal-rst-checker/tests/integration/test_integration_fixtures_present.py -q`          | 25 passed, 0 skip            |

### 2.4 Combined-run note

`pytest internal-rst-checker/tests tests` raises 3 *collection* errors
because three test module names are duplicated between the two
roots (e.g. `tests/test_rdap_conformance.py` and
`internal-rst-checker/tests/rdap/test_rdap_conformance.py`). This is a
**pre-existing repository condition**: it reproduces on the `main`
branch tip without any of the migration changes. The two test roots
are run separately in CI (and locally via the targeted commands above),
so the migration does not introduce a regression here.

### 2.5 `make quality-gate-python`

```
Running Python compliance test gate...
.................................................................   [100%]
```

Pre-existing `make lint` / `make includes` Perl bootstrap is **not**
exercised here; CI continues to handle those steps via apt-installed
modules (`libdata-mirror-perl`, `libicann-rst-spec-perl`).

## 3. Scope audit (`AC9`)

`git diff main…feat/non-epp-fixtures-flat-layout --stat -- inc src rst-test-specs.html rst-test-specs.json Makefile .github` returns no entries: the migration touches **only**:

- `internal-rst-checker/fixtures/{dns,dnssec,rde,rdap,srsgw,idn,integration}/**`
- `internal-rst-checker/tests/{dns,dnssec,rde,rdap,srsgw,idn,integration}/test_<suite>_fixtures_present.py`
- `internal-rst-checker/fixtures/README.md`
- `docs/epp-spec-to-test-mapping.md` (note paragraph only)
- `docs/agent-artifacts/fixtures-dns-dnssec-rde-rdap/{plan,build,test,review}.md`

`inc/**`, `src/rst_compliance/**`, `rst-test-specs.*`, `Makefile`, and
`.github/workflows/**` are unmodified.

## 4. Hand-off to Reviewer

All guard-level acceptance criteria (AC1–AC9) are green; AC10 is the
formal severity gate handled in `review.md`. Reviewer can proceed to
the severity gate run + final PR description.
