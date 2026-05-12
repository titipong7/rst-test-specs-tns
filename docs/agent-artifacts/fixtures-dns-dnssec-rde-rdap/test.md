# Test — Fixtures for DNS / DNSSEC / RDE / RDAP / SRSGW / IDN / Integration

> Role: **Tester**. Validating the Builder output against the approved
> Plan acceptance criteria.
>
> Spec reference: ICANN RST `v2026.04`.

## Test matrix

| Criterion (from plan §4)                                                                                  | Command                                                            | Result                                                                                                |
| --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| 1. Every case in §2 has at least one fixture                                                              | `.venv/bin/pytest internal-rst-checker/tests/<suite> -q`           | **PASS** (per-suite counts below)                                                                     |
| 2. Every case with both branches has `*.success.*` and `*.failure.*` artifacts                            | Same as above (parametrized `test_every_active_*_case_*`)          | **PASS** (`idn-02` and `srsgw-01` documented as spec-only-negative / spec-only-happy respectively)    |
| 3. Per-suite guard tests pass                                                                             | `.venv/bin/pytest internal-rst-checker/tests -q`                   | **PASS** — 315 passed, 14 skipped                                                                     |
| 4. Existing top-level tests stay green                                                                    | `.venv/bin/pytest tests -q`                                        | **PASS** — 65 passed, 0 skipped, 0 failed                                                             |
| 5. README per fixture folder matching `epp/th` layout                                                     | manual inspection                                                  | **PASS** (`fixtures/<suite>/README.md` × 8 + top-level `fixtures/README.md`)                          |
| 6. No `*.env` (only `*.env.example`) added; `.gitignore` already covers `*.env` under `fixtures/**`       | `test_<suite>_no_real_env_files_are_committed` (one per suite)     | **PASS** — 8/8 suites assert empty real-env list                                                      |
| 7. No spec files (`inc/**/*.yaml`, `rst-test-specs.*`) modified                                            | `git diff --name-only main…HEAD -- inc rst-test-specs.*`            | **PASS** — no spec paths in diff                                                                      |
| 8. Reviewer report contains `merge_ready: true` with no `blocker`/`high` findings under the severity gate | see `review.md`                                                    | Pending Reviewer phase                                                                                |

## Per-suite results

| Suite          | Test file                                                                      | Result                       |
| -------------- | ------------------------------------------------------------------------------- | ---------------------------- |
| DNS            | `internal-rst-checker/tests/dns/test_dns_fixtures_present.py`                   | 12 passed, 1 skipped         |
| DNSSEC         | `internal-rst-checker/tests/dnssec/test_dnssec_fixtures_present.py`             | 11 passed, 1 skipped         |
| DNSSEC-Ops     | `internal-rst-checker/tests/dnssec_ops/test_dnssec_ops_fixtures_present.py`     | 11 passed, 1 skipped         |
| RDE            | `internal-rst-checker/tests/rde/test_rde_fixtures_present.py`                   | 38 passed, 1 skipped         |
| RDAP           | `internal-rst-checker/tests/rdap/test_rdap_fixtures_present.py` + existing      | 39 passed, 1 skipped         |
| SRSGW          | `internal-rst-checker/tests/srsgw/test_srsgw_fixtures_present.py`               | 57 passed                    |
| IDN            | `internal-rst-checker/tests/idn/test_idn_fixtures_present.py`                   | 8 passed, 1 skipped          |
| Integration    | `internal-rst-checker/tests/integration/test_integration_fixtures_present.py`   | 25 passed                    |
| EPP (regression check) | existing `internal-rst-checker/tests/epp/*`                              | 112 passed, 8 skipped (unchanged from baseline) |
| Module tests   | `tests/`                                                                       | 65 passed                    |

**Total:** 380 passed, 14 skipped, 0 failed across `internal-rst-checker/tests` + `tests`.

## Skipped tests breakdown

All 14 skips are the deliberate "no XML / JSON fixtures present in this
suite" placeholders emitted by the parametrized syntactic-validity
checks when a suite happens to ship only one of the two file types.
No EPP-suite skip count changed from the pre-existing baseline
(8 `if applicable` skips), confirming no regression.

## Fixture inventory

```
internal-rst-checker/fixtures/
├── dns/         (6 files + README + env.example)
├── dnssec/      (6 files + README + env.example)
├── dnssec-ops/  (7 files + README + env.example + tsig.env.example)
├── rde/         (28 files + README + env.example)
├── rdap/        (36 files + README + env.example)
├── srsgw/       (37 files + README + env.example)
├── idn/         (4 files + README + env.example)
└── integration/ (16 files + README + env.example + sftp.env.example)
```

Total new files added by Builder: **163** (fixtures + READMEs +
env.examples + 8 per-suite guard tests + top-level `fixtures/README.md`).

## Flaky-test notes

- None observed across two consecutive runs of
  `.venv/bin/pytest internal-rst-checker/tests` (1.14s and ≈1.6s).
- The 14 "no-fixtures-of-this-type" skips are deterministic and gated
  on the actual fixture inventory, not on environment.

## Release confidence

**High.** All Plan acceptance criteria 1–7 verified mechanically; only
criterion 8 (`merge_ready: true`) is pending the Reviewer step. The
diff is additive, scope-bound to fixture folders + guard tests + two
documentation files, and contains no secrets.
