# Review — Fixtures for DNS / DNSSEC / RDE / RDAP / SRSGW / IDN / Integration

> Role: **Reviewer**. Findings are graded against
> `.cursor/rules/review-severity-gate.mdc`.

## Acceptance criteria check

| Plan §4 criterion                                                                                                | Status                                                                                                                                                |
| ----------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Every case in §2 has at least one fixture and per-case happy/negative branches                                    | **Met** (see per-suite README tables + `ACTIVE_CASES` dictionaries).                                                                                  |
| Naming convention `*.success.<ext>` / `*.failure.<ext>` used consistently                                         | **Met**, including the documented exceptions (`idn-02` ships only a negative fixture per spec; `srsgw-01` is connectivity-only).                       |
| Per-suite guard test mirroring `tests/epp/test_epp_th_fixtures_present.py`                                        | **Met** — 8 new files under `internal-rst-checker/tests/<suite>/`.                                                                                    |
| Per-suite + top-level README                                                                                      | **Met** — 8 suite READMEs + new `internal-rst-checker/fixtures/README.md`.                                                                            |
| Cross-link from EPP mapping doc to non-EPP suites                                                                 | **Met** — new "Non-EPP Suite Fixture Pointers" section in `docs/epp-spec-to-test-mapping.md`.                                                          |
| No spec files modified                                                                                            | **Met** — diff scoped to `internal-rst-checker/fixtures/**`, `internal-rst-checker/tests/**`, `docs/agent-artifacts/**`, and two existing doc files.   |
| No secrets / no real `.env` files committed                                                                       | **Met** — only `*.env.example` templates added (11 total); placeholders use documentation prefixes (`192.0.2.0/24`, `2001:db8::/32`, `*.example`).     |
| Make targets / CI workflows unchanged                                                                              | **Met** — no `Makefile` or `.github/workflows/**` modifications.                                                                                       |
| Test runs green                                                                                                   | **Met** — 380 passed / 14 skipped / 0 failed across `internal-rst-checker/tests` + `tests` (see `test.md`).                                          |

## Findings

### Severity: blocker

_None._

### Severity: high

_None._

### Severity: medium

**M1. RDE binary placeholders cannot be cryptographically validated in offline tests.**
- Evidence: `internal-rst-checker/fixtures/rde/02-signature/*.sig.example`
  and `internal-rst-checker/fixtures/rde/03-decrypt/*.ryde.example`
  carry human-readable placeholders rather than real OpenPGP or RYDE
  bytes. The fixture-present guard test parametrises only well-formedness
  on `.xml` and `.json` files, so a corrupted real binary would still
  pass.
- Required action (defer rationale acceptable):
  - Defer: live signature/decrypt validation belongs in the
    runtime checker, not in offline fixture smoke tests. The plan
    explicitly excludes "real OpenPGP signatures / live decryption" and
    the README states this.
  - Follow-up: when the runtime decryptor lands for `rde-03`, add a
    targeted negative-path unit test fed by a real (test-only) keypair
    stored outside this repo.

### Severity: low

**L1. Some negative-path JSON fixtures contain an `expectedFindings` advisory key.**
- Evidence: e.g. `rdap/91-tls-conformance/probe.failure.json`,
  `integration/04-glue-policy-host-objects/dns-query.failure.json`.
- Required action: none for this PR. The key is informational, mirrors
  the spec's error catalogues, and the JSON parser accepts it. If a
  future schema landed, the field could be promoted to a typed
  `metadata.expectedFindings` block.

**L2. `srsgw-07` is intentionally absent but never explicitly tested for absence.**
- Evidence: spec note in `inc/srsgw/cases.yaml` ("srsgw-07 has been merged
  with srsgw-06") and prose note in the SRSGW README, but no test
  asserts that no `srsgw/07-*` folder is created later by mistake.
- Required action: backlog. Add a single assertion in
  `test_srsgw_fixtures_present.py` that `srsgw/07-*` glob returns empty,
  once we have a similar guard for any spec-deleted case.

## Diff scope sanity check

```
modified:  docs/epp-spec-to-test-mapping.md           (append-only)
added:     docs/agent-artifacts/fixtures-dns-dnssec-rde-rdap/{plan,build,test,review}.md
added:     internal-rst-checker/fixtures/README.md
added:     internal-rst-checker/fixtures/{dns,dnssec,dnssec-ops,rde,rdap,srsgw,idn,integration}/**
added:     internal-rst-checker/tests/{dns,dnssec,dnssec_ops,rde,rdap,srsgw,idn,integration}/test_<suite>_fixtures_present.py
```

No EPP suite paths, no spec files, no Makefile, no CI workflow changes.

## Merge readiness

- Severity gate: **0 blocker / 0 high / 1 medium (deferred with rationale) / 2 low (backlog).**
- Acceptance criteria 1–9: **all met.**
- CI surface unchanged; new tests are lightweight and deterministic.

**`merge_ready: true`** — pending human approval.
