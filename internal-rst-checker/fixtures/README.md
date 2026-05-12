# Internal RST Checker Fixtures

This directory groups every static fixture used to drive the internal RST
checker against the ICANN RST `v2026.04` specification.

Each sub-folder maps 1:1 to a spec suite, and every active spec case
under that suite ships at least one fixture file. Per-suite presence and
syntactic validity are enforced by guard tests under
`internal-rst-checker/tests/<suite>/test_<suite>_fixtures_present.py`.

| Suite          | Folder           | Cases                                                                                                                                                          | Guard test                                                              |
| -------------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| EPP            | `epp/th/`        | `epp-01..21`, `epp-23..27` (active) + `epp-22` reference                                                                                                       | `tests/epp/test_epp_th_fixtures_present.py`                              |
| DNS            | `dns/`           | `dns-zz-idna2008-compliance`, `dns-zz-consistency`                                                                                                              | `tests/dns/test_dns_fixtures_present.py`                                 |
| DNSSEC         | `dnssec/`        | `dnssec-91`, `dnssec-92`, `dnssec-93`                                                                                                                            | `tests/dnssec/test_dnssec_fixtures_present.py`                           |
| DNSSEC-Ops     | `dnssec-ops/`    | `dnssecOps01-ZSKRollover`, `dnssecOps02-KSKRollover`, `dnssecOps03-AlgorithmRollover` *(still on the per-case sub-folder layout — alignment tracked separately)* | `tests/dnssec_ops/test_dnssec_ops_fixtures_present.py`                   |
| RDE            | `rde/`           | `rde-01..14`                                                                                                                                                    | `tests/rde/test_rde_fixtures_present.py`                                 |
| RDAP           | `rdap/`          | `rdap-01..10`, `rdap-91`, `rdap-92`                                                                                                                              | `tests/rdap/test_rdap_fixtures_present.py`                               |
| SRSGW          | `srsgw/`         | `srsgw-01..06`, `srsgw-08..15` (`srsgw-07` was merged into `srsgw-06` upstream)                                                                                  | `tests/srsgw/test_srsgw_fixtures_present.py`                             |
| IDN            | `idn/`           | `idn-01`, `idn-02`                                                                                                                                              | `tests/idn/test_idn_fixtures_present.py`                                 |
| Integration    | `integration/`   | `integration-01..05`                                                                                                                                            | `tests/integration/test_integration_fixtures_present.py`                 |

## Fixture conventions

- **Flat EPP-style layout.** Every non-EPP suite (DNS, DNSSEC, RDE, RDAP,
  SRSGW, IDN, Integration) now uses the same shape as the EPP template
  at `fixtures/epp/th/`: a single root per suite, no sub-folders, files
  named `<nn>-<slug>-<role>.<ext>` directly under the suite directory.
  `<role>` is `success` / `failure` for the binary spec assertion, or a
  descriptive token (`request`, `approve`, `gateway`, `primary`,
  `create`, `update-domain`, …) for auxiliary artifacts.
  - DNSSEC-Ops is the one exception: it still uses per-case sub-folders
    pending its own alignment commit. It is tagged accordingly in the
    table above.
- **Case prefix.** `<nn>` matches the spec case number (DNS / DNSSEC use
  zero-padded indices from `cases.yaml`; suites that already have spec
  numbers reuse them — `91`, `92`, `93` for DNSSEC; `91`, `92` for
  RDAP TLS / service-port).
- **Happy / failure suffixes.** Files use the
  `<nn>-<slug>-success.<ext>` and `<nn>-<slug>-failure.<ext>` suffix
  pattern. A few cases ship multiple negative branches
  (e.g. `idn/01-variant-create-failure.xml`) or auxiliary frames
  (e.g. `srsgw/06-domain-transfer-{request,approve}.xml`).
- **Placeholders only.** All hostnames, IPs, handles, signatures and
  encryption keys are clearly synthetic. The documentation prefixes
  `192.0.2.0/24` and `2001:db8::/32` are used for all IP literals.
- **Env templates.** Every suite ships a `<suite>.env.example` template
  describing the live runtime parameters. Real `*.env` files are
  git-ignored via `.gitignore` and explicitly enforced by every guard
  test.
- **Binary placeholders.** Files that would normally be binary (RYDE
  bundles, public keys) use a `.example` suffix and a human-readable
  placeholder body. PGP signature placeholders use the `.asc` suffix
  (ASCII-armoured convention). They MUST NOT be replaced by real bytes
  in this repository.

## Adding fixtures for a new case

1. Add the case row to the suite's README table.
2. Drop the new files directly under the suite folder using the
   `<nn>-<slug>-{success,failure}.<ext>` convention (or a descriptive
   role token for auxiliary artifacts).
3. Extend the suite's guard-test `ACTIVE_CASES` tuple so the presence
   check picks up the new prefix.
4. Run the suite's guard test plus
   `.venv/bin/pytest internal-rst-checker/tests -q` and confirm green.

See `docs/agent-artifacts/fixtures-dns-dnssec-rde-rdap/plan.md` for the
flat-layout migration plan and `docs/epp-spec-to-test-mapping.md` for the
spec-to-test cross-reference (now extended with non-EPP suites).
