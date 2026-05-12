# Internal Dashboard — Suite Coverage

The internal RST dashboard surfaces every suite that ships a
`inc/<suite>/cases.yaml` under the v2026.04 spec, plus the etc-asset
smoke checks that live under `internal-rst-checker/tests/etc/`.

| Suite          | Source case file              | Cases | Fixtures dir                                 |
| -------------- | ----------------------------- | ----- | -------------------------------------------- |
| `dns`          | `inc/dns/cases.yaml`          | 2     | `internal-rst-checker/fixtures/dns/`          |
| `dnssec`       | `inc/dnssec/cases.yaml`       | 3     | `internal-rst-checker/fixtures/dnssec/`       |
| `dnssec-ops`   | `inc/dnssec-ops/cases.yaml`   | 3     | `internal-rst-checker/fixtures/dnssec-ops/`   |
| `rdap`         | `inc/rdap/cases.yaml`         | 12    | `internal-rst-checker/fixtures/rdap/`         |
| `rde`          | `inc/rde/cases.yaml`          | 14    | `internal-rst-checker/fixtures/rde/`          |
| `srsgw`        | `inc/srsgw/cases.yaml`        | 14    | `internal-rst-checker/fixtures/srsgw/`        |
| `idn`          | `inc/idn/cases.yaml`          | 2     | `internal-rst-checker/fixtures/idn/`          |
| `integration`  | `inc/integration/cases.yaml`  | 5     | `internal-rst-checker/fixtures/integration/`  |
| `epp`          | `inc/epp/cases.yaml`          | 26    | `internal-rst-checker/fixtures/epp/th/`       |

`minimum-rpms` is read by the spec but not surfaced in the dashboard
because no fixtures are planned for it.

## Generated artefacts

Running `make dashboard` writes:

- `internal-rst-checker/reports/report.json`
- `internal-rst-checker/reports/dashboard.html` (self-contained, no JS)

The unrelated `internal-rst-checker/reports/report.html` is the
pytest-html test-execution report and stays owned by the
`pytest --html` plugin.

## CLI flags

| Flag                          | Effect                                                     |
| ----------------------------- | ---------------------------------------------------------- |
| `--suite NAME` (repeatable)   | Restrict suite-level matrices to the named suites.         |
| `--skip-fixtures`             | Skip the on-disk fixture walk.                             |
| `--skip-errors`               | Skip `errors.yaml` parsing + error-code coverage.          |
| `--dashboard-html PATH`       | Override the `dashboard.html` output path.                 |
| `--no-dashboard`              | Skip rendering the dashboard HTML entirely.                |
| `--dry-run`                   | Don't invoke pytest (useful for offline regeneration).     |
