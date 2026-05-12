# DNSSEC Suite Fixtures

Static request/expected-response samples for the `dnssec` test suite from
`inc/dnssec/cases.yaml` (ICANN RST `v2026.04`).

Layout follows the flat EPP template (`<nn>-<slug>-{success,failure}.<ext>`
directly under this folder).

## Connection template

Use `dnssec.env.example` as your local template:

- `DNSSEC_TLD` — the TLD label under test.
- `DNSSEC_DS_RECORDS_PATH` — path to the DS records JSON used for live runs.

Do not commit real credentials. `*.env` files inside
`internal-rst-checker/fixtures/**` are git-ignored; only `*.env.example`
templates are tracked.

## Fixture files (per test case)

| Spec case   | Happy path                            | Negative path                         | Notes                                                                              |
| ----------- | ------------------------------------- | ------------------------------------- | ---------------------------------------------------------------------------------- |
| `dnssec-91` | `91-signing-algorithm-success.json`   | `91-signing-algorithm-failure.json`   | Failure uses algorithm `5` (RSASHA1) which is below the `>= 8` minimum.            |
| `dnssec-92` | `92-ds-digest-algorithm-success.json` | `92-ds-digest-algorithm-failure.json` | Failure mixes `digestType=1` (SHA-1) and `digestType=12` (GOST), both forbidden.   |
| `dnssec-93` | `93-nsec3-iterations-success.json`    | `93-nsec3-iterations-failure.json`    | Happy enforces `iterations=0` and empty salt; failure uses non-zero/with salt.     |

`tests/dnssec/test_dnssec_fixtures_present.py` enforces presence and
JSON validity for every active spec case prefix (`91-`, `92-`, `93-`).

## Placeholder conventions

- `example` is used as the test zone name; replace with your real zone.
- DS digests are illustrative hex strings only. Real DS values must be
  generated against your live DNSKEYs.
- `keyTag` values are deliberately small synthetic integers.
