# DNSSEC-Ops Suite Fixtures

Static configuration samples for the `dnssec-ops` test suite from
`inc/dnssec-ops/cases.yaml` (ICANN RST `v2026.04`).

## Connection template

Use `dnssec-ops.env.example` as your local template:

- `DNSSEC_OPS_CSK` — `true` if your RSP uses a Combined Signing Key
  (CSK), in which case ZSK rollover monitoring is skipped.
- `DNSSEC_OPS_*_ZONE` — separate zones for ZSK / KSK / algorithm rollover.
- `DNSSEC_OPS_TSIG_*` — TSIG credentials used to authorise zone transfers.
- `DNSSEC_OPS_PRIMARY_V4` / `DNSSEC_OPS_PRIMARY_V6` — primary server
  addresses from which test transfers are pulled.

Do not commit real credentials. `*.env` files inside
`internal-rst-checker/fixtures/**` are git-ignored; only `*.env.example`
templates are tracked.

## Fixture files (per test case)

| Spec case                              | Happy path                                                | Negative path                                            | Notes                                                                                          |
| -------------------------------------- | --------------------------------------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `dnssecOps01-ZSKRollover`              | `01-zsk-rollover/config.success.json`                     | `01-zsk-rollover/config.failure.json`                    | Skipped if `dnssecOps.csk=true`. `tsig.env.example` documents required TSIG inputs.            |
| `dnssecOps02-KSKRollover`              | `02-ksk-rollover/config.success.json`                     | `02-ksk-rollover/config.failure.json`                    | Failure walks through DS withdrawal before the new KSK is published at the parent.             |
| `dnssecOps03-AlgorithmRollover`        | `03-algorithm-rollover/config.success.json`               | `03-algorithm-rollover/config.failure.json`              | Failure targets algorithm `#5` (RSASHA1) which violates the `>= 8` minimum from `dnssec-91`.   |

`tests/dnssec_ops/test_dnssec_ops_fixtures_present.py` enforces presence
and JSON validity for every active spec case.

## Placeholder conventions

- Zone names use the `*.example` documentation TLD.
- All IPs use the documentation prefixes (`192.0.2.0/24`, `2001:db8::/32`).
- `<set-locally-base64>` is a reserved placeholder for the TSIG secret;
  never replace it with a real key inside this repo.
