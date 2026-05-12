# Integration Suite Fixtures

End-to-end driver samples for the `integration` test suite from
`inc/integration/cases.yaml` (ICANN RST `v2026.04`). Each case ships:

- the EPP transform that triggers the integration check
  (`epp-create*.xml`, `epp-update-domain.xml`), and
- the expected downstream observation (RDAP / DNS / RDE) for both the
  happy and SLA-breach paths.

## Connection template

Use `integration.env.example` as your local template:

- `INTEGRATION_TLD` — TLD under test.
- `INTEGRATION_RDAP_BASE_URL` — RDAP base URL for `integration-01`.
- `INTEGRATION_DNS_NAMESERVERS` — nameservers monitored by
  `integration-02`, `integration-04`, `integration-05`.
- `INTEGRATION_SLA_*_HOURS` — the per-case SLA windows from the spec.
- `INTEGRATION_GLUE_POLICY` — `narrow` (`integration-04` and `-05`
  are skipped unless this is `narrow`).
- `INTEGRATION_HOST_MODEL` — `objects` vs. `attributes` decides which
  glue-policy case applies.

Do not commit real credentials. `*.env` files inside
`internal-rst-checker/fixtures/**` are git-ignored; only `*.env.example`
templates are tracked.

## Fixture files (per test case)

| Spec case        | Inputs (EPP frame(s))                                                                                | Expected observation (happy)                                  | Expected observation (failure)                                  | Notes                                                                                  |
| ---------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `integration-01` | `01-epp-rdap/epp-create.xml`                                                                          | `01-epp-rdap/rdap-response.success.json`                      | `01-epp-rdap/rdap-response.failure.json`                         | RDAP visibility within 1 hour of `<crDate>`.                                           |
| `integration-02` | `02-epp-dns/epp-create.xml`                                                                           | `02-epp-dns/dns-query.success.json`                           | `02-epp-dns/dns-query.failure.json`                              | DNS resolution within 1 hour of `<crDate>`.                                            |
| `integration-03` | `03-epp-rde/epp-create.xml`                                                                           | `03-epp-rde/rde-deposit.success.xml`                          | `03-epp-rde/rde-deposit.failure.xml`                             | Domain must appear in next deposit within 24h. `sftp.env.example` documents inputs.    |
| `integration-04` | `04-glue-policy-host-objects/{epp-create-domain,epp-create-host,epp-update-domain}.xml`              | `04-glue-policy-host-objects/dns-query.success.json`          | `04-glue-policy-host-objects/dns-query.failure.json`             | Skipped unless `dns.gluePolicy=narrow` and `epp.hostModel=objects`.                    |
| `integration-05` | `05-glue-policy-host-attributes/{epp-create-domain-1,epp-create-domain-2}.xml`                       | `05-glue-policy-host-attributes/dns-query.success.json`       | `05-glue-policy-host-attributes/dns-query.failure.json`          | Skipped unless `dns.gluePolicy=narrow` and `epp.hostModel=attributes`.                 |

`tests/integration/test_integration_fixtures_present.py` enforces presence and
syntactic validity for every active spec case.

## Placeholder conventions

- Domains use synthetic `*.example` names tied to the case (`integration0N…`).
- IPv4 addresses use the documentation prefix `192.0.2.0/24`.
- `INTEGRATION_RDE_SFTP_PUBLIC_KEY_PATH` is documented but its value
  MUST never be committed; only the `.example` filename template is
  shipped.
