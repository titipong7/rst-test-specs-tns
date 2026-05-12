# Integration Suite Fixtures

End-to-end driver samples for the `integration` test suite from
`inc/integration/cases.yaml` (ICANN RST `v2026.04`). Each case ships:

- the EPP transform that triggers the integration check
  (`*-create*.xml`, `*-update-domain.xml`), and
- the expected downstream observation (RDAP / DNS / RDE) for both the
  happy and SLA-breach paths.

Layout follows the flat EPP template (`<nn>-<slug>-{success,failure,
create,update-domain}.<ext>` directly under this folder).

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

The scoped `03-epp-rde-sftp.env.example` documents the additional SFTP
inputs needed for `integration-03` (`INTEGRATION_RDE_SFTP_HOSTNAME`,
`…USERNAME`, `…DIRECTORY`, `…PUBLIC_KEY_PATH`).

Do not commit real credentials. `*.env` files inside
`internal-rst-checker/fixtures/**` are git-ignored; only `*.env.example`
templates are tracked.

## Fixture files (per test case)

| Spec case        | Inputs (EPP frame(s))                                                                                  | Expected observation (happy)                  | Expected observation (failure)                | Notes                                                                                  |
| ---------------- | ------------------------------------------------------------------------------------------------------ | --------------------------------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------- |
| `integration-01` | `01-epp-rdap-create.xml`                                                                               | `01-epp-rdap-success.json`                    | `01-epp-rdap-failure.json`                    | RDAP visibility within 1 hour of `<crDate>`.                                           |
| `integration-02` | `02-epp-dns-create.xml`                                                                                | `02-epp-dns-success.json`                     | `02-epp-dns-failure.json`                     | DNS resolution within 1 hour of `<crDate>`.                                            |
| `integration-03` | `03-epp-rde-create.xml`                                                                                | `03-epp-rde-success.xml`                      | `03-epp-rde-failure.xml`                      | Domain must appear in next deposit within 24h. `03-epp-rde-sftp.env.example` documents the additional SFTP inputs. |
| `integration-04` | `04-glue-host-objects-create-domain.xml`, `04-glue-host-objects-create-host.xml`, `04-glue-host-objects-update-domain.xml` | `04-glue-host-objects-success.json` | `04-glue-host-objects-failure.json` | Skipped unless `dns.gluePolicy=narrow` and `epp.hostModel=objects`.                    |
| `integration-05` | `05-glue-host-attributes-create-domain-1.xml`, `05-glue-host-attributes-create-domain-2.xml`           | `05-glue-host-attributes-success.json`        | `05-glue-host-attributes-failure.json`        | Skipped unless `dns.gluePolicy=narrow` and `epp.hostModel=attributes`.                 |

`tests/integration/test_integration_fixtures_present.py` enforces
presence and syntactic validity for every active spec case prefix
(`01-` … `05-`).

## Placeholder conventions

- Domains use synthetic `*.example` names tied to the case (`integration0N…`).
- IPv4 addresses use the documentation prefix `192.0.2.0/24`.
- `INTEGRATION_RDE_SFTP_PUBLIC_KEY_PATH` is documented but its value
  MUST never be committed; only the `.example` filename template is
  shipped.
