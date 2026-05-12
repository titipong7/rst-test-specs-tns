# SRSGW Suite Fixtures

Static EPP / RDAP samples for the `srsgw` test suite from
`inc/srsgw/cases.yaml` (ICANN RST `v2026.04`). The suite focuses on
verifying that operations on the SRS Gateway are mirrored on the primary
registry, so each non-connectivity case ships:

- the EPP frame submitted to the **gateway** (`<nn>-<slug>-gateway.xml`,
  or `*-request.xml` / `*-approve.xml` for the two-phase transfer case),
  and
- the expected `<info>` response from the **primary** registry
  (`<nn>-<slug>-success.xml` for the happy path,
  `<nn>-<slug>-failure.xml` for the desynchronised state).

Layout follows the flat EPP template (`<nn>-<slug>-{success,failure}.<ext>`
directly under this folder).

## Connection template

Use `srsgw.env.example` as your local template:

- `SRSGW_EPP_HOST`, `SRSGW_EPP_PORT` — gateway EPP service.
- `SRSGW_EPP_CLID01` / `SRSGW_EPP_PWD01` — primary credentials.
- `SRSGW_EPP_CLID02` / `SRSGW_EPP_PWD02` — second registrar credentials
  (used by `srsgw-06` transfer).
- `SRSGW_REGISTRY_DATA_MODEL` — `minimum`, `maximum`, or `per-registrar`.
  When `minimum`, `srsgw-03`, `srsgw-11`, `srsgw-12` are skipped.
- `SRSGW_RDAP_BASE_URL` / `PRIMARY_RDAP_BASE_URL` — RDAP comparators for
  `srsgw-13..15`.

Do not commit real credentials. `*.env` files inside
`internal-rst-checker/fixtures/**` are git-ignored; only `*.env.example`
templates are tracked.

## Fixture files (per test case)

| Spec case   | Gateway frame(s)                                     | Primary happy                                  | Primary failure                                | Notes                                                                                                |
| ----------- | ---------------------------------------------------- | ---------------------------------------------- | ---------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `srsgw-01`  | `01-connectivity-hello.xml`                          | _connectivity probe — see `epp-01` fixtures_   | _connectivity probe — see `epp-01` fixtures_   | Hello frame is sufficient to drive DNS / TCP / TLS / login probes.                                   |
| `srsgw-02`  | `02-host-create-gateway.xml`                         | `02-host-create-success.xml`                   | `02-host-create-failure.xml`                   | Skipped if `epp.hostModel = attributes`.                                                             |
| `srsgw-03`  | `03-contact-create-gateway.xml`                      | `03-contact-create-success.xml`                | `03-contact-create-failure.xml`                | Skipped if `srsgw.registryDataModel = minimum`.                                                      |
| `srsgw-04`  | `04-domain-create-gateway.xml`                       | `04-domain-create-success.xml`                 | `04-domain-create-failure.xml`                 | Always exercised.                                                                                    |
| `srsgw-05`  | `05-domain-renew-gateway.xml`                        | `05-domain-renew-success.xml`                  | `05-domain-renew-failure.xml`                  | Failure keeps the original `exDate`, which the client must flag as out-of-sync.                      |
| `srsgw-06`  | `06-domain-transfer-request.xml`, `06-domain-transfer-approve.xml` | `06-domain-transfer-success.xml` | `06-domain-transfer-failure.xml` | Two-phase frame: request from `clid-02`, approve from `clid-01` (or auto-ack).                       |
| _srsgw-07_  | _removed — merged into `srsgw-06` per spec_          | _n/a_                                          | _n/a_                                          | Spec comment in `inc/srsgw/cases.yaml`: "srsgw-07 has been merged with srsgw-06".                    |
| `srsgw-08`  | `08-domain-delete-gateway.xml`                       | `08-domain-delete-success.xml`                 | `08-domain-delete-failure.xml`                 | Failure leaves the domain in `ok` after a delete request was acknowledged with `1001`.               |
| `srsgw-09`  | `09-host-update-gateway.xml`                         | `09-host-update-success.xml`                   | `09-host-update-failure.xml`                   | Skipped if `epp.hostModel = attributes`. Failure misses the new IP address.                          |
| `srsgw-10`  | `10-host-delete-gateway.xml`                         | `10-host-delete-success.xml`                   | `10-host-delete-failure.xml`                   | Skipped if `epp.hostModel = attributes`.                                                             |
| `srsgw-11`  | `11-contact-update-gateway.xml`                      | `11-contact-update-success.xml`                | `11-contact-update-failure.xml`                | Skipped if `srsgw.registryDataModel = minimum`. Failure shows unchanged email.                       |
| `srsgw-12`  | `12-contact-delete-gateway.xml`                      | `12-contact-delete-success.xml`                | `12-contact-delete-failure.xml`                | Skipped if `srsgw.registryDataModel = minimum`.                                                      |
| `srsgw-13`  | `13-domain-rdap-primary.json` (RDAP comparator)      | `13-domain-rdap-gateway-success.json`          | `13-domain-rdap-gateway-failure.json`          | Failure changes status / events to drift the RFC 8785 canonicalised payload.                         |
| `srsgw-14`  | `14-nameserver-rdap-primary.json`                    | `14-nameserver-rdap-gateway-success.json`      | `14-nameserver-rdap-gateway-failure.json`      | Skipped if `epp.hostModel = attributes`.                                                             |
| `srsgw-15`  | `15-registrar-rdap-primary.json`                     | `15-registrar-rdap-gateway-success.json`       | `15-registrar-rdap-gateway-failure.json`       | Failure swaps the handle to model a desynchronised registrar lookup.                                 |

`tests/srsgw/test_srsgw_fixtures_present.py` enforces presence and
syntactic validity for every active spec case prefix
(`01-` … `06-`, `08-` … `15-`).

## Placeholder conventions

- Hostnames use `*.example.example` to make it obvious the values are
  synthetic.
- IPv4 / IPv6 use the documentation prefixes (`192.0.2.0/24`, `2001:db8::/32`).
- `AUTH-CODE` is a reserved placeholder for `<domain:authInfo><domain:pw>`.
- `srsgw-07` is intentionally absent in line with the spec deletion note.
