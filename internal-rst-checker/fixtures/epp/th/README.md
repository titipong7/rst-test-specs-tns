# .th EPP Fixtures (THNIC)

This directory contains standalone XML fixtures for EPP testing against `.th`.
Every active StandardEPP test case (`epp-01..epp-27`) has at least one matching
fixture, with a `*-success.xml` happy path and (where applicable) a
`*-failure.xml` negative path.

## Connection template

Use `th.env.example` as your local template:

- `EPP_HOST=epp.thains.co.th`
- `EPP_PORT=700`
- `EPP_USERNAME=THNIC-20001`
- `EPP_PASSWORD=<set-locally>`
- `EPP_CLIENT_CERT=<path-to-client-cert>`
- `EPP_CLIENT_KEY=<path-to-client-key>`

Do not commit real credentials. `*.env` files inside
`internal-rst-checker/fixtures/**` are git-ignored; only `*.env.example`
templates are tracked.

## Fixture files (per test case)

| Spec case | Happy path | Negative path |
| --- | --- | --- |
| `epp-01` connectivity / TLS | `01-hello.xml` | _live probe – see `tests/test_epp_connectivity.py`_ |
| `epp-02` greeting / extensions | `02-greeting-success.xml` | `02-greeting-failure.xml` |
| `epp-03` login / authentication | `03-login-success.xml` | `03-login-failure.xml` |
| `epp-04` domain check | `04-domain-check-success.xml` | `04-domain-check-failure.xml` |
| `epp-05` host check | `05-host-check-success.xml` | `05-host-check-failure.xml` |
| `epp-06` contact check | `06-contact-check-success.xml` | `06-contact-check-failure.xml` |
| `epp-07` contact create | `07-contact-create-success.xml` | `07-contact-create-failure.xml` |
| `epp-08` contact ACL | `08-contact-acl-success.xml` | `08-contact-acl-failure.xml` |
| `epp-09` contact update | `09-contact-update-success.xml` | `09-contact-update-failure.xml` |
| `epp-10` contact delete | `10-contact-delete-success.xml` | `10-contact-delete-failure.xml` |
| `epp-11` host create | `11-host-create-success.xml` | `11-host-create-failure.xml` |
| `epp-12` host ACL | `12-host-acl-success.xml` | `12-host-acl-failure.xml` |
| `epp-13` host update | `13-host-update-success.xml` | `13-host-update-failure.xml` |
| `epp-14` domain create | `14-domain-create-success.xml` | `14-domain-create-failure.xml` |
| `epp-15` registry object integrity | `15-object-integrity-success.xml` | `15-object-integrity-failure.xml` |
| `epp-16` domain update | `16-domain-update-success.xml` | `16-domain-update-failure.xml` |
| `epp-17` service port consistency | `17-service-port-success.xml` | `17-service-port-failure.xml` |
| `epp-18` domain renew | `18-domain-renew-success.xml` | `18-domain-renew-failure.xml` |
| `epp-19` domain transfer request | `19-domain-transfer-request-success.xml` | `19-domain-transfer-request-failure.xml` |
| `epp-20` domain transfer reject | `20-domain-transfer-reject-success.xml` | `20-domain-transfer-reject-failure.xml` |
| `epp-21` domain delete | `21-domain-delete-success.xml` | `21-domain-delete-failure.xml` |
| `epp-22` _(removed in v2026.04)_ | `22-domain-restore-reference.xml` | _none – kept for matrix continuity_ |
| `epp-23` host rename | `23-host-rename-success.xml` | `23-host-rename-failure.xml` |
| `epp-24` host delete | `24-host-delete-success.xml` | `24-host-delete-failure.xml` |
| `epp-25` subordinate host create | `25-subordinate-host-create-success.xml` | `25-subordinate-host-create-failure.xml` |
| `epp-26` wide glue policy | `26-wide-glue-policy.xml` | _same fixture used to assert reject_ |
| `epp-27` glueless internal host | `27-glueless-internal-host-create.xml`, `27-glueless-internal-host-delegate.xml` | _same fixtures used to assert reject_ |

`tests/epp/test_epp_th_fixtures_present.py` enforces that every active spec
case keeps at least one fixture and that every XML fixture in this folder is
well-formed.

## Placeholder conventions

- Replace `example.th` and related hostnames with your test objects.
- Replace `AUTH-CODE` with a valid transfer code for your test domain.
- Keep `clTRID` unique per transaction in real runs.
- Replace `${EPP_PASSWORD}` and other env placeholders with values from your
  local (git-ignored) `th.env`.
