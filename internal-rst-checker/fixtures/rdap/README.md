# RDAP Suite Fixtures

Static request / expected-response samples for the `rdap` test suite from
`inc/rdap/cases.yaml` (ICANN RST `v2026.04`).

Layout follows the flat EPP template (`<nn>-<slug>-{success,failure}.<ext>`
directly under this folder).

## Connection template

Use `rdap.env.example` as your local template:

- `RDAP_BASE_URL` — `https://…/<tld>/` per `rdap.baseURLs`. Trailing slash required.
- `RDAP_TLD`, `RDAP_TEST_DOMAIN`, `RDAP_TEST_NAMESERVER`, `RDAP_TEST_ENTITY_HANDLE`
  — values for the `rdap.testDomains`, `rdap.testNameservers`, and
  `rdap.testEntities` arrays respectively.
- `RDAP_PROFILE_VERSION` — `february-2024` (the only allowed value as of
  `v2026.04`).
- `RDAP_HOST_MODEL` — `objects` or `attributes`. When `attributes`,
  `rdap-02` and `rdap-06` are skipped at runtime.

Do not commit real credentials. `*.env` files inside
`internal-rst-checker/fixtures/**` are git-ignored; only `*.env.example`
templates are tracked.

## Fixture files (per test case)

| Spec case | Happy path                                  | Negative path                               | Auxiliary request                           | Notes                                                                                  |
| --------- | ------------------------------------------- | ------------------------------------------- | ------------------------------------------- | -------------------------------------------------------------------------------------- |
| `rdap-01` | `01-domain-query-success.json`              | `01-domain-query-failure.json`              | `01-domain-query-request.http`              | Failure drops `status`, `entities`, links and uses an invalid `eventDate`.             |
| `rdap-02` | `02-nameserver-query-success.json`          | `02-nameserver-query-failure.json`          | `02-nameserver-query-request.http`          | Skipped if `epp.hostModel = attributes`. Failure carries a malformed IPv4 address.     |
| `rdap-03` | `03-entity-query-success.json`              | `03-entity-query-failure.json`              | `03-entity-query-request.http`              | Failure ships an empty `roles` array, violating the gTLD RDAP profile.                 |
| `rdap-04` | `04-help-query-success.json`                | `04-help-query-failure.json`                | `04-help-query-request.http`                | Failure has no `notices`, which is required by the RDAP profile.                       |
| `rdap-05` | `05-domain-head-success.txt`                | `05-domain-head-failure.txt`                | `05-domain-head-request.http`               | Failure returns 405 Method Not Allowed.                                                |
| `rdap-06` | `06-nameserver-head-success.txt`            | `06-nameserver-head-failure.txt`            | `06-nameserver-head-request.http`           | Skipped if `epp.hostModel = attributes`. Failure ships a non-empty body for HEAD.      |
| `rdap-07` | `07-entity-head-success.txt`                | `07-entity-head-failure.txt`                | `07-entity-head-request.http`               | Failure returns HTTP 500 instead of 200.                                               |
| `rdap-08` | `08-non-existent-domain-success.json`       | `08-non-existent-domain-failure.json`       | `08-non-existent-domain-request.http`       | Happy returns 404 + RDAP error object; failure returns 200 incorrectly.                |
| `rdap-09` | `09-non-existent-nameserver-success.json`   | `09-non-existent-nameserver-failure.json`   | `09-non-existent-nameserver-request.http`   | Failure returns 500 instead of 404.                                                    |
| `rdap-10` | `10-non-existent-entity-success.json`       | `10-non-existent-entity-failure.json`       | `10-non-existent-entity-request.http`       | Failure returns 302 instead of 404.                                                    |
| `rdap-91` | `91-tls-conformance-success.json`           | `91-tls-conformance-failure.json`           | n/a (TLS probe summary)                     | Failure enumerates every TLS / cert / cipher violation expected by the spec.           |
| `rdap-92` | `92-service-port-consistency-success.json`  | `92-service-port-consistency-failure.json`  | n/a (probe summary)                         | Failure has identical paths returning different statuses across service ports.         |

`tests/rdap/test_rdap_fixtures_present.py` enforces presence and JSON
validity for every active spec case prefix (`01-` … `10-`, `91-`, `92-`).

## Placeholder conventions

- Hostnames use the `*.example` documentation TLD; replace with your
  TLD locally.
- IPv4 / IPv6 use the documentation prefixes (`192.0.2.0/24`,
  `2001:db8::/32`).
- The IANA Registrar ID `9995` is used as a clearly synthetic handle.
- HEAD-response fixtures use plain `*.txt` (HTTP-style) instead of JSON
  because HEAD responses must have an empty body.
- `*-request.http` files document the request envelope; they are not
  parsed by the guard test but kept alongside each case for reference.
