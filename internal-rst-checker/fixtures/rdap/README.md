# RDAP Suite Fixtures

Static request / expected-response samples for the `rdap` test suite from
`inc/rdap/cases.yaml` (ICANN RST `v2026.04`).

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

| Spec case   | Happy path                                            | Negative path                                         | Notes                                                                                  |
| ----------- | ----------------------------------------------------- | ----------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `rdap-01`   | `01-domain-query/response.success.json`               | `01-domain-query/response.failure.json`               | Failure drops `status`, `entities`, links and uses an invalid `eventDate`.             |
| `rdap-02`   | `02-nameserver-query/response.success.json`           | `02-nameserver-query/response.failure.json`           | Skipped if `epp.hostModel = attributes`. Failure carries a malformed IPv4 address.     |
| `rdap-03`   | `03-entity-query/response.success.json`               | `03-entity-query/response.failure.json`               | Failure ships an empty `roles` array, violating the gTLD RDAP profile.                 |
| `rdap-04`   | `04-help-query/response.success.json`                 | `04-help-query/response.failure.json`                 | Failure has no `notices`, which is required by the RDAP profile.                       |
| `rdap-05`   | `05-domain-head/response.success.txt`                 | `05-domain-head/response.failure.txt`                 | Failure returns 405 Method Not Allowed.                                                |
| `rdap-06`   | `06-nameserver-head/response.success.txt`             | `06-nameserver-head/response.failure.txt`             | Skipped if `epp.hostModel = attributes`. Failure ships a non-empty body for HEAD.      |
| `rdap-07`   | `07-entity-head/response.success.txt`                 | `07-entity-head/response.failure.txt`                 | Failure returns HTTP 500 instead of 200.                                               |
| `rdap-08`   | `08-non-existent-domain/response.success.json`        | `08-non-existent-domain/response.failure.json`        | Happy returns 404 + RDAP error object; failure returns 200 incorrectly.                |
| `rdap-09`   | `09-non-existent-nameserver/response.success.json`    | `09-non-existent-nameserver/response.failure.json`    | Failure returns 500 instead of 404.                                                    |
| `rdap-10`   | `10-non-existent-entity/response.success.json`        | `10-non-existent-entity/response.failure.json`        | Failure returns 302 instead of 404.                                                    |
| `rdap-91`   | `91-tls-conformance/probe.success.json`               | `91-tls-conformance/probe.failure.json`               | Failure enumerates every TLS / cert / cipher violation expected by the spec.           |
| `rdap-92`   | `92-service-port-consistency/probe.success.json`      | `92-service-port-consistency/probe.failure.json`      | Failure has identical paths returning different statuses across service ports.         |

`tests/rdap/test_rdap_fixtures_present.py` enforces presence and JSON
validity for every active spec case.

## Placeholder conventions

- Hostnames use the `*.example` documentation TLD; replace with your
  TLD locally.
- IPv4 / IPv6 use the documentation prefixes (`192.0.2.0/24`,
  `2001:db8::/32`).
- The IANA Registrar ID `9995` is used as a clearly synthetic handle.
- HEAD-response fixtures use plain `*.txt` (HTTP-style) instead of JSON
  because HEAD responses must have an empty body.
