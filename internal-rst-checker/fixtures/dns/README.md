# DNS Suite Fixtures

Static request/expected-response samples for the `dns` test suite from
`inc/dns/cases.yaml` (ICANN RST `v2026.04`).

## Connection template

Use `dns.env.example` as your local template:

- `DNS_TLD` — the TLD label under test.
- `DNS_GLUE_POLICY` — `narrow` or `wide`, mirrors `dns.gluePolicy`.
- `DNS_PROBE_TIMEOUT_*` — UDP / TCP query timeouts in milliseconds.

Do not commit real credentials. `*.env` files inside
`internal-rst-checker/fixtures/**` are git-ignored; only `*.env.example`
templates are tracked.

## Fixture files (per test case)

| Spec case                       | Happy path                                           | Negative path                                       | Notes                                                                                              |
| ------------------------------- | ---------------------------------------------------- | --------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `dns-zz-idna2008-compliance`    | `idna2008-compliance/nameservers.success.json`       | `idna2008-compliance/nameservers.failure.json`      | `apex-rrsets.zone` ships sample SOA/NS rrsets used by `IDNA2008_INVALID_*` checks.                |
| `dns-zz-consistency`            | `consistency/nameservers.success.json`               | `consistency/nameservers.failure.json`              | `query-matrix.json` documents the apex / delegation query set used per nameserver and transport.   |

`tests/dns/test_dns_fixtures_present.py` enforces that every active spec case
keeps at least one happy and one negative fixture, and that all JSON
fixtures parse cleanly.

## Placeholder conventions

- `example` is used as the test TLD; replace with your real TLD label
  locally.
- IPv4 / IPv6 use the documentation prefixes
  (`192.0.2.0/24`, `2001:db8::/32`); never substitute live addresses.
- The `xn--idn-example-7za.example` label is a deliberately synthetic
  IDNA2008-conformant nameserver used to exercise IDN paths.
