# Pending Suite Implementation Notes

This document records the implementation delivered from the six-item plan for
the previously incomplete RST test areas.

## Scope

Implemented data-driven checker suites for:

1. Coverage source reconciliation and dashboard prefix detection.
2. `StandardIDN` (`idn-01`, `idn-02`).
3. `MinimumRPMs` (`minimumRPMs-01` ... `minimumRPMs-03`).
4. `StandardIntegrationTest` (`integration-01` ... `integration-05`).
5. `StandardSRSGateway` (`srsgw-01` ... `srsgw-06`, `srsgw-08` ... `srsgw-15`).
6. `AdditionalDNSTransports` via `dns-zz-consistency` additional transport probing.

## Design

The new suites follow the existing DNS/RDAP/RDE pattern:

- frozen suite config dataclasses;
- structured result/error dataclasses with `add_error()` and `skip()`;
- one checker class per specification case;
- a `run_all()` suite runner;
- explicit observations supplied by tests or future live harness code.

The checker layer intentionally validates observed behavior instead of opening
network sessions directly. That keeps CI deterministic and leaves live EPP,
TMCH, DNS, RDAP, RDE, and SRS Gateway collection as a separate harness concern.

## Implemented modules

| Suite | Module | Cases | Notes |
|---|---|---:|---|
| `StandardIDN` | `src/rst_compliance/idn_suite.py` | 2 | Valid/invalid label handling, variant policy, IDN-only ASCII rejection |
| `MinimumRPMs` | `src/rst_compliance/minimum_rpms_suite.py` | 3 | Claims check, sunrise create, trademark claims create observations |
| `StandardIntegrationTest` | `src/rst_compliance/integration_suite.py` | 5 | EPP to RDAP/DNS/RDE propagation and glue policy observations |
| `StandardSRSGateway` | `src/rst_compliance/srsgw_suite.py` | 14 | Gateway connectivity, EPP synchronization, RDAP synchronization |
| `AdditionalDNSTransports` | `src/rst_compliance/dns_suite.py` | 1 shared | Optional DoT/DoH/DoQ-style transport labels through `additional_transports` |
| Dashboard mapping | `src/rst_compliance/rst_dashboard.py` | N/A | Detects `idn`, `minimumRPMs`, `srsgw`, and `integration` case IDs |


## Input and expected data by case

The data below is the minimum deterministic fixture set expected by the checker
layer. Live harness code can collect the same values from real registry systems
and populate the suite config dataclasses.

| Case | Input data | Expected data |
|---|---|---|
| `idn-01` | `domain_create_extension_xml`; `domain_create_observations` with valid and invalid generated labels; `variant_observations` for `blocked`, `same-registrant`, and `same-registrar` policies | Valid labels are accepted, invalid labels are rejected, variant creates follow the configured policy, and malformed extension XML returns `EPP_INVALID_IDN_EXTENSION` |
| `idn-02` | `ascii_create_observations` with each TLD, `idn_only` flag, ASCII domain, and accepted/rejected result | Every `idn_only=true` TLD rejects ASCII-only creates; if no IDN-only TLD exists the case is skipped |
| `minimumRPMs-01` | `launch_extension_xml`; `claims_checks` with DNL membership, returned claim key, and claim-key validity | DNL domains return a valid claim key, non-DNL domains return no claim key, invalid keys fail with `RPMS_INVALID_CLAIMS_KEY` |
| `minimumRPMs-02` | `sunrise_creates` with valid SMD success path, invalid SMD, revoked SMD, revoked signature, incorrect SMD, and post-create info observations | Valid SMD creates succeed and info data exists with valid properties; negative SMD paths fail; malformed EPP XML returns `EPP_XML_PARSE_ERROR` |
| `minimumRPMs-03` | `trademark_claims_creates` with valid notice ID, invalid notice ID, expired notice ID, stale acceptance date, and post-create info observations | Valid notice creates succeed and info data exists with valid properties; invalid notice paths fail; malformed EPP XML returns `EPP_XML_PARSE_ERROR` |
| `integration-01` | `rdap_observations` with object name, object type, HTTP status, presence flag, and SLA flag | Each EPP-created object returns RDAP HTTP 200, is present, and appears within SLA |
| `integration-02` | `dns_observations` with domain, DNS server, query success flag, response-present flag, and SLA flag | Every authoritative DNS server answers for the created domain within SLA |
| `integration-03` | `rde_observations` with object name, SFTP reachability, authentication result, deposit presence, and SLA flag | RDE SFTP is reachable, authentication succeeds, and created objects appear in deposit data within SLA |
| `integration-04` | `glue_policy=narrow`, `host_model=objects`, and `host_object_glue_observations` for linked and unlinked host objects | Linked host object glue is observed in DNS; unlinked host object glue is not observed; non-applicable configs skip |
| `integration-05` | `glue_policy=narrow`, `host_model=attributes`, and `host_attribute_glue_observations` for expected and unexpected host attributes | Expected host attribute glue is observed in DNS; unexpected glue is not observed; non-applicable configs skip |
| `srsgw-01` | `connectivity_observations` for both `ipv4` and `ipv6`, including reachable, TLS, and login results | IPv4 and IPv6 service ports are reachable, TLS succeeds, and login succeeds |
| `srsgw-02` | `sync_observations` for host create with gateway command code, primary info code, deadline flag, and property comparison | Gateway host create succeeds, primary registry returns the host within deadline, and properties match; host-attribute model skips |
| `srsgw-03` | `sync_observations` for contact create with gateway command code, primary info code, deadline flag, and property comparison | Gateway contact create succeeds, primary registry returns the contact within deadline, and properties match; minimum data model skips |
| `srsgw-04` | `sync_observations` for domain create with gateway command code, primary info code, deadline flag, and property comparison | Gateway domain create succeeds, primary registry returns the domain within deadline, and properties match |
| `srsgw-05` | `sync_observations` for domain renew with gateway command code, primary info code, deadline flag, and expiry-date comparison | Gateway renew succeeds, primary registry reflects the update within deadline, and expiry dates match |
| `srsgw-06` | `sync_observations` for domain transfer with gateway command code, primary info code, deadline flag, and property comparison | Gateway transfer succeeds, primary registry reflects the transfer within deadline, and properties match |
| `srsgw-08` | `sync_observations` for domain delete with gateway command code, primary info code/update observation, deadline flag, and property comparison | Gateway delete succeeds and primary registry reflects the deletion/update state within deadline |
| `srsgw-09` | `sync_observations` for host update with gateway command code, primary info code, deadline flag, and property comparison | Gateway host update succeeds, primary registry reflects the update within deadline, and properties match; host-attribute model skips |
| `srsgw-10` | `sync_observations` for host delete with gateway command code, primary info code/update observation, deadline flag, and property comparison | Gateway host delete succeeds and primary registry reflects the deletion/update state within deadline; host-attribute model skips |
| `srsgw-11` | `sync_observations` for contact update with gateway command code, primary info code, deadline flag, and property comparison | Gateway contact update succeeds, primary registry reflects the update within deadline, and properties match; minimum data model skips |
| `srsgw-12` | `sync_observations` for contact delete with gateway command code, primary info code/update observation, deadline flag, and property comparison | Gateway contact delete succeeds and primary registry reflects the deletion/update state within deadline; minimum data model skips |
| `srsgw-13` | `rdap_observations` for domain RDAP with HTTP status, presence flag, and property comparison | Domain RDAP returns HTTP 200, object is present, and properties match gateway/primary data |
| `srsgw-14` | `rdap_observations` for nameserver RDAP with HTTP status, presence flag, and property comparison | Nameserver RDAP returns HTTP 200, object is present, and properties match gateway/primary data |
| `srsgw-15` | `rdap_observations` for registrar RDAP with HTTP status, presence flag, and property comparison | Registrar RDAP returns HTTP 200, object is present, and properties match gateway/primary data |
| `dns-zz-consistency` / `AdditionalDNSTransports` | `DnsSuiteConfig.nameservers`, injected `DnsQuerier`, and optional `additional_transports` such as `dot`, `doh`, and `doq` | UDP, TCP, and configured additional transports return consistent SOA response codes across nameservers; query failures are structured errors |

## Validation

New tests cover:

- pass/fail paths for each new suite family;
- applicability skips for IDN-only, integration glue, host object, and contact checks;
- suite runner case counts;
- dashboard case-ID extraction for new suite prefixes;
- additional DNS transport query dispatch.

## Non-goals

- No live EPP/TMCH/SFTP/DNS/RDAP network client was added.
- No long-running SLA polling scheduler was added.
- No Docker spec build behavior was changed.

## Follow-up work

- Add live harness adapters that produce the observation dataclasses from real
  applicant systems.
- Add internal checker smoke tests under `internal-rst-checker/tests` if the
  dashboard should report these new suites from its default internal test root.
- Expand protocol fixture depth as real EPP extension payloads and TMCH samples
  are wired into the harness.
