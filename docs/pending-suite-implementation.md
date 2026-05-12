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
