# RST v2026.04 Test Suite — Implementation Overview

## Summary

This document tracks the implementation status of all 11 RST v2026.04 test
suites across 78+ implemented and 50 pending test cases.

| Status | Suites | Test Cases | Unit Tests |
|--------|--------|------------|------------|
| ✅ Implemented | 5 | 78 | 253 |
| ❌ Not implemented | 5 | 50 | — |
| ⚠️ Shared/overlap | 1 | (1) | — |
| **Total** | **11** | **128+** | **253** |

---

## Implementation Status by Suite

### ✅ Implemented Suites

| # | Suite | Cases | Source File | Tests | Doc |
|---|---|---|---|---|---|
| 1 | **StandardDNS** | 35 | `src/rst_compliance/dns_suite.py` | 50 | `docs/dns-suite-implementation.md` |
| 2 | **StandardDNSSEC** | 14 | `src/rst_compliance/dns_suite.py` | 18 | `docs/dnssec-suite-implementation.md` |
| 3 | **StandardRDAP** | 12 | `src/rst_compliance/rdap_conformance.py` | 89 | `docs/rdap-suite-implementation.md` |
| 4 | **StandardRDE** | 14 | `src/rst_compliance/rde_suite.py` | 41 | `docs/rde-suite-implementation.md` |
| 5 | **DNSSECOperations** | 3 | `src/rst_compliance/dns_suite.py` | 14 | `docs/dnssec-suite-implementation.md` |

### ❌ Not Yet Implemented Suites

| # | Suite | Cases | Spec Source | Notes |
|---|---|---|---|---|
| 6 | **StandardEPP** | 26 | `inc/epp/cases.yaml` | Largest remaining suite. `EppClient` helper exists but no per-case checkers. |
| 7 | **StandardIDN** | 2 | `inc/idn/cases.yaml` | `idn-01` (IDN label validation), `idn-02` (ASCII-only TLD rejection) |
| 8 | **StandardSRSGateway** | 14 | `inc/srsgw/cases.yaml` | Gateway synchronization tests (`srsgw-01`…`06`, `08`…`15`; `07` merged into `06`) |
| 9 | **MinimumRPMs** | 3 | `inc/minimum-rpms/cases.yaml` | Rights Protection Mechanisms (`minimumRPMs-01`…`03`) |
| 10 | **StandardIntegrationTest** | 5 | `inc/integration/cases.yaml` | End-to-end integration (`integration-01`…`05`) |

### ⚠️ Shared/Overlap Suite

| # | Suite | Cases | Notes |
|---|---|---|---|
| 11 | **AdditionalDNSTransports** | 1 | Reuses `dns-zz-consistency` from StandardDNS. Full DoT/DoH/DoQ probing not yet implemented. |

---

## Detailed Test Case Inventory

### 1. StandardDNS — 35 cases ✅

Zonemaster-derived (33) + custom (2). Pattern: `^dns-`

| Module | Cases | Checker Classes |
|---|---|---|
| Address | `dns-address01`…`03` | `DnsAddress01Checker`…`DnsAddress03Checker` |
| Connectivity | `dns-connectivity02`…`03` | `DnsConnectivity02Checker`…`DnsConnectivity03Checker` |
| Consistency | `dns-consistency02`…`06` | `DnsConsistency02Checker`…`DnsConsistency06Checker` |
| Delegation | `dns-delegation01`…`05`, `07` | `DnsDelegation01Checker`…`DnsDelegation07Checker` |
| Nameserver | `dns-nameserver01`…`02`, `04`…`06`, `08`…`14` | `DnsNameserver01Checker`…`DnsNameserver14Checker` |
| Syntax | `dns-syntax05`…`07` | `DnsSyntax05Checker`…`DnsSyntax07Checker` |
| Zone | `dns-zone07`, `10` | `DnsZone07Checker`, `DnsZone10Checker` |
| Custom | `dns-zz-idna2008-compliance` | `DnsIdna2008ComplianceChecker` |
| Custom | `dns-zz-consistency` | `DnsConsistencyChecker` |

### 2. StandardDNSSEC — 14 cases ✅

Zonemaster-derived (11) + custom RST (3). Pattern: `^dnssec-`

| Category | Cases | Checker Classes |
|---|---|---|
| Zonemaster | `dnssec-01`…`06`, `08`…`10`, `13`…`14` | `Dnssec01Checker`…`Dnssec14Checker` |
| Custom | `dnssec-91` (signing algo ≥ 8) | `Dnssec91Checker` |
| Custom | `dnssec-92` (DS digest not SHA-1/GOST) | `Dnssec92Checker` |
| Custom | `dnssec-93` (NSEC3 iterations=0) | `Dnssec93Checker` |

**Skipped** per `zonemaster-test-policies.yaml`: dnssec07, 11, 12, 15, 16, 17, 18.

### 3. StandardRDAP — 12 cases ✅

Pattern: `^rdap-`

| Category | Cases | Checker Classes |
|---|---|---|
| GET queries | `rdap-01`…`04` | `DomainQueryChecker`, `NameserverQueryChecker`, `EntityQueryChecker`, `HelpQueryChecker` |
| HEAD tests | `rdap-05`…`07` | `DomainHeadChecker`, `NameserverHeadChecker`, `EntityHeadChecker` |
| Non-existent | `rdap-08`…`10` | `NonExistentDomainChecker`, `NonExistentNameserverChecker`, `NonExistentEntityChecker` |
| TLS | `rdap-91` | `TlsConformanceChecker` |
| Consistency | `rdap-92` | `ServicePortConsistencyChecker` |

### 4. StandardRDE — 14 cases ✅

Pattern: `^rde-`

| Category | Cases | Checker Classes |
|---|---|---|
| File validation | `rde-01`…`03` | `Rde01FilenameChecker`, `Rde02SignatureChecker`, `Rde03DecryptionChecker` |
| Format validation | `rde-04`…`06` | `Rde04XmlCsvChecker`, `Rde05ObjectTypesChecker`, `Rde06ObjectCountsChecker` |
| Object validation | `rde-07`…`12` | `Rde07DomainChecker`…`Rde12NndnChecker` |
| Metadata | `rde-13`…`14` | `Rde13EppParamsChecker`, `Rde14PolicyChecker` |

### 5. DNSSECOperations — 3 cases ✅

Pattern: `^dnssecOps`

| Case | Summary | Checker Class |
|---|---|---|
| `dnssecOps01-ZSKRollover` | ZSK rollover (48h monitoring, RFC 6781 §4.1.1) | `DnssecOps01ZskRolloverChecker` |
| `dnssecOps02-KSKRollover` | KSK/CSK rollover (RFC 6781 §4.1.2) | `DnssecOps02KskRolloverChecker` |
| `dnssecOps03-AlgorithmRollover` | Algorithm rollover (RFC 6781 §4.1.4) | `DnssecOps03AlgorithmRolloverChecker` |

### 6. StandardEPP — 26 cases ❌

Pattern: `^epp-`. Existing helper: `EppClient` (mTLS transport + command assessment).

| Case | Summary |
|---|---|
| `epp-01` | Service connectivity (TLS, A/AAAA, ciphers) |
| `epp-02` | Protocol conformance (greeting validation) |
| `epp-03` | Authentication (login/mTLS) |
| `epp-04` | Domain `<check>` command |
| `epp-05` | Host `<check>` command |
| `epp-06` | Contact `<check>` command |
| `epp-07` | Contact `<create>` command |
| `epp-08` | Contact access control |
| `epp-09` | Contact `<update>` command |
| `epp-10` | Contact `<delete>` command |
| `epp-11` | Host `<create>` command |
| `epp-12` | Host access control |
| `epp-13` | Host `<update>` command |
| `epp-14` | Domain `<create>` command |
| `epp-15` | Registry object integrity |
| `epp-16` | Domain `<update>` command |
| `epp-17` | Service port consistency |
| `epp-18` | Domain `<renew>` command |
| `epp-19` | Domain `<transfer>` (approve) |
| `epp-20` | Domain `<transfer>` (reject) |
| `epp-21` | Domain `<delete>` command |
| `epp-23` | Host rename |
| `epp-24` | Host `<delete>` command |
| `epp-25` | Subordinate host `<create>` |
| `epp-26` | Wide glue host access control |
| `epp-27` | Glueless internal host access control |

(`epp-22` is commented out in spec — domain restore test)

### 7. StandardIDN — 2 cases ❌

| Case | Summary |
|---|---|
| `idn-01` | IDN label validation via EPP `<create>` using configured IDN tables |
| `idn-02` | ASCII-only label rejection for IDN-only TLDs |

### 8. StandardSRSGateway — 14 cases ❌

| Case | Summary |
|---|---|
| `srsgw-01` | EPP connectivity to gateway |
| `srsgw-02` | EPP greeting validation |
| `srsgw-03` | EPP authentication |
| `srsgw-04` | Domain lifecycle sync (create → RDAP/DNS) |
| `srsgw-05` | Host lifecycle sync |
| `srsgw-06` | Contact lifecycle sync (includes `srsgw-07`) |
| `srsgw-08` | Domain `<update>` sync |
| `srsgw-09` | Domain `<renew>` sync |
| `srsgw-10` | Domain `<transfer>` sync |
| `srsgw-11` | Domain `<delete>` sync |
| `srsgw-12` | DNSSEC sync |
| `srsgw-13` | RDE deposit from gateway |
| `srsgw-14` | RDAP response consistency |
| `srsgw-15` | IDN sync (if applicable) |

### 9. MinimumRPMs — 3 cases ❌

| Case | Summary |
|---|---|
| `minimumRPMs-01` | Claims notice implementation |
| `minimumRPMs-02` | Sunrise registration |
| `minimumRPMs-03` | Trademark Claims (TMCH) |

### 10. StandardIntegrationTest — 5 cases ❌

| Case | Summary |
|---|---|
| `integration-01` | EPP → DNS propagation (domain create → NS query within SLA) |
| `integration-02` | EPP → RDAP propagation (domain create → RDAP query within SLA) |
| `integration-03` | EPP → RDE deposit (objects appear in escrow within 24h) |
| `integration-04` | Narrow glue integration (if applicable) |
| `integration-05` | Host attribute integration (if applicable) |

### 11. AdditionalDNSTransports — 1 case ⚠️

Reuses `dns-zz-consistency` from StandardDNS. Currently only UDP/TCP probing
implemented; full DoT (RFC 7858), DoH (RFC 8484), DoQ (RFC 9250) not yet
supported.

---

## Architecture

All implemented suites follow a consistent dependency-injection pattern:

```
┌──────────────────────┐     ┌─────────────────────┐
│    Suite Config       │────▶│   Checker Classes    │
│  (DnsSuiteConfig,    │     │  (one per test case) │
│   RdapSuiteConfig,   │     │                     │
│   RdeSuiteConfig)    │     │  .run() → TestResult │
└──────────────────────┘     └─────────────────────┘
                                       │
                              ┌────────▼────────┐
                              │  Pluggable I/O   │
                              │  DnsQuerier      │
                              │  RdapHttpClient  │
                              │  TlsProber       │
                              │  ZoneTransferCli │
                              │  RdeDepositParser│
                              └─────────────────┘
```

| Component | Purpose |
|---|---|
| `*SuiteConfig` | Frozen dataclass with all input parameters |
| `*Checker` | One class per test case, accepts `(config, *, querier/client/parser)` |
| `*TestResult` / `*TestError` | Structured result with spec-matching error codes |
| `Standard*TestSuite` | Runner that executes all checkers via `run_all()` |
| Pluggable I/O | Override in tests with stubs; inject real clients in production |

---

## File Index

### Source Files

| File | Suites Covered |
|---|---|
| `src/rst_compliance/dns_suite.py` | StandardDNS (35), StandardDNSSEC (14), DNSSECOperations (3) |
| `src/rst_compliance/rdap_conformance.py` | StandardRDAP (12) |
| `src/rst_compliance/rde_suite.py` | StandardRDE (14) |
| `src/rst_compliance/epp_client.py` | EPP transport/helper only (no per-case checkers) |
| `src/rst_compliance/dnssec_zone_health.py` | DNSSEC zone health CLI helper |

### Test Files

| File | Tests | Suites |
|---|---|---|
| `tests/test_dns_suite.py` | 82 | StandardDNS, StandardDNSSEC, DNSSECOperations |
| `tests/test_rdap_full_suite.py` | 55 | StandardRDAP (rdap-01…91) |
| `tests/test_rdap_service_port_consistency.py` | 34 | StandardRDAP (rdap-92) |
| `tests/test_rdap_conformance.py` | 10 | RDAP payload validation |
| `tests/test_rde_suite.py` | 41 | StandardRDE |
| `tests/test_rde_deposit_helper.py` | 5 | RDE deposit helper |
| `tests/test_dnssec_zone_health.py` | 3 | DNSSEC zone health |
| `tests/test_epp_host_constraints.py` | 5 | EPP host/mTLS |
| `tests/test_rst_triggers.py` | 4 | RST API client |
| `tests/test_rst_dashboard.py` | 7 | Dashboard |
| `tests/test_schema_validation.py` | 4 | Schema validation |
| `tests/test_fips_check.py` | 2 | FIPS 140-3 |
| `tests/test_testcase_log.py` | 1 | Test case log |

### Documentation

| File | Content |
|---|---|
| `docs/implementation-overview.md` | This file — complete status overview |
| `docs/dns-suite-implementation.md` | StandardDNS details |
| `docs/dnssec-suite-implementation.md` | StandardDNSSEC + DNSSECOperations details |
| `docs/rdap-suite-implementation.md` | StandardRDAP details |
| `docs/rde-suite-implementation.md` | StandardRDE details |

---

## Priority Backlog (Not Yet Implemented)

| Priority | Suite | Cases | Complexity | Dependencies |
|---|---|---|---|---|
| 1 | **StandardEPP** | 26 | High — CRUD lifecycle for domains/hosts/contacts, mTLS, transfer, renew | `EppClient` exists; needs per-case checkers |
| 2 | **StandardIntegrationTest** | 5 | High — cross-service (EPP→DNS, EPP→RDAP, EPP→RDE) | Requires EPP + DNS + RDAP + RDE suites |
| 3 | **StandardSRSGateway** | 14 | High — dual-registry sync (primary ↔ gateway) | Requires EPP + RDAP infrastructure |
| 4 | **MinimumRPMs** | 3 | Medium — TMCH integration, sunrise/claims | Requires EPP + TMCH test materials |
| 5 | **StandardIDN** | 2 | Medium — IDN table + EPP create/reject | Requires EPP infrastructure |
| 6 | **AdditionalDNSTransports** | 1 | Low — extend `DnsConsistencyChecker` with DoT/DoH/DoQ | Requires DNS client libraries |
