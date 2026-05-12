# RST v2026.04 Test Suite — Implementation Overview

## Summary

This document tracks the implementation status of all 11 RST v2026.04 test
suites. The formerly pending suites now have data-driven checker
implementations; live network collection remains a harness concern.

| Status | Suites | Test Cases | Unit Tests |
|--------|--------|------------|------------|
| ✅ Implemented checker suites | 10 | 128 | 301 |
| ❌ Not implemented | 0 | 0 | — |
| ⚠️ Shared/overlap | 1 | (1) | covered by DNS tests |
| **Total** | **11** | **128+** | **301** |

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
| 6 | **StandardEPP** | 26 | `src/rst_compliance/epp_client.py` + internal tests | 55 | `docs/epp-test-case-summary.md` |
| 7 | **StandardIDN** | 2 | `src/rst_compliance/idn_suite.py` | 4 | `docs/pending-suite-implementation.md` |
| 8 | **StandardSRSGateway** | 14 | `src/rst_compliance/srsgw_suite.py` | 6 | `docs/pending-suite-implementation.md` |
| 9 | **MinimumRPMs** | 3 | `src/rst_compliance/minimum_rpms_suite.py` | 5 | `docs/pending-suite-implementation.md` |
| 10 | **StandardIntegrationTest** | 5 | `src/rst_compliance/integration_suite.py` | 7 | `docs/pending-suite-implementation.md` |

### ⚠️ Shared/Overlap Suite

| # | Suite | Cases | Notes |
|---|---|---|---|
| 11 | **AdditionalDNSTransports** | 1 | Reuses `dns-zz-consistency`; optional transport labels are supplied through `DnsSuiteConfig.additional_transports`. |

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

### 6. StandardEPP — 26 cases ✅

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

### 7. StandardIDN — 2 cases ✅

| Case | Summary |
|---|---|
| `idn-01` | IDN label validation via EPP `<create>` using configured IDN tables |
| `idn-02` | ASCII-only label rejection for IDN-only TLDs |

Implemented in `src/rst_compliance/idn_suite.py` as observation-driven
checkers for generated IDN label attempts and variant policy outcomes.

### 8. StandardSRSGateway — 14 cases ✅

| Case | Summary |
|---|---|
| `srsgw-01` | IPv4 and IPv6 gateway connectivity |
| `srsgw-02` | Host `<create>` synchronization (if applicable) |
| `srsgw-03` | Contact `<create>` synchronization (if applicable) |
| `srsgw-04` | Domain `<create>` synchronization |
| `srsgw-05` | Domain `<renew>` synchronization |
| `srsgw-06` | Domain `<transfer>` synchronization |
| `srsgw-08` | Domain `<delete>` synchronization |
| `srsgw-09` | Host `<update>` synchronization (if applicable) |
| `srsgw-10` | Host `<delete>` synchronization (if applicable) |
| `srsgw-11` | Contact `<update>` synchronization (if applicable) |
| `srsgw-12` | Contact `<delete>` synchronization (if applicable) |
| `srsgw-13` | Domain RDAP synchronization |
| `srsgw-14` | Nameserver RDAP synchronization |
| `srsgw-15` | Registrar RDAP synchronization |

Implemented in `src/rst_compliance/srsgw_suite.py` as observation-driven
connectivity, EPP synchronization, and RDAP synchronization checkers.

### 9. MinimumRPMs — 3 cases ✅

| Case | Summary |
|---|---|
| `minimumRPMs-01` | Claims notice implementation |
| `minimumRPMs-02` | Sunrise registration |
| `minimumRPMs-03` | Trademark Claims (TMCH) |

Implemented in `src/rst_compliance/minimum_rpms_suite.py` as observation-driven
claims check, sunrise create, and trademark claims create checkers.

### 10. StandardIntegrationTest — 5 cases ✅

| Case | Summary |
|---|---|
| `integration-01` | EPP → DNS propagation (domain create → NS query within SLA) |
| `integration-02` | EPP → RDAP propagation (domain create → RDAP query within SLA) |
| `integration-03` | EPP → RDE deposit (objects appear in escrow within 24h) |
| `integration-04` | Narrow glue integration (if applicable) |
| `integration-05` | Host attribute integration (if applicable) |

Implemented in `src/rst_compliance/integration_suite.py` as observation-driven
EPP to RDAP/DNS/RDE propagation and glue policy checkers.

### 11. AdditionalDNSTransports — 1 case ⚠️

Reuses `dns-zz-consistency` from StandardDNS. UDP/TCP remain default, and
additional transport labels such as DoT, DoH, and DoQ can be supplied through
`DnsSuiteConfig.additional_transports`.

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
| `src/rst_compliance/epp_client.py` | EPP transport/helper and shared command assessment helpers |
| `src/rst_compliance/idn_suite.py` | StandardIDN (2) |
| `src/rst_compliance/minimum_rpms_suite.py` | MinimumRPMs (3) |
| `src/rst_compliance/integration_suite.py` | StandardIntegrationTest (5) |
| `src/rst_compliance/srsgw_suite.py` | StandardSRSGateway (14) |
| `src/rst_compliance/dnssec_zone_health.py` | DNSSEC zone health CLI helper |

### Test Files

| File | Tests | Suites |
|---|---|---|
| `tests/test_dns_suite.py` | 83 | StandardDNS, StandardDNSSEC, DNSSECOperations, AdditionalDNSTransports |
| `tests/test_rdap_full_suite.py` | 55 | StandardRDAP (rdap-01…91) |
| `tests/test_rdap_service_port_consistency.py` | 34 | StandardRDAP (rdap-92) |
| `tests/test_rdap_conformance.py` | 15 | RDAP payload validation |
| `tests/test_rde_suite.py` | 41 | StandardRDE |
| `tests/test_rde_deposit_helper.py` | 10 | RDE deposit helper |
| `tests/test_idn_suite.py` | 4 | StandardIDN |
| `tests/test_minimum_rpms_suite.py` | 5 | MinimumRPMs |
| `tests/test_integration_suite.py` | 7 | StandardIntegrationTest |
| `tests/test_srsgw_suite.py` | 6 | StandardSRSGateway |
| `tests/test_dnssec_zone_health.py` | 3 | DNSSEC zone health |
| `tests/test_epp_connectivity.py` | 4 | EPP connectivity |
| `tests/test_epp_host_constraints.py` | 13 | EPP host/mTLS |
| `tests/test_rst_triggers.py` | 4 | RST API client |
| `tests/test_rst_dashboard.py` | 10 | Dashboard |
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
| `docs/pending-suite-implementation.md` | StandardIDN, MinimumRPMs, StandardIntegrationTest, StandardSRSGateway, and additional transport details |

---

## Follow-up Backlog

| Priority | Area | Scope | Dependencies |
|---|---|---|---|
| 1 | Live harness adapters | Produce observation dataclasses from real EPP, DNS, RDAP, RDE, TMCH, and SRS Gateway systems | Applicant credentials and resources |
| 2 | Dashboard defaults | Add internal checker smoke tests or dashboard coverage summaries for the new suite families | `internal-rst-checker/tests` conventions |
| 3 | Fixture depth | Expand protocol payload fixtures for EPP extensions, IDN variants, and TMCH negative paths | Realistic conformance fixtures |
| 4 | Additional DNS transports | Wire DoT/DoH/DoQ labels to concrete resolver implementations | DNS client libraries |
