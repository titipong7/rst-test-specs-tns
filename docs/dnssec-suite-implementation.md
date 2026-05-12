# StandardDNSSEC + DNSSECOperations Test Suites — Implementation Summary

## Test Cases Implemented

### StandardDNSSEC Suite (14 test cases matching `^dnssec-`)

#### Zonemaster-derived (11 cases)

| Test ID | Summary | Checker Class | Error Code(s) |
|---|---|---|---|
| `dnssec-01` | DS record present for delegation | `Dnssec01Checker` | `ZM_DS01_DS_ALGO_2_MISSING` |
| `dnssec-02` | DS matches a DNSKEY (KSK/CSK) | `Dnssec02Checker` | `ZM_DS02_DNSKEY_NOT_SEP`, `ZM_DS02_NO_DNSKEY_FOR_DS`, `ZM_DS02_NO_MATCHING_DNSKEY_RRSIG` |
| `dnssec-03` | NSEC/NSEC3 present, zone is signed | `Dnssec03Checker` | `ZM_DS03_NO_DNSSEC_SUPPORT` |
| `dnssec-04` | RRSIG lifetime validity | `Dnssec04Checker` | — |
| `dnssec-05` | Algorithm is IANA-registered | `Dnssec05Checker` | `ZM_ALGORITHM_NOT_RECOMMENDED` |
| `dnssec-06` | NSEC/NSEC3 type bitmap coverage | `Dnssec06Checker` | — |
| `dnssec-08` | RRSIG for DNSKEY RRset valid | `Dnssec08Checker` | `ZM_DS02_NO_MATCHING_DNSKEY_RRSIG` |
| `dnssec-09` | SOA RRSIG valid | `Dnssec09Checker` | — |
| `dnssec-10` | All NS respond with DNSSEC data | `Dnssec10Checker` | `ZM_DS05_SERVER_NO_DNSSEC`, `ZM_NO_RESPONSE_DNSKEY` |
| `dnssec-13` | Complete RRSIG algorithm coverage | `Dnssec13Checker` | `ZM_DS13_ALGO_NOT_SIGNED_DNSKEY` |
| `dnssec-14` | DNSKEY RRset signed by valid KSK | `Dnssec14Checker` | — |

**Skipped Zonemaster cases** (per `zonemaster-test-policies.yaml`): dnssec07, dnssec11, dnssec12, dnssec15, dnssec16, dnssec17, dnssec18.

#### Custom RST cases (3 cases)

| Test ID | Summary | Checker Class | Error Code(s) |
|---|---|---|---|
| `dnssec-91` | Signing algorithm ≥ 8 | `Dnssec91Checker` | `DNSSEC_INVALID_SIGNING_ALGORITHM`, `DNSSEC_DNS_QUERY_ERROR` |
| `dnssec-92` | DS digest not SHA-1 (#1) or GOST (#12) | `Dnssec92Checker` | `DNSSEC_INVALID_DIGEST_ALGORITHM` |
| `dnssec-93` | NSEC3 iterations=0, salt=empty (RFC 9276) | `Dnssec93Checker` | `DNSSEC_NSEC3_ITERATIONS_IS_NOT_ZERO`, `DNSSEC_NSEC3_SALT_IS_NOT_EMPTY` |

### DNSSECOperations Suite (3 test cases matching `^dnssecOps`)

| Test ID | Summary | Checker Class | Error Code(s) |
|---|---|---|---|
| `dnssecOps01-ZSKRollover` | ZSK rollover (RFC 6781 §4.1.1) | `DnssecOps01ZskRolloverChecker` | `DNSSEC_OPS_ZSK_ROLLOVER_*`, `DNSSEC_OPS_ZONE_IS_INVALID`, `DNSSEC_OPS_XFR_*`, `DNSSEC_OPS_INVALID_ALGORITHM` |
| `dnssecOps02-KSKRollover` | KSK/CSK rollover (RFC 6781 §4.1.2) | `DnssecOps02KskRolloverChecker` | `DNSSEC_OPS_KSK_ROLLOVER_*`, same shared errors |
| `dnssecOps03-AlgorithmRollover` | Algorithm rollover (RFC 6781 §4.1.4) | `DnssecOps03AlgorithmRolloverChecker` | `DNSSEC_OPS_ALGORITHM_ROLLOVER_*`, same shared errors |

---

## Implementation Details

### Source File

`src/rst_compliance/dns_suite.py`

### Architecture

| Component | Type | Purpose |
|---|---|---|
| `DnsSuiteConfig` | Dataclass | Config for StandardDNSSEC: `nameservers`, `ds_records` |
| `DnssecOpsConfig` | Dataclass | Config for DNSSEC-Ops: `primary_servers`, `tsig_key`, `csk`, `*_rollover_zone` |
| `DnsQuerier` | Class | Pluggable DNS querier (`query_dnskey()`, `query_nsec3param()`, etc.) |
| `ZoneTransferClient` | Class | Pluggable AXFR client for DNSSEC-Ops |
| `StandardDnssecTestSuite` | Class | Runs all 14 DNSSEC test cases |
| `DnssecOperationsTestSuite` | Class | Runs all 3 DNSSEC-Ops test cases |

### DNSSECOperations Execution Flow

```
DnssecOps01ZskRolloverChecker.run()
│
├── If csk=true → SKIP
├── Validate zone name is configured
├── Zone Transfer via ZoneTransferClient
│   ├── Check zone validity
│   ├── Check chain of trust not broken
│   ├── Check rollover completed within 48h
│   └── Check new algorithm ≥ 8
├── SOA query via DnsQuerier (monitoring)
└── Return DnsTestResult with structured errors
```

### Input Parameters

| Parameter | Suite | Used By |
|---|---|---|
| `dns.nameservers` | StandardDNSSEC | All Zonemaster DNSSEC cases |
| `dnssec.dsRecords` | StandardDNSSEC | dnssec-01, dnssec-02, dnssec-91, dnssec-92 |
| `dnssecOps.primaryServers` | DNSSECOperations | All 3 ops cases (zone transfer) |
| `dnssecOps.tsigKey` | DNSSECOperations | AXFR authentication |
| `dnssecOps.csk` | DNSSECOperations | dnssecOps01 skip logic |
| `dnssecOps.zskRolloverZone` | DNSSECOperations | dnssecOps01 |
| `dnssecOps.kskRolloverZone` | DNSSECOperations | dnssecOps02 |
| `dnssecOps.algorithmRolloverZone` | DNSSECOperations | dnssecOps03 |

---

## Test Coverage

### Test File

`tests/test_dns_suite.py` — **82 tests total** (50 DNS + 32 DNSSEC/DNSSEC-Ops)

| Test Class | Count | Coverage |
|---|---|---|
| `TestDnssec01` | 2 | DS present/absent |
| `TestDnssec02` | 2 | SEP key present/absent |
| `TestDnssec03` | 2 | DNSKEY present/absent (zone signed check) |
| `TestDnssec05` | 2 | IANA algorithm / unknown algorithm |
| `TestDnssec08` | 2 | RRSIG present/absent for DNSKEY |
| `TestDnssec10` | 2 | All servers have DNSSEC / server missing DNSSEC |
| `TestDnssec13` | 2 | All algorithms signed / unsigned algorithm |
| `TestDnssec91` | 3 | Algorithm 13 (pass), 5 (fail), 8 (pass) |
| `TestDnssec92` | 3 | SHA-256 (pass), SHA-1 (fail), GOST (fail) |
| `TestDnssec93` | 4 | Valid NSEC3, nonzero iterations, nonempty salt, skip |
| `TestDnssecOps01ZskRollover` | 8 | Success, CSK skip, chain broken, not completed, invalid zone, invalid algorithm, XFR failure, DNS query failure |
| `TestDnssecOps02KskRollover` | 4 | Success, chain broken, not completed, no zone |
| `TestDnssecOps03AlgorithmRollover` | 4 | Success, chain broken, not completed, no zone |
| `TestStandardDnssecTestSuite` | 1 | Runs all 14 cases |
| `TestDnssecOperationsTestSuite` | 1 | Runs all 3 ops cases |

### Relationship to EPP/RDAP/DNS

| DNSSEC Test | Counterpart | Shared Concept |
|---|---|---|
| `dnssec-01` (DS present) | `epp-14` (domain create with DNSSEC) | DS record provisioning |
| `dnssec-05` (IANA algorithm) | `dnssec-91` (algorithm ≥ 8) | Algorithm validation (91 is stricter) |
| `dnssec-10` (all NS have DNSSEC) | `rdap-92` / `epp-17` | Cross-server consistency |
| `dnssecOps01` (ZSK rollover) | — | Operational procedure |
| `dnssecOps02` (KSK rollover) | — | Operational procedure |
| `dnssecOps03` (algorithm rollover) | — | Operational procedure |
