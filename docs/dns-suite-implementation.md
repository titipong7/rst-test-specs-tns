# StandardDNS + StandardDNSSEC Test Suite — Implementation Summary

## Test Cases Implemented

### StandardDNS Suite (35 test cases matching `^dns-`)

| Test ID | Module | Summary | Checker Class | Error Code(s) |
|---|---|---|---|---|
| `dns-address01` | Address | Name server address must be globally routable | `DnsAddress01Checker` | `ZM_A01_ADDR_NOT_GLOBALLY_REACHABLE` |
| `dns-address02` | Address | Reverse DNS entry exists | `DnsAddress02Checker` | `ZM_A_UNEXPECTED_RCODE` |
| `dns-address03` | Address | Address not in IANA special-purpose range | `DnsAddress03Checker` | `ZM_A01_DOCUMENTATION_ADDR`, `ZM_A01_LOCAL_USE_ADDR` |
| `dns-connectivity02` | Connectivity | Nameservers in more than one AS | `DnsConnectivity02Checker` | `ZM_IPV4_ONE_ASN`, `ZM_IPV6_ONE_ASN` |
| `dns-connectivity03` | Connectivity | Both IPv4 and IPv6 required | `DnsConnectivity03Checker` | `ZM_NO_IPV4_NS_CHILD`, `ZM_NO_IPV6_NS_CHILD` |
| `dns-consistency02` | Consistency | SOA RNAME consistency | `DnsConsistency02Checker` | `ZM_MULTIPLE_SOA_RNAMES` |
| `dns-consistency03` | Consistency | SOA timers consistency | `DnsConsistency03Checker` | `ZM_MULTIPLE_SOA_TIME_PARAMETER_SET` |
| `dns-consistency04` | Consistency | NS set consistency | `DnsConsistency04Checker` | `ZM_MULTIPLE_NS_SET` |
| `dns-consistency05` | Consistency | SOA MNAME consistency | `DnsConsistency05Checker` | `ZM_MULTIPLE_SOA_MNAMES` |
| `dns-consistency06` | Consistency | SOA serial consistency | `DnsConsistency06Checker` | `ZM_MULTIPLE_SOA_SERIALS` |
| `dns-delegation01` | Delegation | Minimum two nameservers | `DnsDelegation01Checker` | `ZM_CHILD_NS_FAILED` |
| `dns-delegation02` | Delegation | NS IP not in private range | `DnsDelegation02Checker` | `ZM_NAMESERVER_IP_PRIVATE_NETWORK` |
| `dns-delegation03` | Delegation | No truncation without EDNS | `DnsDelegation03Checker` | `ZM_REFERRAL_SIZE_TOO_LARGE` |
| `dns-delegation04` | Delegation | Nameservers are authoritative | `DnsDelegation04Checker` | `ZM_CHILD_ZONE_LAME`, `ZM_NO_RESPONSE` |
| `dns-delegation05` | Delegation | NS name is a hostname (not IP) | `DnsDelegation05Checker` | `ZM_NS_ERROR` |
| `dns-delegation07` | Delegation | Parent-child NS consistency | `DnsDelegation07Checker` | `ZM_EXTRA_ADDRESS_CHILD` |
| `dns-nameserver01` | Nameserver | Not a recursor | `DnsNameserver01Checker` | — |
| `dns-nameserver02` | Nameserver | EDNS support | `DnsNameserver02Checker` | `ZM_NO_EDNS_SUPPORT` |
| `dns-nameserver04` | Nameserver | Same source address | `DnsNameserver04Checker` | `ZM_DIFFERENT_SOURCE_IP` |
| `dns-nameserver05` | Nameserver | AAAA query behaviour | `DnsNameserver05Checker` | — |
| `dns-nameserver06` | Nameserver | NS name can be resolved | `DnsNameserver06Checker` | — |
| `dns-nameserver08` | Nameserver | QNAME case sensitivity | `DnsNameserver08Checker` | — |
| `dns-nameserver09` | Nameserver | Unknown OPCODE handling | `DnsNameserver09Checker` | — |
| `dns-nameserver10` | Nameserver | EDNS version negotiation | `DnsNameserver10Checker` | `ZM_N10_UNEXPECTED_RCODE` |
| `dns-nameserver11` | Nameserver | Unknown EDNS option handling | `DnsNameserver11Checker` | `ZM_N11_*` |
| `dns-nameserver12` | Nameserver | Unknown EDNS flag handling | `DnsNameserver12Checker` | `ZM_Z_FLAGS_NOTCLEAR` |
| `dns-nameserver13` | Nameserver | Not an open resolver | `DnsNameserver13Checker` | — |
| `dns-nameserver14` | Nameserver | Unknown EDNS data handling | `DnsNameserver14Checker` | `ZM_UNKNOWN_OPTION_CODE` |
| `dns-syntax05` | Syntax | SOA RNAME valid mailbox | `DnsSyntax05Checker` | `ZM_RNAME_MISUSED_AT_SIGN` |
| `dns-syntax06` | Syntax | SOA RNAME not localhost | `DnsSyntax06Checker` | `ZM_RNAME_MAIL_DOMAIN_LOCALHOST` |
| `dns-syntax07` | Syntax | SOA MNAME resolvable | `DnsSyntax07Checker` | — |
| `dns-zone07` | Zone | SOA MNAME in NS records | `DnsZone07Checker` | — |
| `dns-zone10` | Zone | Valid SOA RNAME | `DnsZone10Checker` | `ZM_RNAME_RFC822_INVALID` |
| `dns-zz-idna2008-compliance` | Custom | IDNA2008 compliance of apex names | `DnsIdna2008ComplianceChecker` | `DNS_IDNA2008_*` |
| `dns-zz-consistency` | Custom | Cross-vantage-point consistency | `DnsConsistencyChecker` | `DNS_CONSISTENCY_*`, `DNS_INCONSISTENT_*` |

### StandardDNSSEC Suite (3 custom test cases matching `^dnssec-`)

| Test ID | Summary | Checker Class | Error Code(s) |
|---|---|---|---|
| `dnssec-91` | Signing algorithm ≥ 8 | `Dnssec91Checker` | `DNSSEC_INVALID_SIGNING_ALGORITHM`, `DNSSEC_DNS_QUERY_ERROR` |
| `dnssec-92` | DS digest not SHA-1 or GOST | `Dnssec92Checker` | `DNSSEC_INVALID_DIGEST_ALGORITHM` |
| `dnssec-93` | NSEC3 iterations=0, salt=empty | `Dnssec93Checker` | `DNSSEC_NSEC3_ITERATIONS_IS_NOT_ZERO`, `DNSSEC_NSEC3_SALT_IS_NOT_EMPTY` |

All test cases can be run via `StandardDnsTestSuite.run_all()` and
`StandardDnssecTestSuite.run_all()`.

---

## Implementation Details

### Source File

`src/rst_compliance/dns_suite.py`

### Architecture

| Component | Type | Purpose |
|---|---|---|
| **Shared types** | | |
| `DnsSuiteConfig` | Dataclass | Unified config: `nameservers`, `ds_records`, `glue_policy`, `timeout_seconds` |
| `DnsQuerier` | Class | Pluggable DNS querier with `query()`, `query_soa()`, `query_ns()`, `query_dnskey()`, `query_nsec3param()` |
| `DnsQueryResult` | Dataclass | Query result: `rcode`, `answer`, `authority`, `additional`, `flags`, `edns` |
| `DnsTestResult` / `DnsTestError` | Dataclass | Structured result/error types matching RDAP pattern |
| **35 DNS checker classes** | Class | One per test case, all accept `(config, querier=)` |
| **3 DNSSEC checker classes** | Class | dnssec-91, dnssec-92, dnssec-93 |
| `StandardDnsTestSuite` | Class | Runs all 35 DNS test cases |
| `StandardDnssecTestSuite` | Class | Runs all 3 DNSSEC custom cases |

### Input Parameters

| Parameter | Source | Used By |
|---|---|---|
| `dns.nameservers` | `inc/dns/inputs.yaml` | All DNS test cases |
| `dns.gluePolicy` | `inc/dns/inputs.yaml` | Delegation tests, EPP integration |
| `dnssec.dsRecords` | `inc/dnssec/inputs.yaml` | dnssec-91, dnssec-92 |

### Zonemaster Module Mapping

The StandardDNS test cases map to Zonemaster modules as follows (skipped
test cases from `zonemaster-test-policies.yaml` are excluded):

| Zonemaster Module | Test Cases Included | Test Cases Skipped |
|---|---|---|
| Address | address01, address02, address03 | — |
| Connectivity | connectivity02, connectivity03 | connectivity01, connectivity04 |
| Consistency | consistency02-06 | consistency01 |
| Delegation | delegation01-05, delegation07 | delegation06 |
| Nameserver | nameserver01-02, 04-06, 08-14 | nameserver03, 07, 15 |
| Syntax | syntax05-07 | syntax01-04, syntax08 |
| Zone | zone07, zone10 | zone01-06, 08-09, 11 |
| DNSSEC | *(in StandardDNSSEC suite)* | dnssec07, 11-12, 15-18 |

### Relationship to EPP and RDAP

| DNS/DNSSEC Test | EPP/RDAP Counterpart | Shared Concept |
|---|---|---|
| `dns-address01` (globally routable) | `epp-01` (service port reachable) | Network accessibility |
| `dns-connectivity03` (IPv4+IPv6) | `epp-01` (A+AAAA records) | Dual-stack requirement |
| `dns-delegation01` (min 2 NS) | — | DNS-specific |
| `dns-zz-consistency` (cross-port) | `rdap-92` / `epp-17` | Response consistency |
| `dns-zz-idna2008-compliance` | — | DNS-specific |
| `dnssec-91` (signing algorithm) | — | DNSSEC-specific |
| `dnssec-92` (digest algorithm) | — | DNSSEC-specific |
| `dnssec-93` (NSEC3 params) | — | DNSSEC-specific |

### Usage Example

```python
from rst_compliance.dns_suite import (
    DnsSuiteConfig,
    StandardDnsTestSuite,
    StandardDnssecTestSuite,
)

config = DnsSuiteConfig(
    nameservers=[{
        "name": "example",
        "nameservers": [
            {"name": "ns1.example.com", "v4Addrs": ["93.184.216.34"],
             "v6Addrs": ["2001:500:8d::53"]},
            {"name": "ns2.example.net", "v4Addrs": ["93.184.216.35"],
             "v6Addrs": ["2001:500:8e::53"]},
        ],
    }],
    ds_records=[{
        "name": "example",
        "dsRecords": [{"keyTag": 12345, "alg": 13, "digestType": 2, "digest": "AABB"}],
    }],
)

dns_results = StandardDnsTestSuite(config).run_all()
dnssec_results = StandardDnssecTestSuite(config).run_all()

for r in dns_results + dnssec_results:
    status = "SKIP" if r.skipped else ("PASS" if r.passed else "FAIL")
    print(f"  {r.test_id}: {status}")
    for e in r.errors:
        if e.severity != "INFO":
            print(f"    [{e.severity}] {e.code}: {e.detail}")
```

---

## Test Coverage

### Test File

`tests/test_dns_suite.py` — **50 tests**

| Test Class | Count | Coverage |
|---|---|---|
| `TestDnsAddress01` | 3 | Globally routable, private, loopback |
| `TestDnsAddress03` | 2 | Documentation address, local-use |
| `TestDnsConnectivity02` | 2 | Multiple ASNs, single ASN |
| `TestDnsConnectivity03` | 3 | Both families, no IPv6, no IPv4 |
| `TestDnsConsistency06` | 2 | Consistent serials, multiple serials |
| `TestDnsDelegation01` | 2 | Two NS pass, one NS fail |
| `TestDnsDelegation02` | 2 | Public pass, private fail |
| `TestDnsDelegation04` | 2 | Authoritative pass, lame fail |
| `TestDnsDelegation05` | 2 | Hostname pass, IP-as-name fail |
| `TestDnsNameserver02` | 2 | EDNS supported, no EDNS |
| `TestDnsSyntax05` | 2 | Valid RNAME, @ sign in RNAME |
| `TestDnsSyntax06` | 2 | Normal RNAME, localhost RNAME |
| `TestDnsZone10` | 2 | Valid RNAME, empty RNAME |
| `TestDnsIdna2008Compliance` | 3 | Compliant, invalid MNAME, query failure |
| `TestDnsConsistency` | 3 | Consistent, inconsistent RCODE, query failure |
| `TestDnssec91` | 3 | Algorithm 13, algorithm 5 (fail), algorithm 8 |
| `TestDnssec92` | 3 | SHA-256, SHA-1 (fail), GOST (fail) |
| `TestDnssec93` | 4 | Valid NSEC3, nonzero iterations, nonempty salt, no NSEC3 (skip) |
| `TestDnsTestResult` | 3 | Initial state, skip, add_error |
| `TestStandardDnsTestSuite` | 2 | Runs all 35 cases, all pass |
| `TestStandardDnssecTestSuite` | 1 | Runs all 3 cases |
