# rdap-92: Service Port Consistency Check — Implementation Summary

## Test Case Specification

**Test ID:** `rdap-92`
**Summary:** Service port consistency check
**Maturity:** GAMMA
**Implemented:** true

### Description

This test confirms that all RDAP service ports return identical responses.

Since applicants must provide an RDAP service over both IPv4 and IPv6, at
least two service ports will be checked.

The client will establish separate connections to each RDAP service port
(defined as an IP address and TCP port, where at least one IPv4 address/port
pair and IPv6 address/port pair are expected) and perform RDAP queries on
the objects specified in the `rdap.testDomains`, `rdap.testEntities`, and
`rdap.testNameservers` input parameters.

The responses returned by each service port (1) **MUST** have the 200 status
code, and (2) **MUST**, with the exception of the `last update of RDAP
database` event, be consistent, once the JSON body has been parsed and
canonicalised. The values that appear in the `entities`, `events`,
`notices`, `remarks`, `links`, `rdapConformance`, `publicIDs`, `status`,
`ipAddresses`, `nameservers` and `redactions` properties of the response may
(if present) appear in any order.

### Input Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `rdap.baseURLs` | `array` | **Yes** | RDAP base URL(s) for the TLD(s). One per TLD. |
| `rdap.testDomains` | `array` | **Yes** | Domain names to query for domain response validation. |
| `rdap.testEntities` | `array` | **Yes** | Entity handles to query for entity response validation. |
| `rdap.testNameservers` | `array` | **Yes** | Nameservers to query for nameserver response validation. |

### Errors

| Error Code | Severity | Description |
|---|---|---|
| `RDAP_TLS_DNS_RESOLUTION_ERROR` | ERROR | An error occurred during DNS resolution of one of the RDAP base URL(s). |
| `RDAP_TLS_SERVICE_PORT_UNREACHABLE` | ERROR | A service port was not reachable. If all service ports are unreachable, then the test case will fail. |
| `RDAP_TLS_NO_SERVICE_PORTS_REACHABLE` | CRITICAL | No service ports could be reached. |
| `RDAP_QUERY_FAILED` | ERROR | An RDAP query that should have been successful produced an error response or could not be completed. |
| `RDAP_SERVICE_PORT_NOT_CONSISTENT` | ERROR | The responses received are not consistent across all service ports. |

---

## Implementation Details

### Source File

`src/rst_compliance/rdap_conformance.py`

### Components Added

| Component | Type | Purpose |
|---|---|---|
| `ServicePortConsistencyChecker` | Class | Main orchestrator — resolves DNS, queries service ports, canonicalizes responses, and compares for consistency. |
| `Rdap92Config` | Dataclass | Configuration: `base_urls`, `test_domains`, `test_entities`, `test_nameservers`, `timeout_seconds`. |
| `DnsResolver` | Class | Pluggable DNS resolution using `socket.getaddrinfo` for both IPv4 (`AF_INET`) and IPv6 (`AF_INET6`). |
| `RdapServicePortQuerier` | Class | Performs RDAP queries against a specific service port with correct `Host` header routing. |
| `canonicalize_rdap_response()` | Function | Produces a canonical form of an RDAP response for comparison. |
| `ServicePort` | Dataclass (frozen) | Represents an (ip, port, address_family) tuple. |
| `Rdap92Result` | Dataclass | Aggregated result with `passed` flag, `errors` list, and `service_ports_checked`. |
| `Rdap92Error` | Dataclass (frozen) | Structured error with `code`, `severity`, and `detail` fields. |

### Execution Flow

```
ServicePortConsistencyChecker.run()
│
├── For each base URL in config.base_urls:
│   │
│   ├── 1. DNS Resolution
│   │   └── DnsResolver.resolve(hostname, port)
│   │       ├── Query AF_INET  (IPv4 A records)
│   │       └── Query AF_INET6 (IPv6 AAAA records)
│   │       → Returns list[ServicePort]
│   │
│   ├── 2. Build Query Paths (filtered by TLD)
│   │   ├── domain/{name}      ← from rdap.testDomains
│   │   ├── entity/{handle}    ← from rdap.testEntities
│   │   └── nameserver/{name}  ← from rdap.testNameservers
│   │
│   └── 3. For each query path:
│       │
│       ├── Query each service port
│       │   └── RdapServicePortQuerier.query(base_url, service_port, path)
│       │       ├── Returns 200 → collect response
│       │       ├── Non-200     → RDAP_QUERY_FAILED
│       │       └── Unreachable → RDAP_TLS_SERVICE_PORT_UNREACHABLE
│       │
│       ├── Canonicalize each response
│       │   └── canonicalize_rdap_response(payload)
│       │       ├── Strip "last update of RDAP database" events (recursive)
│       │       └── Sort order-independent arrays (recursive)
│       │
│       └── Compare all canonicalized responses
│           ├── Match    → pass
│           └── Mismatch → RDAP_SERVICE_PORT_NOT_CONSISTENT
│
└── Return Rdap92Result
```

### Canonicalization Rules

Per the specification, the following rules are applied before comparing
responses across service ports:

1. **Event stripping:** All events with `eventAction` equal to
   `"last update of RDAP database"` are removed at all nesting levels
   (top-level and within nested entities).

2. **Order-independent sorting:** The following JSON properties are sorted
   by their canonical JSON representation (`json.dumps(x, sort_keys=True)`):
   - `entities`
   - `events`
   - `notices`
   - `remarks`
   - `links`
   - `rdapConformance`
   - `publicIDs`
   - `status`
   - `ipAddresses`
   - `nameservers`
   - `redactions`

3. **Deep copy:** The original payload is never modified.

### Usage Example

```python
from rst_compliance.rdap_conformance import (
    Rdap92Config,
    ServicePortConsistencyChecker,
)

config = Rdap92Config(
    base_urls=[
        {"tld": "example", "baseURL": "https://rdap.example.com/example/"},
    ],
    test_domains=[
        {"tld": "example", "name": "test.example"},
    ],
    test_entities=[
        {"tld": "example", "handle": "9995"},
    ],
    test_nameservers=[
        {"tld": "example", "nameserver": "ns1.example.com"},
    ],
    timeout_seconds=30,
)

checker = ServicePortConsistencyChecker(config)
result = checker.run()

if result.passed:
    print("rdap-92: PASS")
    print(f"  Service ports checked: {len(result.service_ports_checked)}")
else:
    print("rdap-92: FAIL")
    for error in result.errors:
        print(f"  [{error.severity}] {error.code}: {error.detail}")
```

### Dependency Injection for Testing

All external dependencies are pluggable:

```python
checker = ServicePortConsistencyChecker(
    config,
    resolver=CustomDnsResolver(),    # Override DNS resolution
    querier=CustomQuerier(),         # Override HTTP queries
)
```

---

## Test Coverage

### Test File

`tests/test_rdap_service_port_consistency.py`

### Test Classes (34 tests total)

| Test Class | Count | Coverage |
|---|---|---|
| `TestCanonicalizeRdapResponse` | 11 | Event stripping (top-level, nested, empty), array sorting (`status`, `entities`, `nameservers`, `links`, `redactions`, `rdapConformance`), immutability, no-op on payloads without order-independent keys. |
| `TestDnsResolution` | 3 | DNS resolution error → `RDAP_TLS_DNS_RESOLUTION_ERROR`, empty results → `RDAP_TLS_NO_SERVICE_PORTS_REACHABLE`, resolved ports recorded on result. |
| `TestQueryPaths` | 3 | All object types queried (domain, entity, nameserver), each port queried for each path (2×3=6 calls), TLD filtering excludes non-matching entries. |
| `TestConsistency` | 5 | Identical responses pass, responses differing only in "last update of RDAP database" event date pass, responses with different array ordering pass, substantive differences (e.g. different status) fail with `RDAP_SERVICE_PORT_NOT_CONSISTENT`, different entity content fails. |
| `TestServicePortErrors` | 3 | All ports unreachable → `RDAP_TLS_SERVICE_PORT_UNREACHABLE` + `RDAP_TLS_NO_SERVICE_PORTS_REACHABLE`, one port unreachable (partial failure), non-200 status → `RDAP_QUERY_FAILED`. |
| `TestMultipleTLDs` | 1 | Multiple TLDs checked independently, all query paths verified. |
| `TestRdap92Result` | 4 | Initial state (`passed=True`), ERROR severity sets `passed=False`, CRITICAL severity sets `passed=False`, WARNING preserves `passed=True`. |
| `TestServicePort` | 2 | Frozen dataclass, equality. |
| `TestSinglePort` | 1 | Single service port skips consistency check (no comparison possible). |
| `TestRdap92Error` | 1 | Frozen dataclass attributes. |

### Relationship to EPP epp-17

The rdap-92 test case is the RDAP counterpart to `epp-17` (Service Port
consistency test). Both tests verify that all service ports for a given
protocol return consistent responses:

| Aspect | epp-17 | rdap-92 |
|---|---|---|
| Protocol | EPP (RFC 5730) | RDAP (RFC 9083) |
| Transport | TLS on TCP port 700 | HTTPS on TCP port 443 |
| Service ports | A/AAAA records for EPP hostname | A/AAAA records for RDAP base URL hostname |
| Object types | Domain, Host, Contact (via `<info>`) | Domain, Entity, Nameserver (via GET) |
| Comparison | `<infData>` XML content identical | JSON body identical after canonicalization |
| Canonicalization | N/A (XML strict comparison) | Strip "last update of RDAP database" events, sort order-independent arrays |
| Error code | `EPP_SERVICE_PORT_NOT_CONSISTENT` | `RDAP_SERVICE_PORT_NOT_CONSISTENT` |
