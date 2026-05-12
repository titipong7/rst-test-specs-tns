# StandardRDAP Test Suite (rdap-01 … rdap-92) — Implementation Summary

## Test Cases Implemented

| Test ID | Summary | Checker Class | Error Code(s) |
|---|---|---|---|
| `rdap-01` | Domain query test | `DomainQueryChecker` | `RDAP_DOMAIN_RESPONSE_VALIDATION_FAILED` |
| `rdap-02` | Nameserver query test | `NameserverQueryChecker` | `RDAP_NAMESERVER_RESPONSE_VALIDATION_FAILED` |
| `rdap-03` | Registrar (entity) query test | `EntityQueryChecker` | `RDAP_ENTITY_RESPONSE_VALIDATION_FAILED` |
| `rdap-04` | Help query test | `HelpQueryChecker` | `RDAP_HELP_RESPONSE_VALIDATION_FAILED` |
| `rdap-05` | Domain HEAD test | `DomainHeadChecker` | `RDAP_DOMAIN_HEAD_FAILED` |
| `rdap-06` | Nameserver HEAD test | `NameserverHeadChecker` | `RDAP_NAMESERVER_HEAD_FAILED` |
| `rdap-07` | Entity HEAD test | `EntityHeadChecker` | `RDAP_ENTITY_HEAD_FAILED` |
| `rdap-08` | Non-existent domain test | `NonExistentDomainChecker` | `RDAP_INVALID_RESPONSE_FOR_NON_EXISTENT_DOMAIN` |
| `rdap-09` | Non-existent nameserver test | `NonExistentNameserverChecker` | `RDAP_INVALID_RESPONSE_FOR_NON_EXISTENT_NAMESERVER` |
| `rdap-10` | Non-existent entity test | `NonExistentEntityChecker` | `RDAP_INVALID_RESPONSE_FOR_NON_EXISTENT_ENTITY` |
| `rdap-91` | TLS version conformance check | `TlsConformanceChecker` | `RDAP_TLS_*` (10 error codes) |
| `rdap-92` | Service port consistency check | `ServicePortConsistencyChecker` | `RDAP_SERVICE_PORT_NOT_CONSISTENT`, `RDAP_QUERY_FAILED`, `RDAP_TLS_*` |

All test cases can be run together via `StandardRdapTestSuite.run_all()`.

---

## Implementation Details

### Source File

`src/rst_compliance/rdap_conformance.py`

### Components

| Component | Type | Purpose |
|---|---|---|
| **Shared types** | | |
| `RdapSuiteConfig` | Dataclass | Unified configuration for the full suite: base URLs, test objects, registry data model, host model, timeout. |
| `RdapHttpClient` | Class | Pluggable HTTP client with `get()` and `head()` methods. |
| `RdapTestResult` | Dataclass | Aggregated result with `test_id`, `passed`, `skipped`, `errors`. |
| `RdapTestError` | Dataclass (frozen) | Structured error with `code`, `severity`, `detail`. |
| **rdap-01 … rdap-04** (GET query tests) | | |
| `DomainQueryChecker` | Class | Queries domains, validates objectClassName, ldhName, entities per data model. |
| `NameserverQueryChecker` | Class | Queries nameservers (skipped when hostModel=attributes). |
| `EntityQueryChecker` | Class | Queries entities, validates handle, vcardArray. |
| `HelpQueryChecker` | Class | Queries /help, validates rdapConformance + notices. |
| **rdap-05 … rdap-07** (HEAD tests) | | |
| `DomainHeadChecker` | Class | HEAD requests for domains: status 200, CORS header, empty body. |
| `NameserverHeadChecker` | Class | HEAD requests for nameservers (skipped when hostModel=attributes). |
| `EntityHeadChecker` | Class | HEAD requests for entities. |
| **rdap-08 … rdap-10** (non-existent object tests) | | |
| `NonExistentDomainChecker` | Class | Randomly-generated domain → expects 404 + valid RDAP error + CORS. |
| `NonExistentNameserverChecker` | Class | Internal + external random nameserver → expects 404. |
| `NonExistentEntityChecker` | Class | Random entity handle → expects 404. |
| **rdap-91** (TLS conformance) | | |
| `TlsConformanceChecker` | Class | DNS resolution → TLS probe per port → checks 7 criteria. |
| `TlsProber` / `TlsProbeResult` | Class/Dataclass | Pluggable TLS probing with result fields for all check criteria. |
| **rdap-92** (service port consistency) | | |
| `ServicePortConsistencyChecker` | Class | DNS resolution → per-port queries → canonicalize → compare. |
| `canonicalize_rdap_response()` | Function | Strips "last update of RDAP database" events, sorts order-independent arrays. |
| `DnsResolver` | Class | Pluggable DNS resolution (IPv4 + IPv6). |
| `RdapServicePortQuerier` | Class | Per-port RDAP queries with Host header. |
| **Suite runner** | | |
| `StandardRdapTestSuite` | Class | Runs all 12 test cases and returns `list[RdapTestResult]`. |

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

### Test Files

| File | Tests | Coverage |
|---|---|---|
| `tests/test_rdap_full_suite.py` | 55 | rdap-01 through rdap-10, rdap-91, StandardRdapTestSuite integration |
| `tests/test_rdap_service_port_consistency.py` | 34 | rdap-92 (service port consistency) |
| `tests/test_rdap_conformance.py` | 10 | Original RDAP payload validation tests |
| **Total** | **99** | Full StandardRDAP suite |

### rdap-01 … rdap-10 + rdap-91 Tests (`test_rdap_full_suite.py`)

| Test Class | Count | Coverage |
|---|---|---|
| `TestRdap01DomainQuery` | 6 | Valid response, wrong objectClassName, missing ldhName, maximum model registrant, HTTP error, TLD filtering |
| `TestRdap02NameserverQuery` | 4 | Valid response, skip when hostModel=attributes, wrong objectClassName, missing ldhName |
| `TestRdap03EntityQuery` | 5 | Valid response, wrong objectClassName, missing handle, missing vcardArray, invalid vcardArray |
| `TestRdap04HelpQuery` | 5 | Valid response, missing rdapConformance, missing notices, empty rdapConformance, HTTP error |
| `TestRdap05DomainHead` | 4 | Valid HEAD, non-200 status, missing CORS header, non-empty body |
| `TestRdap06NameserverHead` | 2 | Valid HEAD, skip when hostModel=attributes |
| `TestRdap07EntityHead` | 2 | Valid HEAD, non-200 status |
| `TestRdap08NonExistentDomain` | 6 | Valid 404+error body, empty body, 200 instead of 404, missing CORS, invalid JSON body, missing errorCode |
| `TestRdap09NonExistentNameserver` | 2 | Both internal+external 404, non-404 for internal |
| `TestRdap10NonExistentEntity` | 2 | Valid 404, non-404 fails |
| `TestRdap91TlsConformance` | 12 | All pass, TLS 1.2 missing, forbidden protocol, untrusted cert, expired cert, chain missing, hostname mismatch, bad cipher, DNS error, no ports, all unreachable, multiple failures |
| `TestRdapTestResult` | 3 | Initial state, skip, add_error |
| `TestStandardRdapTestSuite` | 2 | Runs all 12 tests, all pass integration |

### rdap-92 Tests (`test_rdap_service_port_consistency.py`)

| Test Class | Count | Coverage |
|---|---|---|
| `TestCanonicalizeRdapResponse` | 11 | Event stripping, array sorting, deep nesting, immutability |
| `TestDnsResolution` | 3 | Resolution errors, empty results, port recording |
| `TestQueryPaths` | 3 | All object types, port×path multiplication, TLD filtering |
| `TestConsistency` | 5 | Identical, last-update-only diff, array reorder, substantive diff |
| `TestServicePortErrors` | 3 | All unreachable, partial failure, non-200 |
| `TestMultipleTLDs` | 1 | Independent checking |
| `TestRdap92Result` | 4 | State and severity |
| `TestServicePort` / `TestSinglePort` / `TestRdap92Error` | 4 | Edge cases |

### Relationship to EPP Test Suite

| RDAP Test | EPP Counterpart | Shared Concept |
|---|---|---|
| `rdap-01` (domain query) | `epp-04` (domain check) | Query object, validate response |
| `rdap-02` (nameserver query) | `epp-05` (host check) | Skip when hostModel=attributes |
| `rdap-03` (entity query) | `epp-06` (contact check) | Entity/contact response validation |
| `rdap-04` (help query) | `epp-02` (greeting) | Protocol conformance baseline |
| `rdap-05…07` (HEAD tests) | — | RDAP-specific (no EPP equivalent) |
| `rdap-08…10` (non-existent) | — | RDAP-specific 404 handling |
| `rdap-91` (TLS conformance) | `epp-01` (service connectivity) | TLS version, cert, cipher checks |
| `rdap-92` (port consistency) | `epp-17` (port consistency) | Cross-port response comparison |
