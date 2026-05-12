# RST v2026.04 — Implementation Plan for Remaining Test Suites

## Overview

5 test suites with **50 test cases** remain to be implemented. This document
provides a detailed plan for each, ordered by dependency and priority.

```
                ┌────────────────────┐
                │   StandardEPP (26) │  ← foundation for everything else
                └────────┬───────────┘
           ┌─────────────┼──────────────┐
           ▼             ▼              ▼
  ┌─────────────┐ ┌────────────┐ ┌────────────────┐
  │ StandardIDN │ │ MinimumRPMs│ │ StandardSRS    │
  │     (2)     │ │    (3)     │ │ Gateway (14)   │
  └─────────────┘ └────────────┘ └────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │ StandardIntegration  │
              │       Test (5)       │
              └──────────────────────┘
```

---

## Phase 1: StandardEPP (26 cases) — Foundation

**File:** `src/rst_compliance/epp_suite.py`
**Tests:** `tests/test_epp_suite.py`
**Doc:** `docs/epp-suite-implementation.md`

### Why first?

StandardEPP is the foundation — StandardIDN, MinimumRPMs, SRSGateway, and
IntegrationTest all depend on EPP connectivity and commands. The existing
`EppClient` provides transport (mTLS, TLS 1.3, RSA 4096) but no per-case
checkers.

### Test cases

| Group | Cases | Summary |
|---|---|---|
| **Connectivity** | `epp-01` | Service connectivity (DNS, TLS, A/AAAA, ciphers — mirrors `rdap-91`) |
| **Protocol** | `epp-02` | Greeting validation (svID, svDate, version, lang, objURI, extURI) |
| **Auth** | `epp-03` | Authentication (valid/invalid login, mTLS cert scenarios) |
| **Domain CRUD** | `epp-04`, `14`, `16`, `18`–`21` | check, create, update, renew, transfer (approve/reject), delete |
| **Host CRUD** | `epp-05`, `11`–`13`, `23`–`27` | check, create, update, rename, delete, access control, glue policy |
| **Contact CRUD** | `epp-06`–`10` | check, create, access control, update, delete |
| **Integrity** | `epp-15` | Delete linked objects must be rejected |
| **Consistency** | `epp-17` | Service port consistency (mirrors `rdap-92`) |

### Architecture

```python
@dataclass(frozen=True)
class EppSuiteConfig:
    hostname: str
    clid01: str; pwd01: str
    clid02: str; pwd02: str
    host_model: str  # "objects" | "attributes"
    registry_data_model: str
    registered_names: list[str]
    # ... other input parameters

class EppCommandClient:
    """Pluggable EPP command client (override for testing)."""
    def login(self, ...) -> EppResponse: ...
    def domain_check(self, ...) -> EppResponse: ...
    def domain_create(self, ...) -> EppResponse: ...
    def domain_info(self, ...) -> EppResponse: ...
    # ... all EPP commands

class Epp01ConnectivityChecker:
    def run(self) -> EppTestResult: ...

class StandardEppTestSuite:
    def run_all(self) -> list[EppTestResult]: ...
```

### Key implementation details

- **`epp-01`**: Reuse `DnsResolver` + `TlsProber` from RDAP/DNS suites
- **`epp-02`**: Parse `<greeting>` XML → validate svID, svDate (±30s NTP),
  version="1.0", lang includes "en", mandatory objURI/extURI
- **`epp-03`**: 6 login scenarios (nonexistent ID, wrong password, wrong cert,
  other client cert, no cert, valid)
- **`epp-04`…`epp-21`**: Domain/host/contact CRUD lifecycle using `EppClient`
  transport with XML command templates
- **`epp-17`**: Port consistency — create objects on one port, `<info>` on
  all others → compare `<infData>`
- **`epp-23`…`epp-27`**: Host rename, subordinate host, glue policy enforcement

### Estimated scope

- ~26 checker classes + `EppCommandClient` abstraction + XML response parser
- ~80–100 unit tests
- Reuses existing `EppClient`, `EppMtlsConfig`, `assess_epp_command`

---

## Phase 2: StandardIDN (2 cases) — Depends on EPP

**File:** `src/rst_compliance/idn_suite.py`
**Tests:** `tests/test_idn_suite.py`
**Doc:** `docs/idn-suite-implementation.md`

### Test cases

| Case | Summary | Skip condition |
|---|---|---|
| `idn-01` | IDN label validation via EPP `<create>` | — |
| `idn-02` | ASCII domain rejection for IDN-only TLDs | All TLDs have `idnOnly: false` |

### Architecture

```python
@dataclass(frozen=True)
class IdnSuiteConfig:
    epp_config: EppSuiteConfig
    idn_tables: list[dict]  # allocatable/unallocatable labels
    domain_create_extension: str | None  # idn.domainCreateExtension

class Idn01LabelValidationChecker:
    """Uses EPP <create> to test valid/invalid IDN labels and variant policy."""

class Idn02AsciiRejectionChecker:
    """Uses EPP <create> to confirm ASCII labels rejected for idnOnly TLDs."""

class StandardIdnTestSuite:
    def run_all(self) -> list[IdnTestResult]: ...
```

### Key implementation details

- **`idn-01`**: Generate domain names from IDN table allocatable/unallocatable
  labels → EPP `<create>` → verify accept/reject. Also test variant policy
  (blocked / same-registrant / same-registrar)
- **`idn-02`**: For each TLD with `idnOnly: true`, send `<create>` for a
  random ASCII domain → server MUST reject

### Error codes

`IDN_SERVER_ACCEPTS_INVALID_LABEL`, `IDN_SERVER_REJECTS_VALID_LABEL`,
`IDN_VARIANT_LABEL_NOT_BLOCKED`, `IDN_VARIANT_SERVER_*` (4 variant errors),
`IDN_IDNONLY_TLD_ACCEPTS_ASCII_DOMAIN`

### Estimated scope

- 2 checker classes
- ~10–15 unit tests

---

## Phase 3: MinimumRPMs (3 cases) — Depends on EPP + TMCH

**File:** `src/rst_compliance/rpms_suite.py`
**Tests:** `tests/test_rpms_suite.py`
**Doc:** `docs/rpms-suite-implementation.md`

### Test cases

| Case | Summary |
|---|---|
| `minimumRPMs-01` | Claims `<check>` — verify `<launch:claimKey>` present/absent per DNL |
| `minimumRPMs-02` | Sunrise `<create>` — valid/invalid/revoked SMD handling |
| `minimumRPMs-03` | Trademark claims `<create>` — valid/invalid/expired notice ID |

### Architecture

```python
@dataclass(frozen=True)
class RpmsSuiteConfig:
    epp_config: EppSuiteConfig
    sunrise_tld: str
    claims_tld: str
    sunrise_model: str  # "start-date" | "end-date"
    # TMCH resources loaded from tmch.test* resources

class MinimumRpms01ClaimsCheckChecker:
    """EPP <check> with Launch extension, verify claimKey."""

class MinimumRpms02SunriseCreateChecker:
    """EPP <create> with valid/invalid/revoked SMD files."""

class MinimumRpms03TrademarkCreateChecker:
    """EPP <create> with claims notice acknowledgement."""

class MinimumRpmsTestSuite:
    def run_all(self) -> list[RpmsTestResult]: ...
```

### Key implementation details

- Uses Launch Extension (RFC 8334) XML structures
- Requires TMCH test materials (test cert, CRL, DNL, SMDRL, SURL)
  available as resources
- Tests both positive (valid SMD/notice) and negative (invalid, revoked,
  expired) scenarios

### Error codes

`RPMS_MISSING_CLAIMS_KEY`, `RPMS_UNEXPECTED_CLAIMS_KEY`,
`RPMS_INVALID_CLAIMS_KEY`, `RPMS_SUNRISE_CREATE_*` (6 codes),
`RPMS_TRADEMARK_CREATE_*` (6 codes)

### Estimated scope

- 3 checker classes
- ~15–20 unit tests

---

## Phase 4: StandardSRSGateway (14 cases) — Depends on EPP + RDAP

**File:** `src/rst_compliance/srsgw_suite.py`
**Tests:** `tests/test_srsgw_suite.py`
**Doc:** `docs/srsgw-suite-implementation.md`

### Test cases

| Case | Summary | Skip condition |
|---|---|---|
| `srsgw-01` | Gateway EPP connectivity | — |
| `srsgw-02` | Host `<create>` sync | hostModel=attributes |
| `srsgw-03` | Contact `<create>` sync | registryDataModel=minimum |
| `srsgw-04` | Domain lifecycle sync (create → RDAP/DNS) | — |
| `srsgw-05` | Host lifecycle sync | hostModel=attributes |
| `srsgw-06` | Contact lifecycle sync (includes old srsgw-07) | registryDataModel=minimum |
| `srsgw-08` | Domain `<update>` sync | — |
| `srsgw-09` | Domain `<renew>` sync | — |
| `srsgw-10` | Domain `<transfer>` sync | — |
| `srsgw-11` | Domain `<delete>` sync | — |
| `srsgw-12` | DNSSEC sync | — |
| `srsgw-13` | RDE deposit from gateway | — |
| `srsgw-14` | RDAP response consistency | — |
| `srsgw-15` | IDN sync | No IDN tables |

### Architecture

```python
@dataclass(frozen=True)
class SrsgwSuiteConfig:
    primary_epp_config: EppSuiteConfig
    gateway_epp_config: EppSuiteConfig  # srsgw.epp* parameters
    gateway_rdap_base_urls: list[dict]
    gateway_registry_data_model: str

class SrsgwCommandClient:
    """Dual EPP client — primary + gateway systems."""
    def create_on_gateway(self, ...) -> EppResponse: ...
    def info_on_primary(self, ...) -> EppResponse: ...
    def compare_responses(self, ...) -> bool: ...

class Srsgw01ConnectivityChecker: ...
class Srsgw02HostSyncChecker: ...
# ... etc

class StandardSrsgwTestSuite:
    def run_all(self) -> list[SrsgwTestResult]: ...
```

### Key implementation details

- Each test creates objects on gateway EPP → verifies they appear on primary
  EPP with identical properties (usually within 30s deadline)
- `srsgw-04`: Also checks RDAP and DNS propagation
- `srsgw-13`: Checks RDE deposit from gateway contains synced objects
- `srsgw-14`: RDAP responses from gateway must match primary
- Requires dual EPP connections (primary + gateway)

### Error codes

`SRSGW_*` prefix — `SRSGW_HOST_CREATE_FAILED`,
`SRSGW_HOST_CREATE_OBJECT_NOT_FOUND_WITHIN_DEADLINE`,
`SRSGW_HOST_CREATE_OBJECT_HAS_MISSING_OR_INVALID_PROPERTIES`, etc.

### Estimated scope

- 14 checker classes + `SrsgwCommandClient`
- ~40–50 unit tests

---

## Phase 5: StandardIntegrationTest (5 cases) — Depends on EPP + DNS + RDAP + RDE

**File:** `src/rst_compliance/integration_suite.py`
**Tests:** `tests/test_integration_suite.py`
**Doc:** `docs/integration-suite-implementation.md`

### Test cases

| Case | Summary | Skip condition |
|---|---|---|
| `integration-01` | EPP → RDAP propagation (within 1 hour SLA) | — |
| `integration-02` | EPP → DNS propagation (within 1 hour SLA) | — |
| `integration-03` | EPP → RDE deposit (within 24 hours, via SFTP) | — |
| `integration-04` | Narrow glue verification (host objects) | gluePolicy≠narrow OR hostModel≠objects |
| `integration-05` | Narrow glue verification (host attributes) | gluePolicy≠narrow OR hostModel≠attributes |

### Architecture

```python
@dataclass(frozen=True)
class IntegrationSuiteConfig:
    epp_config: EppSuiteConfig
    rdap_base_urls: list[dict]
    dns_nameservers: list[dict]
    rde_sftp_hostname: str
    rde_sftp_username: str
    rde_sftp_directory: str
    glue_policy: str
    host_model: str

class SftpClient:
    """Pluggable SFTP client for RDE deposit retrieval."""
    def list_deposits(self, ...) -> list[str]: ...
    def download(self, ...) -> bytes: ...

class Integration01EppRdapChecker:
    """Create objects via EPP, query RDAP within 1 hour."""

class Integration02EppDnsChecker:
    """Create objects via EPP, query DNS within 1 hour."""

class Integration03EppRdeChecker:
    """Create objects via EPP, find in RDE deposit via SFTP within 24 hours."""

class Integration04GlueObjectsChecker:
    """Create hosts with glue, verify DNS A/AAAA within 60 minutes."""

class Integration05GlueAttributesChecker:
    """Create domains with host attributes, verify DNS glue."""

class StandardIntegrationTestSuite:
    def run_all(self) -> list[IntegrationTestResult]: ...
```

### Key implementation details

- **`integration-01`**: EPP `<create>` domain → poll RDAP `/domain/{name}`
  until 200 response (within 1 hour)
- **`integration-02`**: EPP `<create>` domain → poll DNS NS query until
  answered (within 1 hour)
- **`integration-03`**: EPP `<create>` → SFTP connect → scan `.ryde` files →
  decrypt → find objects (within 24 hours). Needs `SftpClient` abstraction.
- **`integration-04`/`-05`**: Create internal hosts with glue → monitor DNS
  A/AAAA → linked hosts MUST appear, unlinked MUST NOT

### Error codes

`INTEGRATION_RDAP_REQUEST_FAILED`, `INTEGRATION_DNS_QUERY_FAILED`,
`INTEGRATION_DOMAIN_NOT_PRESENT_IN_RDAP`, `INTEGRATION_DOMAIN_NOT_PRESENT_IN_DNS`,
`INTEGRATION_DOMAIN_NOT_PRESENT_IN_RDE`, `INTEGRATION_RDE_SFTP_*`,
`INTEGRATION_LINKED_HOST_OBJECTS_NOT_OBSERVED`,
`INTEGRATION_UNLINKED_HOST_OBJECTS_OBSERVED`,
`INTEGRATION_EXPECTED_GLUE_NOT_OBSERVED`,
`INTEGRATION_UNEXPECTED_GLUE_OBSERVED`

### Estimated scope

- 5 checker classes + `SftpClient` abstraction
- ~20–25 unit tests

---

## Phase 6: AdditionalDNSTransports (extend existing)

**File:** Update `src/rst_compliance/dns_suite.py`

Extend `DnsConsistencyChecker` to support:
- DNS over TLS (DoT, RFC 7858) — port 853
- DNS over HTTPS (DoH, RFC 8484) — port 443
- DNS over QUIC (DoQ, RFC 9250) — port 853

Based on `supportsDoT`, `supportsDoH`, `supportsDoQ` flags in
`dns.nameservers` input parameter.

### Estimated scope

- Extend `DnsQuerier` with DoT/DoH/DoQ transport methods
- ~5–10 additional tests

---

## Implementation Timeline

| Phase | Suite | Cases | Dependencies | Est. Tests |
|---|---|---|---|---|
| **1** | StandardEPP | 26 | `EppClient` (exists) | 80–100 |
| **2** | StandardIDN | 2 | Phase 1 | 10–15 |
| **3** | MinimumRPMs | 3 | Phase 1 + TMCH resources | 15–20 |
| **4** | StandardSRSGateway | 14 | Phase 1 + RDAP | 40–50 |
| **5** | StandardIntegrationTest | 5 | Phase 1 + DNS + RDAP + RDE | 20–25 |
| **6** | AdditionalDNSTransports | 1 | DNS suite | 5–10 |
| **Total** | | **51** | | **170–220** |

After all phases, the project will have **~129 test cases** with
**~420–470 unit tests** covering all 11 RST v2026.04 test suites.

---

## Shared Infrastructure to Build

| Component | Used by | Notes |
|---|---|---|
| `EppCommandClient` | EPP, IDN, RPMs, SRSGW, Integration | Pluggable EPP command abstraction over `EppClient` |
| `EppResponseParser` | EPP, IDN, RPMs, SRSGW, Integration | Parse `<greeting>`, `<response>`, `<infData>` XML |
| `SftpClient` | Integration | Pluggable SFTP for RDE deposit retrieval |
| `SrsgwCommandClient` | SRSGW | Dual EPP client (primary + gateway) |
| DoT/DoH/DoQ transports | DNS (phase 6) | Extend `DnsQuerier` |
