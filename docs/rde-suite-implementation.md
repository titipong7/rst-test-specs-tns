# StandardRDE Test Suite — Implementation Summary

## Test Cases Implemented (14)

| Test ID | Summary | Checker Class | Key Error Code(s) |
|---|---|---|---|
| `rde-01` | Validate deposit filename format | `Rde01FilenameChecker` | `RDE_INVALID_FILENAME` |
| `rde-02` | Validate PGP signature | `Rde02SignatureChecker` | `RDE_INVALID_SIGNATURE` |
| `rde-03` | Decrypt deposit file | `Rde03DecryptionChecker` | `RDE_DECRYPTION_FAILED` |
| `rde-04` | Validate XML/CSV well-formedness | `Rde04XmlCsvChecker` | `RDE_XML_PARSE_ERROR`, `RDE_MISSING_FILES` |
| `rde-05` | Validate object types (header/menu URIs) | `Rde05ObjectTypesChecker` | `RDE_MENU_AND_HEADER_URIS_DIFFER`, `RDE_MISSING_OBJECT_URI` |
| `rde-06` | Validate object counts | `Rde06ObjectCountsChecker` | `RDE_OBJECT_COUNT_MISMATCH` |
| `rde-07` | Validate domain objects | `Rde07DomainChecker` | `RDE_DOMAIN_*` (22 error codes) |
| `rde-08` | Validate host objects | `Rde08HostChecker` | `RDE_HOST_*` (12 error codes) |
| `rde-09` | Validate contact objects | `Rde09ContactChecker` | `RDE_CONTACT_*` (12 error codes) |
| `rde-10` | Validate registrar objects | `Rde10RegistrarChecker` | `RDE_REGISTRAR_*` (8 error codes) |
| `rde-11` | Validate IDN table objects | `Rde11IdnChecker` | `RDE_IDN_*` |
| `rde-12` | Validate NNDN objects | `Rde12NndnChecker` | `RDE_NNDN_*` |
| `rde-13` | Validate EPP parameters object | `Rde13EppParamsChecker` | `RDE_MISSING_EPP_PARAMS_OBJECT`, `RDE_EPP_PARAMS_*` |
| `rde-14` | Validate policy object | `Rde14PolicyChecker` | `RDE_POLICY_OBJECT_MISSING` |

**Skip conditions:**
- `rde-08` skipped when `epp.hostModel = "attributes"`
- `rde-09` skipped when `general.registryDataModel = "minimum"`
- `rde-11` skipped when no IDN tables configured

---

## Implementation Details

### Source File

`src/rst_compliance/rde_suite.py`

### Architecture

| Component | Type | Purpose |
|---|---|---|
| `RdeSuiteConfig` | Dataclass | Config: deposit filename/XML, signature/decryption status, data model, host model, TLDs |
| `RdeDepositParser` | Class | Pluggable XML parser extracting domains, hosts, contacts, registrars, URIs, NNDN, EPP params |
| `RdeTestResult` / `RdeTestError` | Dataclass | Structured results matching spec error codes |
| `StandardRdeTestSuite` | Class | Runs all 14 test cases via `run_all()` |

### Input Parameters

| Parameter | Used By |
|---|---|
| `rde.depositFile` | rde-01 (filename), rde-02 (signature), rde-03 (decryption) |
| `rde.signatureFile` | rde-02 |
| `rde.publicKey` | rde-02 |
| `general.registryDataModel` | rde-05, rde-07, rde-09, rde-14 |
| `epp.hostModel` | rde-05, rde-07, rde-08 |

### Validation Pipeline

```
rde-01  Filename format ──────────────────────┐
rde-02  PGP signature ───────────────────────┤
rde-03  Decryption ──────────────────────────┤
            │                                 │
            ▼ (decrypted XML/CSV)             │
rde-04  XML/CSV parse + schema ──────────────┤
rde-05  Object type URIs ────────────────────┤
rde-06  Object counts ──────────────────────┤  All feed into
rde-07  Domain objects ──────────────────────┤  RdeTestResult
rde-08  Host objects (if objects model) ─────┤
rde-09  Contact objects (if thick model) ────┤
rde-10  Registrar objects ───────────────────┤
rde-11  IDN table objects ───────────────────┤
rde-12  NNDN objects ────────────────────────┤
rde-13  EPP parameters ─────────────────────┤
rde-14  Policy object ──────────────────────┘
```

---

## Test Coverage

### Test File

`tests/test_rde_suite.py` — **41 tests**

| Test Class | Count | Coverage |
|---|---|---|
| `TestRde01Filename` | 4 | Valid, invalid format, wrong TLD, empty |
| `TestRde02Signature` | 3 | Valid, invalid, None (not checked) |
| `TestRde03Decryption` | 2 | Success, failure |
| `TestRde04XmlCsv` | 3 | Valid XML, invalid XML, no XML |
| `TestRde05ObjectTypes` | 2 | Matching URIs, mismatched URIs |
| `TestRde07Domain` | 5 | Valid, no domains, duplicate name, missing registrant (max model), invalid ROID |
| `TestRde08Host` | 3 | Valid hosts, skipped (attributes), no hosts |
| `TestRde09Contact` | 3 | Skipped (minimum), valid, invalid email |
| `TestRde10Registrar` | 4 | Valid, no registrars, missing gurid, duplicate ID |
| `TestRde11Idn` | 1 | Skipped (no IDN tables) |
| `TestRde12Nndn` | 3 | No NNDN, conflicts with domain, duplicate name |
| `TestRde13EppParams` | 3 | Valid, missing object, missing extURI |
| `TestRde14Policy` | 3 | Minimum (skip), maximum with policy, maximum without |
| `TestStandardRdeTestSuite` | 2 | Runs all 14, all pass |

### Relationship to Other Suites

| RDE Test | Counterpart | Shared Concept |
|---|---|---|
| `rde-05` (object type URIs) | `epp-02` (greeting URIs) | XML namespace validation |
| `rde-07` (domain validation) | `epp-14` (domain create) | Domain object properties |
| `rde-08` (host validation) | `epp-11` (host create) | Host object model |
| `rde-09` (contact validation) | `epp-07` (contact create) | Contact data model |
| `rde-13` (EPP params) | `epp-02` (greeting extensions) | Required extension URIs |
