# StandardEPP Test Case Summary (v2026.04)

This document summarizes current internal checker coverage for StandardEPP test
cases (`epp-01` to `epp-27`) based on the latest dashboard/reporting behavior.

## Coverage Legend

- `covered`: mapped tests exist and passed
- `partial`: partly covered, removed in spec, or requires follow-up
- `missing`: no mapped internal checker test yet

## Case-by-Case Status


| Case   | Status  | Current Evidence                                                                                                                 | Notes                                                          |
| ------ | ------- | -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| epp-01 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `tests/test_epp_connectivity.py`, `src/rst_compliance/epp_connectivity.py` | Full-spec connectivity checks (DNS/TCP/TLS/cert/cipher) with hybrid live/offline coverage |
| epp-02 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `tests/test_epp_host_constraints.py`, `src/rst_compliance/epp_client.py` | Full-spec greeting conformance checks (`svID`/`svDate`/version/lang/objURI/extURI/recommended extensions) |
| epp-03 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `tests/test_epp_host_constraints.py`, `src/rst_compliance/epp_client.py` | Authentication scenario matrix (expected reject/accept paths) |
| epp-04 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `tests/test_epp_host_constraints.py`, `src/rst_compliance/epp_client.py` | Domain `<check>` invalid/registered/unregistered availability semantics |
| epp-05 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `src/rst_compliance/epp_client.py`                           | Host `<check>` semantics aligned to invalid/registered behavior |
| epp-06 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `src/rst_compliance/epp_client.py`                           | Contact `<check>` semantics and invalid input handling         |
| epp-07 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `src/rst_compliance/epp_client.py`                           | Contact `<create>` success/failure flow assertions             |
| epp-08 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `src/rst_compliance/epp_client.py`                           | Access-control flow assertions with conditional applicability   |
| epp-09 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `src/rst_compliance/epp_client.py`                           | Contact `<update>` success/failure flow assertions             |
| epp-10 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `src/rst_compliance/epp_client.py`                           | Contact `<delete>` success/failure flow assertions             |
| epp-11 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `src/rst_compliance/epp_client.py`                           | Host `<create>` with applicability and negative-path checks    |
| epp-12 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `src/rst_compliance/epp_client.py`                           | Host ACL flow assertions with conditional applicability         |
| epp-13 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `src/rst_compliance/epp_client.py`                           | Host `<update>` with applicability and negative-path checks    |
| epp-14 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                | Domain `<create>` smoke behavior                               |
| epp-15 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                | Registry object integrity smoke checks with applicability skip |
| epp-16 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                | Domain `<update>` smoke behavior                               |
| epp-17 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                | Service port consistency check                                 |
| epp-18 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `src/rst_compliance/epp_client.py`                           | Domain `<renew>` success/failure flow assertions               |
| epp-19 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `src/rst_compliance/epp_client.py`                           | Domain `<transfer>` request success/failure assertions         |
| epp-20 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `src/rst_compliance/epp_client.py`                           | Reject flow keeps command semantics consistent                 |
| epp-21 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `src/rst_compliance/epp_client.py`                           | Domain `<delete>` success/failure flow assertions              |
| epp-22 | partial | `src/rst_compliance/rst_dashboard.py`                                                                                            | Removed in v2026.04; retained in matrix for continuity         |
| epp-23 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                | Host rename behavior covered with applicability skip           |
| epp-24 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                | Host `<delete>` behavior covered with applicability skip       |
| epp-25 | covered | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                | Subordinate host `<create>` covered with applicability skip    |
| epp-26 | covered | `internal-rst-checker/tests/epp/test_epp_host_constraints.py`, `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py` | Wide glue host object access control                           |
| epp-27 | covered | `internal-rst-checker/tests/epp/test_epp_host_constraints.py`, `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py` | Glueless internal host object access control                   |


## Summary

- Covered: **26**
- Partial: **1**
- Missing: **0**

## Related Components

- Coverage generation logic: `src/rst_compliance/rst_dashboard.py`
- EPP helper logic: `src/rst_compliance/epp_client.py`
- EPP-01 connectivity engine: `src/rst_compliance/epp_connectivity.py`
- Internal EPP tests:
  - `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`
  - `internal-rst-checker/tests/epp/test_epp_host_constraints.py`
  - `tests/test_epp_connectivity.py`

## Remaining Focus

1. Keep `epp-22` as `partial` with explicit rationale (removed in v2026.04).
2. Expand functional depth per case (beyond smoke checks) using real protocol/data fixtures.
3. Add stricter conformance assertions for extension schema and EPP result-code semantics.

## Example Input / Expected Output (epp-01..epp-27)

The entries below provide concise examples for command intent and expected
checker behavior. They are smoke-level examples aligned to current internal
checker design.


| Case   | Example input (EPP command intent)                | Expected success                                                             | Expected failure                                            |
| ------ | ------------------------------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------- |
| epp-01 | DNS + TCP/700 + TLS/cert/cipher connectivity probe | DNS resolves, TCP reachable, TLSv1.2 pass, TLSv1.1 blocked, trusted cert, recommended cipher -> checker `pass` | DNS/TCP/TLS/cert/cipher policy violation -> checker `fail` |
| epp-02 | greeting frame conformance (`<greeting>` block)   | `svID`/`svDate`/`version=1.0`/`en`/required URIs pass; checker `pass`        | missing or invalid greeting field/URI; checker `fail` or warning for recommended extension |
| epp-03 | `<login/>` authentication matrix                  | only valid credential+certificate scenario accepted; checker `pass`           | reject scenarios unexpectedly succeed (or valid scenario fails); checker `fail` |
| epp-04 | `<check/>` domain check semantics                 | invalid domain handled by allowed error or `avail=false`; registered unavailable; unregistered available | any availability mismatch against expected semantics; checker `fail` |
| epp-05 | `<check/>` host check flow                        | valid host check success; checker `pass`                                     | invalid host syntax/policy rejection; checker `fail`        |
| epp-06 | `<check/>` contact check (if applicable)          | valid contact check success; checker `pass`                                  | invalid contact ID/policy rejection; checker `fail`         |
| epp-07 | `<create/>` contact create (if applicable)        | valid contact create success; checker `pass`                                 | invalid contact payload/policy rejection; checker `fail`    |
| epp-08 | `<info/>`/`<update/>` contact ACL (if applicable) | own-object operation allowed; checker `pass`                                 | foreign-object operation rejected; checker `fail`           |
| epp-09 | `<update/>` contact update (if applicable)        | valid update success; checker `pass`                                         | invalid field/policy rejection; checker `fail`              |
| epp-10 | `<delete/>` contact delete (if applicable)        | deletable contact success; checker `pass`                                    | linked/protected contact rejected; checker `fail`           |
| epp-11 | `<create/>` host create (if applicable)           | valid host create success; checker `pass`                                    | malformed/disallowed host create rejected; checker `fail`   |
| epp-12 | `<update/>` host ACL (if applicable)              | sponsor update allowed; checker `pass`                                       | non-sponsor update rejected; checker `fail`                 |
| epp-13 | `<update/>` host update (if applicable)           | valid host update success; checker `pass`                                    | invalid host update rejected; checker `fail`                |
| epp-14 | `<create/>` domain create                         | valid domain create success; checker `pass`                                  | invalid create/policy rejection; checker `fail`             |
| epp-15 | object integrity checks (if applicable)           | consistent object state; checker `pass`                                      | integrity mismatch/policy rejection; checker `fail`         |
| epp-16 | `<update/>` domain update                         | valid domain update success; checker `pass`                                  | invalid update/policy rejection; checker `fail`             |
| epp-17 | service port consistency check                    | command uses configured EPP port; checker `pass`                             | unexpected port/path mismatch; checker `fail`               |
| epp-18 | `<renew/>` domain renew                           | valid renew success; checker `pass`                                          | invalid renew state/policy rejection; checker `fail`        |
| epp-19 | `<transfer op="request"/>`                        | valid transfer request success; checker `pass`                               | invalid auth/status rejects transfer; checker `fail`        |
| epp-20 | `<transfer op="reject"/>`                         | rejection flow behaves as expected; checker `pass`                           | reject flow inconsistent/invalid state; checker `fail`      |
| epp-21 | `<delete/>` domain delete                         | deletable domain success; checker `pass`                                     | prohibited/linked domain delete rejected; checker `fail`    |
| epp-22 | domain restore flow (removed in v2026.04)         | N/A (kept for matrix continuity only)                                        | marked `partial` by design                                  |
| epp-23 | host rename (if applicable)                       | valid rename success; checker `pass`                                         | forbidden rename rejected; checker `fail`                   |
| epp-24 | host delete (if applicable)                       | valid host delete success; checker `pass`                                    | linked/protected host delete rejected; checker `fail`       |
| epp-25 | subordinate host create (if applicable)           | valid subordinate host create success; checker `pass`                        | disallowed subordinate create rejected; checker `fail`      |
| epp-26 | wide glue host object ACL                         | disallowed wide-glue action rejected; checker `pass` when rejection observed | action incorrectly accepted; checker `fail`                 |
| epp-27 | glueless internal host ACL                        | allowed create + disallowed delegation behavior observed; checker `pass`     | policy not enforced; checker `fail`                         |


## Full XML Per Case (ready-to-use fixtures)

### epp-01

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><hello/></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><hello/></command></epp>
```

### epp-02

- Success:

```xml
<extension xmlns="urn:ietf:params:xml:ns:epp-1.0"><login xmlns="urn:example:epp-ext-1.0"><flag>on</flag></login></extension>
```

- Failure:

```xml
<login xmlns="urn:example:epp-ext-1.0"><flag>on</flag></login>
```

### epp-03

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><login><clID>ClientX</clID><pw>EXAMPLE-TOKEN</pw><options><version>1.0</version><lang>en</lang></options><svcs><objURI>urn:ietf:params:xml:ns:domain-1.0</objURI></svcs></login><clTRID>epp-03-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><login><clID>ClientX</clID><pw>WRONG-TOKEN</pw></login><clTRID>epp-03-fail</clTRID></command></epp>
```

### epp-04

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><check><domain:check xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>example.test</domain:name></domain:check></check><clTRID>epp-04-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><check><domain:check xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>invalid name</domain:name></domain:check></check><clTRID>epp-04-fail</clTRID></command></epp>
```

### epp-05

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><check><host:check xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>ns1.example.test</host:name></host:check></check><clTRID>epp-05-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><check><host:check xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>bad host name</host:name></host:check></check><clTRID>epp-05-fail</clTRID></command></epp>
```

### epp-06

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><check><contact:check xmlns:contact="urn:ietf:params:xml:ns:contact-1.0"><contact:id>sh8013</contact:id></contact:check></check><clTRID>epp-06-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><check><contact:check xmlns:contact="urn:ietf:params:xml:ns:contact-1.0"><contact:id>invalid contact id</contact:id></contact:check></check><clTRID>epp-06-fail</clTRID></command></epp>
```

### epp-07

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><create><contact:create xmlns:contact="urn:ietf:params:xml:ns:contact-1.0"><contact:id>sh8013</contact:id><contact:postalInfo type="loc"><contact:name>Example Name</contact:name><contact:addr><contact:street>Example Street</contact:street><contact:city>Example City</contact:city><contact:cc>US</contact:cc></contact:addr></contact:postalInfo><contact:email>ops@example.test</contact:email></contact:create></create><clTRID>epp-07-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><create><contact:create xmlns:contact="urn:ietf:params:xml:ns:contact-1.0"><contact:id>sh8013</contact:id></contact:create></create><clTRID>epp-07-fail</clTRID></command></epp>
```

### epp-08

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><info><contact:info xmlns:contact="urn:ietf:params:xml:ns:contact-1.0"><contact:id>self-owned-contact</contact:id></contact:info></info><clTRID>epp-08-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><update><contact:update xmlns:contact="urn:ietf:params:xml:ns:contact-1.0"><contact:id>other-owned-contact</contact:id></contact:update></update><clTRID>epp-08-fail</clTRID></command></epp>
```

### epp-09

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><update><contact:update xmlns:contact="urn:ietf:params:xml:ns:contact-1.0"><contact:id>sh8013</contact:id><contact:chg><contact:email>new-ops@example.test</contact:email></contact:chg></contact:update></update><clTRID>epp-09-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><update><contact:update xmlns:contact="urn:ietf:params:xml:ns:contact-1.0"><contact:id>sh8013</contact:id><contact:chg><contact:email>invalid-email</contact:email></contact:chg></contact:update></update><clTRID>epp-09-fail</clTRID></command></epp>
```

### epp-10

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><delete><contact:delete xmlns:contact="urn:ietf:params:xml:ns:contact-1.0"><contact:id>deletable-contact</contact:id></contact:delete></delete><clTRID>epp-10-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><delete><contact:delete xmlns:contact="urn:ietf:params:xml:ns:contact-1.0"><contact:id>linked-contact</contact:id></contact:delete></delete><clTRID>epp-10-fail</clTRID></command></epp>
```

### epp-11

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><create><host:create xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>ns1.example.test</host:name></host:create></create><clTRID>epp-11-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><create><host:create xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>invalid host</host:name></host:create></create><clTRID>epp-11-fail</clTRID></command></epp>
```

### epp-12

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><update><host:update xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>self-owned-host</host:name></host:update></update><clTRID>epp-12-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><update><host:update xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>other-owned-host</host:name></host:update></update><clTRID>epp-12-fail</clTRID></command></epp>
```

### epp-13

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><update><host:update xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>ns1.example.test</host:name><host:add><host:addr ip="v4">192.0.2.44</host:addr></host:add></host:update></update><clTRID>epp-13-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><update><host:update xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>ns1.example.test</host:name><host:add><host:addr ip="v4">999.999.999.999</host:addr></host:add></host:update></update><clTRID>epp-13-fail</clTRID></command></epp>
```

### epp-14

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><create><domain:create xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>new-example.test</domain:name><domain:period unit="y">1</domain:period></domain:create></create><clTRID>epp-14-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><create><domain:create xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>invalid domain</domain:name></domain:create></create><clTRID>epp-14-fail</clTRID></command></epp>
```

### epp-15

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><info><domain:info xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>consistent-example.test</domain:name></domain:info></info><clTRID>epp-15-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><info><domain:info xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>inconsistent-example.test</domain:name></domain:info></info><clTRID>epp-15-fail</clTRID></command></epp>
```

### epp-16

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><update><domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>example.test</domain:name></domain:update></update><clTRID>epp-16-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><update><domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>bad domain</domain:name></domain:update></update><clTRID>epp-16-fail</clTRID></command></epp>
```

### epp-17

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><hello/></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><check><domain:check xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>example.test</domain:name></domain:check></check><clTRID>epp-17-fail-port</clTRID></command></epp>
```

### epp-18

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><renew><domain:renew xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>example.test</domain:name><domain:curExpDate>2026-12-01</domain:curExpDate><domain:period unit="y">1</domain:period></domain:renew></renew><clTRID>epp-18-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><renew><domain:renew xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>example.test</domain:name><domain:curExpDate>invalid-date</domain:curExpDate></domain:renew></renew><clTRID>epp-18-fail</clTRID></command></epp>
```

### epp-19

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><transfer op="request"><domain:transfer xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>example.test</domain:name><domain:authInfo><domain:pw>AUTH-CODE</domain:pw></domain:authInfo></domain:transfer></transfer><clTRID>epp-19-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><transfer op="request"><domain:transfer xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>example.test</domain:name><domain:authInfo><domain:pw>WRONG-CODE</domain:pw></domain:authInfo></domain:transfer></transfer><clTRID>epp-19-fail</clTRID></command></epp>
```

### epp-20

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><transfer op="reject"><domain:transfer xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>example.test</domain:name></domain:transfer></transfer><clTRID>epp-20-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><transfer op="reject"><domain:transfer xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>no-pending-transfer.test</domain:name></domain:transfer></transfer><clTRID>epp-20-fail</clTRID></command></epp>
```

### epp-21

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><delete><domain:delete xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>deletable-example.test</domain:name></domain:delete></delete><clTRID>epp-21-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><delete><domain:delete xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>linked-example.test</domain:name></domain:delete></delete><clTRID>epp-21-fail</clTRID></command></epp>
```

### epp-22 (removed in v2026.04, kept for matrix continuity)

- Reference XML:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><update><domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>example.test</domain:name></domain:update></update><extension><rgp:update xmlns:rgp="urn:ietf:params:xml:ns:rgp-1.0"><rgp:restore op="request"/></rgp:update></extension><clTRID>epp-22-reference</clTRID></command></epp>
```

### epp-23

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><update><host:update xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>old-ns.example.test</host:name><host:chg><host:name>new-ns.example.test</host:name></host:chg></host:update></update><clTRID>epp-23-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><update><host:update xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>externally-linked.example.test</host:name><host:chg><host:name>rename-denied.example.test</host:name></host:chg></host:update></update><clTRID>epp-23-fail</clTRID></command></epp>
```

### epp-24

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><delete><host:delete xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>orphan-ns.example.test</host:name></host:delete></delete><clTRID>epp-24-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><delete><host:delete xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>linked-ns.example.test</host:name></host:delete></delete><clTRID>epp-24-fail</clTRID></command></epp>
```

### epp-25

- Success:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><create><host:create xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>ns1.example.test</host:name></host:create></create><clTRID>epp-25-ok</clTRID></command></epp>
```

- Failure:

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><create><host:create xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>ns1.other-client.test</host:name></host:create></create><clTRID>epp-25-fail</clTRID></command></epp>
```

### epp-26

- Success (policy rejection is expected behavior):

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><create><host:create xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>ns1.other-client.example.test</host:name><host:addr ip="v4">192.0.2.44</host:addr></host:create></create><clTRID>epp-26-expected-reject</clTRID></command></epp>
```

- Failure (unexpected accept):

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><create><host:create xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>ns1.other-client.example.test</host:name><host:addr ip="v4">192.0.2.44</host:addr></host:create></create><clTRID>epp-26-unexpected-accept</clTRID></command></epp>
```

### epp-27

- Success step 1 (create glueless host):

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><create><host:create xmlns:host="urn:ietf:params:xml:ns:host-1.0"><host:name>ns2.other-client.example.test</host:name></host:create></create><clTRID>epp-27-create-ok</clTRID></command></epp>
```

- Success step 2 (delegation rejected):

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><update><domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>other-client.example.test</domain:name><domain:add><domain:ns><domain:hostObj>ns2.other-client.example.test</domain:hostObj></domain:ns></domain:add></domain:update></update><clTRID>epp-27-delegate-reject</clTRID></command></epp>
```

- Failure (unexpected accept of forbidden delegation):

```xml
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><command><update><domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"><domain:name>other-client.example.test</domain:name><domain:add><domain:ns><domain:hostObj>ns2.other-client.example.test</domain:hostObj></domain:ns></domain:add></domain:update></update><clTRID>epp-27-unexpected-accept</clTRID></command></epp>
```

