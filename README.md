> [!TIP]
> [Click here to go directly to the current RST test
> specifications.](https://icann.github.io/rst-test-specs/rst-test-specs.html)

> [!NOTE]
> Releases of the RST v2.0 test specifications do not always align with releases
> of the RST v2.0 service, as it is often necessary to publish an update to the
> test specs before the corresponding update to the test system.
>
> As described in the [API spec](https://github.com/icann/rst-api-spec), the
> `testPlan` property of test objects includes the version of the test specs
> that is used for performing tests. This can be used to determine which version
> of the test specs is currently deployed in the given environment (OT&E or
> production).

This repository contains the specifications for ICANN's [Registry System Testing
(RST)](https://icann.org/resources/registry-system-testing-v2.0) v2.0 service.

## Repository Contents

* The files in [inc/](inc/) are what you need to edit if you want to make
  changes to the test specifications.

* [rst-test-spec-schema.yaml](rst-test-spec-schema.yaml) is a schema for the
  YAML spec file.

* [zonemaster-test-policies.yaml](zonemaster-test-policies.yaml) contains
  policies that are applied to Zonemaster tests when generating the spec files
  and the Zonemaster profile.

* The [data](data) directory contains the XLSX files from which the [data
  providers](https://icann.github.io/rst-test-specs/rst-test-specs.html#Preamble-2.3.2.-Data-providers)
  are generated.

* The [resources](resources) directory contains static
  [resources](https://icann.github.io/rst-test-specs/rst-test-specs.html#Preamble-2.3.3.-Resources).

* The [.env](.env) file specifies which version of Zonemaster should be used to
  generate DNS and DNSSEC test cases, and their associated error codes.
  [zonemaster-test-policies.yaml](zonemaster-test-policies.yaml) controls how
  the Zonemaster test cases and documentation should be incorporated into the
  RST specs.

## Building the specification

The simplest way to build the specification is to run `docker compose run spec`
(you obviously need Docker). The first run will take a while as it needs to
build the image, but it will be quite fast after that.

## Python Pytest scaffold for RST v2026.04 compliance

A Python-based Pytest scaffold is available for developing automated compliance
tests for RST v2026.04 in:

* `src/rst_compliance/` (RST API trigger client, schema validators, log model)
* `tests/` (service trigger, schema validation, and log tests)
* `schemas/rst-api-spec/v2026.4/` (location for official JSON/XML schemas)
* `config.json` (environment configuration for Sandbox vs. Production)

To run it:

1. Create a virtual environment.
2. Install the project in editable mode: `pip install -e .`
3. Run tests: `pytest`

### Module overview

| Module | Purpose |
|---|---|
| `client.py` | RST API trigger client (Bearer auth, POST /v2/tests/trigger) |
| `lifecycle.py` | RST v2.0 lifecycle state machine: Create → Submit → Poll → Retrieve |
| `input_generator.py` | Pydantic-based input parameter generator for StandardPreDelegationTest and RSPEvaluation |
| `epp_client.py` | EPP mTLS client (RSA-4096, TLS 1.3, Narrow Glue Policy checks) |
| `rdap_conformance.py` | RDAP conformance checks (SLA < 400 ms, mandatory fields, registry data model) |
| `dnssec_zone_health.py` | DNSSEC zone health checks (algorithm rollover, DS-to-DNSKEY, Zonemaster tag mapping) |
| `tlsa_check.py` | TLSA/DANE record verification (RFC 6698, SHA-256/SHA-512, full-cert/SPKI selectors) |
| `idn_lgr.py` | IDN label validation using LGR rules for .th/.ไทย (IDNA2008, Thai Unicode block) |
| `rde_deposit_helper.py` | RDE-13 deposit validation (filename, registrar/NNDN uniqueness, ICANN manifest) |
| `testcase_log.py` | TestCaseLog model and ERROR/CRITICAL tag extraction from ICANN API responses |
| `fips_check.py` | FIPS 140-3 HSM mode probe (simulated PKCS#11) |
| `rst_dashboard.py` | Pytest-HTML dashboard mapping results to ICANN test case IDs |
| `schema_validation.py` | JSON Schema and XSD validation helpers |

### Environment configuration (`config.json`)

Switch between Sandbox (OT&E) and Production by editing `config.json`:

```json
{
  "active_environment": "sandbox"
}
```

Set credentials and endpoints in the corresponding environment block, or
override individual fields via environment variables (e.g. `EPP_HOST`,
`EPP_CERT`, `EPP_KEY`).

### RST v2.0 lifecycle state machine

Drive the full four-phase lifecycle programmatically:

```python
from rst_compliance.lifecycle import RstLifecycleClient
from rst_compliance.config import RstApiConfig

client = RstLifecycleClient(RstApiConfig(base_url="https://rst-ote.icann.org", auth_token="…"))
lc, results = client.run_full_lifecycle(
    test_plan="StandardPreDelegationTest",
    tld="example",
    service="DNS",
    input_parameters={"dns.tld": "example", "dns.nameservers": ["ns1.example.test"]},
)
print(lc.state, lc.error_tags)
```

### Input Parameter Generator

Generate well-formed RST API payloads from Pydantic models:

```python
from rst_compliance.input_generator import StandardPreDelegationTestInput, RdapBaseUrls

spdt = StandardPreDelegationTestInput(
    tld="example",
    ns_hostnames=["ns1.example.test", "ns2.example.test"],
    rdap_base_urls=RdapBaseUrls(domain="https://rdap.example.test/"),
)
payload = spdt.to_api_payload()
```

### TLSA/DANE verification

Verify a certificate against TLSA DNS records (RFC 6698):

```python
from rst_compliance.tlsa_check import verify_tlsa_records

results = verify_tlsa_records(pem_bytes, ["3 1 1 <sha256-hex>"])
```

### IDN/LGR validation for .th / .ไทย

```python
from rst_compliance.idn_lgr import validate_idn_domain

results = validate_idn_domain("สวัสดี.ไทย", tld="th")
```

### Internal checker workspace

An `internal-rst-checker/` workspace is included for keeping module-specific
checks together:

* `internal-rst-checker/tests/epp/`
* `internal-rst-checker/tests/rdap/`
* `internal-rst-checker/tests/dns/`
* `internal-rst-checker/schemas/json/` and `internal-rst-checker/schemas/xml/`
* `internal-rst-checker/reports/`
* `internal-rst-checker/rst_dashboard.py`

Run the dashboard to map specs from `tests/`, execute tests with `pytest`, print
a terminal summary table (Pass/Fail + reason), and write reports into
`internal-rst-checker/reports/`:

`python internal-rst-checker/rst_dashboard.py`

The HTML dashboard is generated by `pytest-html` as:

* `internal-rst-checker/reports/report.html`

### DNSSEC zone health helper script

For RST v2026.04 DNSSEC checks aligned with Zonemaster v2025.2.1, use:

`python -m rst_compliance.dnssec_zone_health --parent-ds-file <file> --child-dnskey-file <file> --zonemaster-output <file>`

The script validates DNSSEC algorithm rollover readiness (RSA/SHA-256 and
ECDSA P-256), checks DS-to-DNSKEY alignment, and maps parsed Zonemaster tags to
RST DNSSEC error codes.

### RDE deposit validation helper script

For RST v2026.04 RDE checks (including `rde-13` review updates for registrar and
NNDN uniqueness), use:

`python -m rst_compliance.rde_deposit_helper --xml-file <decrypted-rde-xml> --deposit-filename <deposit.ryde> --signature-filename <deposit.sig> --public-key-filename <key.asc> --tld <tld> --manifest-output <manifest.json>`

The script validates deposit filename constraints aligned with v2026.4,
validates registrar and NNDN uniqueness in XML deposits, and generates an
ICANN-style input manifest (`inputTemplateVersion`, `service`, and
`inputParameters`).

## Releasing a new version

1. Make the changes you want to make.
2. Once committed, tag the commit. The tag **MUST** take the form `vYYYY.DD`
   where `YYYY` is the current year and `DD` is a two-digit serial number that
   resets to `01` at the start of each year. Then push the tag to GitHub using
   `git push --tags`.
3. Create a new [release](https://github.com/icann/rst-test-specs/releases/new)
   using the tag.

Since the [RST API spec](https://github.com/icann/rst-api-spec) includes data
elements from the test specs, every time a new version of the RST spec is
released, a [new version of the API
spec](https://github.com/icann/rst-api-spec?tab=readme-ov-file#releasing-a-new-version)
must also be released, in order to incorporate any changes to those data
elements.

### EPP Extension List, RDAP Conformance Tool and Zonemaster configuration

Unlike the test specs, changes to the [EPP Extensions
List](epp-extensions/README.md), and configuration files for the [RDAP
Conformance Tool](tools/generate-rdapct-config.pl) and
[Zonemaster](tools/generate-zonemaster-profile.pl) do not require creation of a
new release. Just update the appropriate files, and commit to the `main` branch,
and the [`build-pages`](.github/workflows/build-pages.yaml) workflow will
generate and publish the updated files. The RST system will pick them up
automatically (after cache expiration).

### Updating the Zonemaster version used

To change the version of Zonemaster used, edit [.env](.env) and set the
`ZONEMASTER_VERSION` and `ZONEMASTER_ENGINE_VERSION` variables accordingly. Then
generate the specs.

Quite often, a new release of Zonemaster will add, remove or change the error
codes that are generated. So before publishing a new version of the test specs,
the delta between the old and new versions should be manually inspected, to
ensure that any changes are acceptable and appropriate.

## See Also

* [RST API Specification](https://icann.github.io/rst-api-spec) ([GitHub
  repository](https://github.com/icann/rst-api-spec))
* [IDN test labels for RST v2.0](https://github.com/icann/rst-idn-test-labels)

## Copyright Statement

This repository is (c) 2025 Internet Corporation for Assigned Names and Numbers
(ICANN). All rights reserved.
