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

To run it:

1. Create a virtual environment.
2. Install the project in editable mode: `pip install -e .`
3. Run tests: `pytest`

The scaffold also includes a DNSSEC helper CLI that performs a focused RST
v2026.04-style health check for:

* algorithm rollover readiness using `RSASHA256` (algorithm 8) and
  `ECDSAP256SHA256` (algorithm 13);
* parent `DS` to child `DNSKEY` matching;
* Zonemaster error-tag normalization into `ZM_*` RST error codes.

Run it with:

```sh
rst-dnssec-zone-health example.tld --zonemaster-output /path/to/zonemaster-output.json
```

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
