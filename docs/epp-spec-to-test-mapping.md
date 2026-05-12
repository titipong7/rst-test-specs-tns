# StandardEPP Spec-to-Test Mapping (1:1)

This table maps each StandardEPP case in the v2026.04 specification to the
internal checker test function currently used in this repository.

Source spec section: `5.4.2 Test cases` in `rst-test-specs-0.html`.
Live coverage status below is synced from `internal-rst-checker/reports/report.json`
(generatedAt: `2026-05-11T08:59:19.426355+00:00`).


| Spec Case | Spec Title                                                   | Internal Test Function                                        | Test File                                                                                                                                                         | Mapping Status  | Coverage Status |
| --------- | ------------------------------------------------------------ | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | --------------- |
| epp-01    | Service connectivity test                                    | `test_epp_service_connectivity_smoke_epp_01`, `test_epp01_*`  | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`, `tests/test_epp_connectivity.py`, `src/rst_compliance/epp_connectivity.py`                  | mapped          | covered         |
| epp-02    | Protocol conformance test                                    | `test_epp_protocol_extension_shape_validation_epp_02`         | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py` (plus branch coverage in `tests/test_epp_host_constraints.py`, helper in `src/rst_compliance/epp_client.py`) | mapped          | covered         |
| epp-03    | Authentication test                                          | `test_epp_authentication_rejects_invalid_login_epp_03`        | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py` (plus branch coverage in `tests/test_epp_host_constraints.py`, helper in `src/rst_compliance/epp_client.py`) | mapped          | covered         |
| epp-04    | Domain `<check>` command test                                | `test_epp_domain_check_command_smoke_epp_04`                  | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py` (plus branch coverage in `tests/test_epp_host_constraints.py`, helper in `src/rst_compliance/epp_client.py`) | mapped          | covered         |
| epp-05    | Host `<check>` command test (if applicable)                  | `test_epp_host_check_command_smoke_epp_05`                    | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-06    | Contact `<check>` command test (if applicable)               | `test_epp_contact_check_command_smoke_epp_06`                 | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-07    | Contact `<create>` command test (if applicable)              | `test_epp_contact_create_command_smoke_epp_07`                | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-08    | Contact object access control (if applicable)                | `test_epp_contact_object_access_control_smoke_epp_08`         | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-09    | Contact `<update>` command test (if applicable)              | `test_epp_contact_update_command_smoke_epp_09`                | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-10    | Contact `<delete>` command test (if applicable)              | `test_epp_contact_delete_command_smoke_epp_10`                | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-11    | Host `<create>` command test (if applicable)                 | `test_epp_host_create_command_smoke_epp_11`                   | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-12    | Host object access control (if applicable)                   | `test_epp_host_object_access_control_smoke_epp_12`            | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-13    | Host `<update>` command test (if applicable)                 | `test_epp_host_update_command_smoke_epp_13`                   | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-14    | Domain `<create>` command test                               | `test_epp_domain_create_smoke_epp_14`                         | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-15    | Registry object integrity test (if applicable)               | `test_epp_registry_object_integrity_smoke_epp_15`             | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-16    | Domain `<update>` command test                               | `test_epp_domain_update_smoke_epp_16`                         | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-17    | Service Port consistency test                                | `test_epp_service_port_consistency_smoke_epp_17`              | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-18    | Domain `<renew>` command test                                | `test_epp_domain_renew_command_smoke_epp_18`                  | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-19    | Domain `<transfer>` command test                             | `test_epp_domain_transfer_command_smoke_epp_19`               | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-20    | Domain `<transfer>` rejection test                           | `test_epp_domain_transfer_rejection_smoke_epp_20`             | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-21    | Domain `<delete>` command test                               | `test_epp_domain_delete_command_smoke_epp_21`                 | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-22    | Domain restore test (removed from v2026.04)                  | N/A                                                           | N/A                                                                                                                                                               | removed-in-spec | partial         |
| epp-23    | Host rename test (if applicable)                             | `test_epp_host_rename_command_smoke_epp_23`                   | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-24    | Host `<delete>` command test (if applicable)                 | `test_epp_host_delete_command_smoke_epp_24`                   | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-25    | Subordinate host `<create>` command test (if applicable)     | `test_epp_subordinate_host_create_command_smoke_epp_25`       | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py`                                                                                                 | mapped          | covered         |
| epp-26    | Wide glue host object access control (if applicable)         | `test_epp_wide_glue_policy_smoke_epp_26`                      | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py` (plus policy-focused coverage in `internal-rst-checker/tests/epp/test_epp_host_constraints.py`) | mapped          | covered         |
| epp-27    | Glueless internal host object access control (if applicable) | `test_epp_glueless_internal_host_access_control_smoke_epp_27` | `internal-rst-checker/tests/epp/test_epp_standard_suite_smoke.py` (plus policy-focused coverage in `internal-rst-checker/tests/epp/test_epp_host_constraints.py`) | mapped          | covered         |


## Quick Notes

- Tests marked "if applicable" intentionally use conditional variants/skip
patterns in the test implementation.
- Dashboard mapping is driven by `epp-xx` labels in test names/docstrings.
- epp-01 now uses hybrid full-spec checks (live probe entrypoint in dashboard + offline mocked branches for CI).
- epp-02..epp-04 now include Batch 1 full-spec rule checks with dedicated branch assertions.
- epp-05..epp-27 use shared rule helpers for check semantics and success/failure flow validation, while preserving per-case `epp-xx` mapping names.
- Latest report summary: `covered=26`, `partial=1`, `missing=0`.


## Non-EPP Suite Fixture Pointers

Each non-EPP suite now ships fixtures and a per-suite guard test under
`internal-rst-checker/`. The table below maps each suite to its fixture
folder and the guard test that enforces presence + syntactic validity.

> **Layout note.** DNS / DNSSEC / RDE / RDAP / SRSGW / IDN / Integration
> have been re-aligned to the flat EPP-style layout
> (`<nn>-<slug>-{success,failure}.<ext>` directly under the suite
> folder). DNSSEC-Ops still uses per-case sub-folders; its alignment is
> tracked as a separate follow-up.

| Suite          | Spec ids                                                                                       | Fixture folder                                                       | Guard test                                                              |
| -------------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| DNS            | `dns-zz-idna2008-compliance`, `dns-zz-consistency`                                              | `internal-rst-checker/fixtures/dns/`                                 | `internal-rst-checker/tests/dns/test_dns_fixtures_present.py`           |
| DNSSEC         | `dnssec-91`, `dnssec-92`, `dnssec-93`                                                            | `internal-rst-checker/fixtures/dnssec/`                              | `internal-rst-checker/tests/dnssec/test_dnssec_fixtures_present.py`     |
| DNSSEC-Ops     | `dnssecOps01-ZSKRollover`, `dnssecOps02-KSKRollover`, `dnssecOps03-AlgorithmRollover`            | `internal-rst-checker/fixtures/dnssec-ops/`                          | `internal-rst-checker/tests/dnssec_ops/test_dnssec_ops_fixtures_present.py` |
| RDE            | `rde-01..14`                                                                                    | `internal-rst-checker/fixtures/rde/`                                 | `internal-rst-checker/tests/rde/test_rde_fixtures_present.py`           |
| RDAP           | `rdap-01..10`, `rdap-91`, `rdap-92`                                                              | `internal-rst-checker/fixtures/rdap/`                                | `internal-rst-checker/tests/rdap/test_rdap_fixtures_present.py`         |
| SRSGW          | `srsgw-01..06`, `srsgw-08..15` (`srsgw-07` merged into `srsgw-06`)                               | `internal-rst-checker/fixtures/srsgw/`                               | `internal-rst-checker/tests/srsgw/test_srsgw_fixtures_present.py`       |
| IDN            | `idn-01`, `idn-02`                                                                              | `internal-rst-checker/fixtures/idn/`                                 | `internal-rst-checker/tests/idn/test_idn_fixtures_present.py`           |
| Integration    | `integration-01..05`                                                                            | `internal-rst-checker/fixtures/integration/`                         | `internal-rst-checker/tests/integration/test_integration_fixtures_present.py` |

See `internal-rst-checker/fixtures/README.md` for the per-suite case
tables, placeholder conventions, and skip-condition documentation.