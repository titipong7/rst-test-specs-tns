"""Tests for the StandardSRSGateway test suite."""
from __future__ import annotations

from rst_compliance.srsgw_suite import (
    Srsgw01ConnectivityChecker,
    Srsgw02HostCreateChecker,
    Srsgw03ContactCreateChecker,
    Srsgw04DomainCreateChecker,
    Srsgw13DomainRdapChecker,
    SrsgwConnectivityObservation,
    SrsgwRdapObservation,
    SrsgwSuiteConfig,
    SrsgwSyncObservation,
    StandardSrsgwTestSuite,
)


def _complete_config() -> SrsgwSuiteConfig:
    sync_observations = [
        SrsgwSyncObservation(case_id, f"{case_id}.example", 1000)
        for case_id in ("srsgw-02", "srsgw-03", "srsgw-04", "srsgw-05", "srsgw-06", "srsgw-08", "srsgw-09", "srsgw-10", "srsgw-11", "srsgw-12")
    ]
    rdap_observations = [
        SrsgwRdapObservation("srsgw-13", "example.test", 200, True),
        SrsgwRdapObservation("srsgw-14", "ns1.example.test", 200, True),
        SrsgwRdapObservation("srsgw-15", "registrar-1", 200, True),
    ]
    return SrsgwSuiteConfig(
        connectivity_observations=[
            SrsgwConnectivityObservation("ipv4", True),
            SrsgwConnectivityObservation("ipv6", True),
        ],
        sync_observations=sync_observations,
        rdap_observations=rdap_observations,
    )


def test_srsgw_01_connectivity_passes_for_ipv4_and_ipv6() -> None:
    result = Srsgw01ConnectivityChecker(_complete_config()).run()

    assert result.passed


def test_srsgw_01_reports_missing_ipv6_probe() -> None:
    result = Srsgw01ConnectivityChecker(
        SrsgwSuiteConfig(connectivity_observations=[SrsgwConnectivityObservation("ipv4", True)])
    ).run()

    assert not result.passed
    assert any(error.code == "EPP_NO_SERVICE_PORTS_REACHABLE" for error in result.errors)


def test_srsgw_sync_checker_reports_gateway_failure() -> None:
    result = Srsgw04DomainCreateChecker(
        SrsgwSuiteConfig(sync_observations=[SrsgwSyncObservation("srsgw-04", "example.test", 2400)])
    ).run()

    assert not result.passed
    assert any(error.code == "SRSGW_DOMAIN_CREATE_FAILED" for error in result.errors)


def test_srsgw_host_and_contact_applicability_skips() -> None:
    host_result = Srsgw02HostCreateChecker(SrsgwSuiteConfig(host_model="attributes")).run()
    contact_result = Srsgw03ContactCreateChecker(SrsgwSuiteConfig(registry_data_model="minimum")).run()

    assert host_result.skipped
    assert contact_result.skipped


def test_srsgw_rdap_checker_reports_property_mismatch() -> None:
    result = Srsgw13DomainRdapChecker(
        SrsgwSuiteConfig(rdap_observations=[SrsgwRdapObservation("srsgw-13", "example.test", 200, True, properties_match=False)])
    ).run()

    assert not result.passed
    assert any(error.code == "SRSGW_DOMAIN_RDAP_HAS_MISSING_OR_INVALID_PROPERTIES" for error in result.errors)


def test_standard_srsgw_suite_runs_all_fourteen_cases() -> None:
    results = StandardSrsgwTestSuite(_complete_config()).run_all()

    assert len(results) == 14
    assert results[0].test_id == "srsgw-01"
    assert results[-1].test_id == "srsgw-15"
