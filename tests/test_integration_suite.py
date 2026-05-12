"""Tests for the StandardIntegrationTest suite (integration-01 ... integration-05)."""
from __future__ import annotations

from rst_compliance.integration_suite import (
    DnsPropagationObservation,
    GluePolicyObservation,
    Integration01RdapPropagationChecker,
    Integration02DnsPropagationChecker,
    Integration03RdePropagationChecker,
    Integration04HostObjectGlueChecker,
    Integration05HostAttributeGlueChecker,
    IntegrationSuiteConfig,
    RdapPropagationObservation,
    RdePropagationObservation,
    StandardIntegrationTestSuite,
)


def test_integration_01_rdap_propagation_passes() -> None:
    result = Integration01RdapPropagationChecker(
        IntegrationSuiteConfig(rdap_observations=[RdapPropagationObservation("example.test", "domain", 200, True)])
    ).run()

    assert result.passed


def test_integration_01_rdap_propagation_reports_missing_object() -> None:
    result = Integration01RdapPropagationChecker(
        IntegrationSuiteConfig(rdap_observations=[RdapPropagationObservation("example.test", "domain", 404, False)])
    ).run()

    assert not result.passed
    assert {error.code for error in result.errors} == {"INTEGRATION_RDAP_REQUEST_FAILED", "INTEGRATION_DOMAIN_NOT_PRESENT_IN_RDAP"}


def test_integration_02_dns_propagation_passes() -> None:
    result = Integration02DnsPropagationChecker(
        IntegrationSuiteConfig(dns_observations=[DnsPropagationObservation("example.test", "ns1.example", True)])
    ).run()

    assert result.passed


def test_integration_03_rde_propagation_reports_sftp_authentication_error() -> None:
    result = Integration03RdePropagationChecker(
        IntegrationSuiteConfig(rde_observations=[RdePropagationObservation("example.test", True, authenticated=False)])
    ).run()

    assert not result.passed
    assert any(error.code == "INTEGRATION_RDE_SFTP_SERVER_AUTHENTICATION_ERROR" for error in result.errors)


def test_integration_04_host_object_glue_policy_pass_and_skip() -> None:
    passing = Integration04HostObjectGlueChecker(
        IntegrationSuiteConfig(
            host_model="objects",
            host_object_glue_observations=[
                GluePolicyObservation("linked.example", True, True),
                GluePolicyObservation("unlinked.example", False, False),
            ],
        )
    ).run()
    skipped = Integration04HostObjectGlueChecker(IntegrationSuiteConfig(host_model="attributes")).run()

    assert passing.passed
    assert skipped.skipped


def test_integration_05_host_attribute_glue_reports_unexpected_glue() -> None:
    result = Integration05HostAttributeGlueChecker(
        IntegrationSuiteConfig(
            host_model="attributes",
            host_attribute_glue_observations=[GluePolicyObservation("unexpected.example", False, True)],
        )
    ).run()

    assert not result.passed
    assert any(error.code == "INTEGRATION_UNEXPECTED_GLUE_OBSERVED" for error in result.errors)


def test_standard_integration_suite_runs_all_five_cases() -> None:
    config = IntegrationSuiteConfig(
        rdap_observations=[RdapPropagationObservation("example.test", "domain", 200, True)],
        dns_observations=[DnsPropagationObservation("example.test", "ns1.example", True)],
        rde_observations=[RdePropagationObservation("example.test", True)],
        host_object_glue_observations=[GluePolicyObservation("linked.example", True, True)],
    )

    results = StandardIntegrationTestSuite(config).run_all()

    assert [result.test_id for result in results] == [
        "integration-01",
        "integration-02",
        "integration-03",
        "integration-04",
        "integration-05",
    ]
