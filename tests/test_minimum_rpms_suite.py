"""Tests for the MinimumRPMs test suite."""
from __future__ import annotations

from rst_compliance.minimum_rpms_suite import (
    ClaimsCheckObservation,
    MinimumRpms01ClaimsCheckChecker,
    MinimumRpms02SunriseCreateChecker,
    MinimumRpms03TrademarkClaimsCreateChecker,
    MinimumRpmsSuiteConfig,
    MinimumRpmsTestSuite,
    RpmsCreateObservation,
)


EPP_SUCCESS = '<epp><response><result code="1000"/></response></epp>'
EPP_FAILURE = '<epp><response><result code="2306"/></response></epp>'


def test_minimum_rpms_01_claims_check_passes() -> None:
    config = MinimumRpmsSuiteConfig(
        launch_extension_xml='<extension xmlns="urn:ietf:params:xml:ns:epp-1.0"><launch:check xmlns:launch="urn:ietf:params:xml:ns:launch-1.0"/></extension>',
        claims_checks=[
            ClaimsCheckObservation("dnl.example", present_on_dnl=True, claim_key="abc123"),
            ClaimsCheckObservation("plain.example", present_on_dnl=False, claim_key=None),
        ],
    )

    result = MinimumRpms01ClaimsCheckChecker(config).run()

    assert result.passed


def test_minimum_rpms_01_reports_missing_and_unexpected_claim_keys() -> None:
    config = MinimumRpmsSuiteConfig(
        claims_checks=[
            ClaimsCheckObservation("dnl.example", present_on_dnl=True, claim_key=None),
            ClaimsCheckObservation("plain.example", present_on_dnl=False, claim_key="abc123"),
        ]
    )

    result = MinimumRpms01ClaimsCheckChecker(config).run()

    assert not result.passed
    assert {error.code for error in result.errors} == {"RPMS_MISSING_CLAIMS_KEY", "RPMS_UNEXPECTED_CLAIMS_KEY"}


def test_minimum_rpms_02_sunrise_create_validates_expected_outcomes() -> None:
    result = MinimumRpms02SunriseCreateChecker(
        MinimumRpmsSuiteConfig(
            sunrise_creates=[
                RpmsCreateObservation("valid-smd", expected_success=True, response_xml=EPP_SUCCESS),
                RpmsCreateObservation("invalid-smd", expected_success=False, response_xml=EPP_FAILURE),
            ]
        )
    ).run()

    assert result.passed


def test_minimum_rpms_03_trademark_claims_reports_invalid_notice_success() -> None:
    result = MinimumRpms03TrademarkClaimsCreateChecker(
        MinimumRpmsSuiteConfig(
            trademark_claims_creates=[
                RpmsCreateObservation("invalid-notice", expected_success=False, response_xml=EPP_SUCCESS),
            ]
        )
    ).run()

    assert not result.passed
    assert any(error.code == "RPMS_TRADEMARK_CREATE_UNEXPECTED_SUCCESS_USING_INVALID_NOTICE_ID" for error in result.errors)


def test_minimum_rpms_suite_runs_all_three_cases() -> None:
    config = MinimumRpmsSuiteConfig(
        claims_checks=[ClaimsCheckObservation("dnl.example", present_on_dnl=True, claim_key="abc123")],
        sunrise_creates=[RpmsCreateObservation("valid-smd", expected_success=True, response_xml=EPP_SUCCESS)],
        trademark_claims_creates=[RpmsCreateObservation("valid-notice", expected_success=True, response_xml=EPP_SUCCESS)],
    )

    results = MinimumRpmsTestSuite(config).run_all()

    assert [result.test_id for result in results] == ["minimumRPMs-01", "minimumRPMs-02", "minimumRPMs-03"]
