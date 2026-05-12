"""Tests for the StandardIDN test suite (idn-01, idn-02)."""
from __future__ import annotations

from rst_compliance.idn_suite import (
    Idn01LabelValidationChecker,
    Idn02AsciiIdnOnlyChecker,
    IdnAsciiCreateObservation,
    IdnDomainCreateObservation,
    IdnSuiteConfig,
    IdnVariantObservation,
    StandardIdnTestSuite,
)


def test_idn_01_valid_labels_and_blocked_variants_pass() -> None:
    config = IdnSuiteConfig(
        domain_create_extension_xml='<extension xmlns="urn:ietf:params:xml:ns:epp-1.0"><idn/></extension>',
        domain_create_observations=[
            IdnDomainCreateObservation("xn--valid.example", expected_valid=True, accepted=True),
            IdnDomainCreateObservation("xn--invalid.example", expected_valid=False, accepted=False),
        ],
        variant_observations=[
            IdnVariantObservation("xn--blocked.example", policy="blocked", same_registrar=True, same_registrant=True, accepted=False),
        ],
    )

    result = Idn01LabelValidationChecker(config).run()

    assert result.passed


def test_idn_01_reports_invalid_label_and_variant_policy_failures() -> None:
    config = IdnSuiteConfig(
        domain_create_observations=[
            IdnDomainCreateObservation("xn--bad.example", expected_valid=False, accepted=True),
            IdnDomainCreateObservation("xn--good.example", expected_valid=True, accepted=False),
        ],
        variant_observations=[
            IdnVariantObservation("xn--variant.example", policy="same-registrant", same_registrar=True, same_registrant=False, accepted=True),
        ],
    )

    result = Idn01LabelValidationChecker(config).run()

    assert not result.passed
    codes = {error.code for error in result.errors}
    assert "IDN_SERVER_ACCEPTS_INVALID_LABEL" in codes
    assert "IDN_SERVER_REJECTS_VALID_LABEL" in codes
    assert "IDN_VARIANT_SERVER_ACCEPTS_VARIANT_CREATE_WITH_INCORRECT_REGISTRANT" in codes


def test_idn_02_ascii_rejection_and_skip() -> None:
    passing = Idn02AsciiIdnOnlyChecker(
        IdnSuiteConfig(ascii_create_observations=[IdnAsciiCreateObservation("ascii.example", "example", True, False)])
    ).run()
    skipped = Idn02AsciiIdnOnlyChecker(
        IdnSuiteConfig(ascii_create_observations=[IdnAsciiCreateObservation("ascii.test", "test", False, True)])
    ).run()

    assert passing.passed
    assert skipped.skipped


def test_standard_idn_suite_runs_both_cases() -> None:
    config = IdnSuiteConfig(
        domain_create_observations=[IdnDomainCreateObservation("xn--valid.example", expected_valid=True, accepted=True)],
        ascii_create_observations=[IdnAsciiCreateObservation("ascii.example", "example", True, False)],
    )

    results = StandardIdnTestSuite(config).run_all()

    assert [result.test_id for result in results] == ["idn-01", "idn-02"]
