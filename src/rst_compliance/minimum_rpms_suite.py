"""MinimumRPMs test suite checkers for RST v2026.04.

Implements all three MinimumRPMs test cases from the RST specification:
  - minimumRPMs-01: Claims check command behavior
  - minimumRPMs-02: Sunrise create command behavior
  - minimumRPMs-03: Trademark claims create command behavior

All checkers follow the same dependency-injection pattern as RDAP/DNS/RDE suites.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from rst_compliance.epp_client import EppClient


@dataclass(frozen=True)
class MinimumRpmsTestError:
    """Structured error produced by any MinimumRPMs test case."""
    code: str
    severity: str
    detail: str


@dataclass
class MinimumRpmsTestResult:
    """Aggregated result of a single MinimumRPMs test case run."""
    test_id: str
    passed: bool = True
    skipped: bool = False
    errors: list[MinimumRpmsTestError] = field(default_factory=list)

    def add_error(self, code: str, severity: str, detail: str) -> None:
        self.errors.append(MinimumRpmsTestError(code=code, severity=severity, detail=detail))
        if severity in ("ERROR", "CRITICAL"):
            self.passed = False

    def skip(self, reason: str) -> None:
        self.skipped = True
        self.errors.append(MinimumRpmsTestError(code="SKIPPED", severity="INFO", detail=reason))


@dataclass(frozen=True)
class ClaimsCheckObservation:
    """Observed Launch claims check response for one domain."""
    domain: str
    present_on_dnl: bool
    claim_key: str | None = None
    claim_key_valid: bool = True


@dataclass(frozen=True)
class RpmsCreateObservation:
    """Observed Launch create response for one scenario."""
    scenario: str
    expected_success: bool
    response_xml: str
    info_object_exists: bool = True
    info_properties_valid: bool = True


@dataclass(frozen=True)
class MinimumRpmsSuiteConfig:
    """Unified configuration for the MinimumRPMs test suite."""
    launch_extension_xml: str | None = None
    claims_checks: list[ClaimsCheckObservation] = field(default_factory=list)
    sunrise_creates: list[RpmsCreateObservation] = field(default_factory=list)
    trademark_claims_creates: list[RpmsCreateObservation] = field(default_factory=list)


def _validate_launch_extension(result: MinimumRpmsTestResult, extension_xml: str | None) -> None:
    if not extension_xml:
        return
    try:
        EppClient.validate_extension_xml(extension_xml)
    except ValueError as exc:
        result.add_error("EPP_INVALID_EXTENSION", "ERROR", str(exc))


def _response_succeeded(response_xml: str) -> bool:
    return EppClient.is_success(response_xml)


class MinimumRpms01ClaimsCheckChecker:
    """minimumRPMs-01: Claims check command behavior."""
    def __init__(self, config: MinimumRpmsSuiteConfig) -> None:
        self.config = config

    def run(self) -> MinimumRpmsTestResult:
        result = MinimumRpmsTestResult(test_id="minimumRPMs-01")
        _validate_launch_extension(result, self.config.launch_extension_xml)
        if not self.config.claims_checks:
            result.add_error("RPMS_NO_CLAIMS_CHECK_OBSERVATIONS", "ERROR", "No claims check observations were provided.")
            return result

        for observation in self.config.claims_checks:
            has_key = bool(observation.claim_key)
            if observation.present_on_dnl and not has_key:
                result.add_error("RPMS_MISSING_CLAIMS_KEY", "ERROR", f"Domain {observation.domain} is on the DNL but no claim key was returned.")
            if not observation.present_on_dnl and has_key:
                result.add_error("RPMS_UNEXPECTED_CLAIMS_KEY", "ERROR", f"Domain {observation.domain} is not on the DNL but a claim key was returned.")
            if has_key and not observation.claim_key_valid:
                result.add_error("RPMS_INVALID_CLAIMS_KEY", "ERROR", f"Domain {observation.domain} returned an invalid claim key.")
        return result


class _RpmsCreateChecker:
    test_id = ""
    no_observations_code = ""
    valid_failure_code = ""
    invalid_success_code = ""
    missing_info_code = ""
    invalid_info_code = ""

    def __init__(self, config: MinimumRpmsSuiteConfig) -> None:
        self.config = config

    def _observations(self) -> list[RpmsCreateObservation]:
        raise NotImplementedError

    def run(self) -> MinimumRpmsTestResult:
        result = MinimumRpmsTestResult(test_id=self.test_id)
        _validate_launch_extension(result, self.config.launch_extension_xml)
        observations = self._observations()
        if not observations:
            result.add_error(self.no_observations_code, "ERROR", f"No observations were provided for {self.test_id}.")
            return result

        for observation in observations:
            try:
                succeeded = _response_succeeded(observation.response_xml)
            except ValueError as exc:
                result.add_error("EPP_XML_PARSE_ERROR", "ERROR", f"{observation.scenario} response parse failed: {exc}")
                continue
            if observation.expected_success and not succeeded:
                result.add_error(self.valid_failure_code, "ERROR", f"Scenario {observation.scenario} was expected to succeed but failed.")
            if not observation.expected_success and succeeded:
                result.add_error(self.invalid_success_code, "ERROR", f"Scenario {observation.scenario} was expected to fail but succeeded.")
            if observation.expected_success and succeeded and not observation.info_object_exists:
                result.add_error(self.missing_info_code, "ERROR", f"Scenario {observation.scenario} created object was not found by info.")
            if observation.expected_success and succeeded and not observation.info_properties_valid:
                result.add_error(self.invalid_info_code, "ERROR", f"Scenario {observation.scenario} info object has missing or invalid properties.")
        return result


class MinimumRpms02SunriseCreateChecker(_RpmsCreateChecker):
    """minimumRPMs-02: Sunrise create command behavior."""
    test_id = "minimumRPMs-02"
    no_observations_code = "RPMS_NO_SUNRISE_CREATE_OBSERVATIONS"
    valid_failure_code = "RPMS_SUNRISE_CREATE_UNEXPECTED_FAILURE_USING_VALID_SMD"
    invalid_success_code = "RPMS_SUNRISE_CREATE_UNEXPECTED_SUCCESS_USING_INVALID_SMD"
    missing_info_code = "RPMS_SUNRISE_CREATE_INFO_OBJECT_DOES_NOT_EXIST"
    invalid_info_code = "RPMS_SUNRISE_CREATE_INFO_OBJECT_IS_HAS_MISSING_OR_INVALID_PROPERTIES"

    def _observations(self) -> list[RpmsCreateObservation]:
        return self.config.sunrise_creates


class MinimumRpms03TrademarkClaimsCreateChecker(_RpmsCreateChecker):
    """minimumRPMs-03: Trademark claims create command behavior."""
    test_id = "minimumRPMs-03"
    no_observations_code = "RPMS_NO_TRADEMARK_CREATE_OBSERVATIONS"
    valid_failure_code = "RPMS_TRADEMARK_CREATE_UNEXPECTED_FAILURE_USING_VALID_NOTICE_ID"
    invalid_success_code = "RPMS_TRADEMARK_CREATE_UNEXPECTED_SUCCESS_USING_INVALID_NOTICE_ID"
    missing_info_code = "RPMS_TRADEMARK_CREATE_INFO_OBJECT_DOES_NOT_EXIST"
    invalid_info_code = "RPMS_TRADEMARK_CREATE_INFO_OBJECT_IS_HAS_MISSING_OR_INVALID_PROPERTIES"

    def _observations(self) -> list[RpmsCreateObservation]:
        return self.config.trademark_claims_creates


_MINIMUM_RPMS_CHECKERS = [
    MinimumRpms01ClaimsCheckChecker,
    MinimumRpms02SunriseCreateChecker,
    MinimumRpms03TrademarkClaimsCreateChecker,
]


class MinimumRpmsTestSuite:
    """Runs all test cases in the MinimumRPMs suite."""
    def __init__(self, config: MinimumRpmsSuiteConfig) -> None:
        self.config = config

    def run_all(self) -> list[MinimumRpmsTestResult]:
        return [checker_cls(self.config).run() for checker_cls in _MINIMUM_RPMS_CHECKERS]
